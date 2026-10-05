//! What an executable file says about itself, read through a descriptor
//! the caller opened and checked (M2 plan D-33, task M2-27): its format,
//! a Mach-O file's code directory (whose hash is the code identity macOS
//! checks when it runs the file), and whether an ELF file finds its
//! libraries relative to its own path (`$ORIGIN`).
//!
//! Every reader here takes the file as hostile input: offsets and lengths
//! are checked against the file and against fixed caps before anything is
//! read, a malformed file is [`FormatError`], never a panic or a guess,
//! and nothing is read past what the format names. Nothing here runs or
//! maps the file.
//!
//! - [`executable_format`]: ELF, Mach-O (thin or universal), a `#!` script,
//!   or none of these.
//! - [`code_directory`]: the code directory a Mach-O file's signature holds
//!   for this machine's architecture, the one the kernel uses: of several,
//!   the one of the strongest hash type the kernel ranks first
//!   (`cs_hash_type_rank` in XNU: SHA-384, SHA-256, SHA-256 truncated,
//!   SHA-1). Its hash, truncated to 20 bytes, is the cdhash
//!   ([`CodeDirectory::cdhash_input`] is what is hashed); callers hash it,
//!   so this crate needs no hash function. The identifier and the Team ID
//!   it names are read from the directory as written: nothing here checks
//!   the signature's certificate chain, so they are labels, not proof.
//! - [`elf_uses_origin`]: whether an ELF file's run path, legacy run path
//!   or needed libraries name `$ORIGIN`, which a sealed in-memory copy of
//!   the file cannot honour (SPEC §6.6: such a launch is
//!   `checked_at_rest`).

use std::fs::File;
use std::os::unix::fs::FileExt;

/// The largest file read here: 512 MiB (as the daemon's executable hashing
/// caps it, M2 plan D-09).
pub const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;

/// Load commands, program headers and dynamic entries are capped so a
/// hostile count cannot make a reader loop for long.
const MAX_ENTRIES: u32 = 4096;
/// A code signature, or a dynamic string table, larger than this is
/// refused.
const MAX_TABLE: u64 = 64 * 1024 * 1024;

/// Why a file could not be read as the format it claims. Carries no byte
/// of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatError {
    /// A read failed, or the file ended inside a structure.
    Truncated,
    /// A structure is malformed: an offset or length outside the file, a
    /// count past its cap, an unknown magic number.
    Malformed,
    /// The file is larger than [`MAX_EXECUTABLE`].
    TooLarge,
    /// A universal file with no slice, or more than one, for this
    /// machine's architecture: which one would run is not certain.
    NoSlice,
}

/// What kind of executable a file is, from its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutableFormat {
    Elf,
    /// A thin Mach-O file of either word size.
    MachO,
    /// A universal ("fat") Mach-O file.
    MachOUniversal,
    /// A file that starts with `#!`.
    Script,
    /// None of these.
    Other,
}

fn read_exact_at(f: &File, buf: &mut [u8], at: u64) -> Result<(), FormatError> {
    f.read_exact_at(buf, at).map_err(|_| FormatError::Truncated)
}

fn file_len(f: &File) -> Result<u64, FormatError> {
    let len = f.metadata().map_err(|_| FormatError::Truncated)?.len();
    if len > MAX_EXECUTABLE {
        return Err(FormatError::TooLarge);
    }
    Ok(len)
}

/// The format of `f`, from its first four bytes. A file shorter than that
/// is [`ExecutableFormat::Other`].
///
/// # Errors
/// [`FormatError::Truncated`] when the file cannot be read.
pub fn executable_format(f: &File) -> Result<ExecutableFormat, FormatError> {
    let mut head = [0u8; 4];
    match f.read_at(&mut head, 0) {
        Ok(4) => {}
        Ok(n) if n >= 2 && &head[..2] == b"#!" => return Ok(ExecutableFormat::Script),
        Ok(_) => return Ok(ExecutableFormat::Other),
        Err(_) => return Err(FormatError::Truncated),
    }
    Ok(match head {
        [0x7f, b'E', b'L', b'F'] => ExecutableFormat::Elf,
        [b'#', b'!', ..] => ExecutableFormat::Script,
        // MH_MAGIC and MH_MAGIC_64, little-endian as Apple's platforms
        // write them, and big-endian.
        [0xce | 0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xce | 0xcf] => {
            ExecutableFormat::MachO
        }
        // FAT_MAGIC and FAT_MAGIC_64, always big-endian.
        [0xca, 0xfe, 0xba, 0xbe | 0xbf] => ExecutableFormat::MachOUniversal,
        _ => ExecutableFormat::Other,
    })
}

/// A code directory, as [`code_directory`] found it.
#[derive(Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    /// The directory's hash type: 1 SHA-1, 2 SHA-256, 3 SHA-256 truncated
    /// to 20 bytes, 4 SHA-384.
    pub hash_type: u8,
    /// The directory blob, whose hash (by [`CodeDirectory::hash_type`],
    /// truncated to 20 bytes) is the cdhash.
    pub blob: Vec<u8>,
    /// The signing identifier written in the directory.
    pub identifier: Option<String>,
    /// The Team ID written in the directory (version 0x20200 on).
    pub team: Option<String>,
}

impl core::fmt::Debug for CodeDirectory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CodeDirectory")
            .field("hash_type", &self.hash_type)
            .field("blob", &self.blob.len())
            .field("identifier", &self.identifier)
            .field("team", &self.team)
            .finish()
    }
}

impl CodeDirectory {
    /// The bytes whose hash is the cdhash.
    pub fn cdhash_input(&self) -> &[u8] {
        &self.blob
    }
}

/// The CPU type a universal file's slice must have to run here.
#[cfg(target_arch = "aarch64")]
const HOST_CPU: u32 = 0x0100_000c;
#[cfg(target_arch = "x86_64")]
const HOST_CPU: u32 = 0x0100_0007;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const HOST_CPU: u32 = 0;

const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ALTERNATE_FIRST: u32 = 0x1000;
const CSSLOT_ALTERNATE_LAST: u32 = 0x1004;

/// The kernel's preference among hash types, highest first.
fn rank(hash_type: u8) -> Option<u8> {
    match hash_type {
        4 => Some(4),
        2 => Some(3),
        3 => Some(2),
        1 => Some(1),
        _ => None,
    }
}

fn be32(b: &[u8], at: usize) -> Result<u32, FormatError> {
    let s = b.get(at..at + 4).ok_or(FormatError::Malformed)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], at: usize) -> Result<u64, FormatError> {
    let s = b.get(at..at + 8).ok_or(FormatError::Malformed)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_be_bytes(a))
}

/// The slice of a Mach-O file for this machine: `(offset, length)`, the
/// whole file for a thin one.
fn host_slice(f: &File, len: u64) -> Result<(u64, u64), FormatError> {
    match executable_format(f)? {
        ExecutableFormat::MachO => Ok((0, len)),
        ExecutableFormat::MachOUniversal => {
            let mut head = [0u8; 8];
            read_exact_at(f, &mut head, 0)?;
            let wide = head[3] == 0xbf;
            let count = be32(&head, 4)?;
            if count == 0 || count > 64 {
                return Err(FormatError::Malformed);
            }
            let entry = if wide { 32 } else { 20 };
            let mut table = vec![0u8; usize::try_from(count).unwrap_or(0) * entry];
            read_exact_at(f, &mut table, 8)?;
            let mut found = None;
            for e in table.chunks_exact(entry) {
                if be32(e, 0)? != HOST_CPU {
                    continue;
                }
                let (off, size) = if wide {
                    (be64(e, 8)?, be64(e, 16)?)
                } else {
                    (u64::from(be32(e, 8)?), u64::from(be32(e, 12)?))
                };
                if off.checked_add(size).is_none_or(|end| end > len) {
                    return Err(FormatError::Malformed);
                }
                if found.replace((off, size)).is_some() {
                    return Err(FormatError::NoSlice);
                }
            }
            found.ok_or(FormatError::NoSlice)
        }
        _ => Err(FormatError::Malformed),
    }
}

/// The code directory the kernel would use for `f` on this machine, or
/// `None` when the file is a Mach-O file without a code signature (an
/// unsigned x86_64 executable: SPEC §6.6 makes its launch
/// `checked_at_rest`).
///
/// # Errors
/// [`FormatError`] for a file that is not a well-formed Mach-O file, has
/// no slice for this machine, or is larger than [`MAX_EXECUTABLE`].
pub fn code_directory(f: &File) -> Result<Option<CodeDirectory>, FormatError> {
    let len = file_len(f)?;
    let (base, size) = host_slice(f, len)?;
    let mut header = [0u8; 32];
    read_exact_at(f, &mut header, base)?;
    let (magic_le, magic_be) = (
        u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]),
    );
    let (little, wide) = match (magic_le, magic_be) {
        (0xfeed_facf, _) => (true, true),
        (0xfeed_face, _) => (true, false),
        (_, 0xfeed_facf) => (false, true),
        (_, 0xfeed_face) => (false, false),
        _ => return Err(FormatError::Malformed),
    };
    let word = |b: &[u8], at: usize| -> Result<u32, FormatError> {
        let s = b.get(at..at + 4).ok_or(FormatError::Malformed)?;
        let a = [s[0], s[1], s[2], s[3]];
        Ok(if little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    };
    let ncmds = word(&header, 16)?;
    let sizeofcmds = word(&header, 20)?;
    if ncmds > MAX_ENTRIES || u64::from(sizeofcmds) > size {
        return Err(FormatError::Malformed);
    }
    let start = base + if wide { 32 } else { 28 };
    let mut cmds = vec![0u8; usize::try_from(sizeofcmds).map_err(|_| FormatError::Malformed)?];
    read_exact_at(f, &mut cmds, start)?;
    let mut at = 0usize;
    let mut signature = None;
    for _ in 0..ncmds {
        let cmd = word(&cmds, at)?;
        let cmdsize = usize::try_from(word(&cmds, at + 4)?).map_err(|_| FormatError::Malformed)?;
        if cmdsize < 8 || at + cmdsize > cmds.len() {
            return Err(FormatError::Malformed);
        }
        if cmd == LC_CODE_SIGNATURE {
            if signature.is_some() || cmdsize < 16 {
                return Err(FormatError::Malformed);
            }
            signature = Some((
                u64::from(word(&cmds, at + 8)?),
                u64::from(word(&cmds, at + 12)?),
            ));
        }
        at += cmdsize;
    }
    let Some((dataoff, datasize)) = signature else {
        return Ok(None);
    };
    if datasize > MAX_TABLE || dataoff.checked_add(datasize).is_none_or(|end| end > size) {
        return Err(FormatError::Malformed);
    }
    let mut blob = vec![0u8; usize::try_from(datasize).map_err(|_| FormatError::Malformed)?];
    read_exact_at(f, &mut blob, base + dataoff)?;
    best_directory(&blob).map(Some)
}

/// The best code directory in an embedded signature (a SuperBlob, always
/// big-endian).
fn best_directory(sig: &[u8]) -> Result<CodeDirectory, FormatError> {
    if be32(sig, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(FormatError::Malformed);
    }
    let length = usize::try_from(be32(sig, 4)?).map_err(|_| FormatError::Malformed)?;
    let count = be32(sig, 8)?;
    if length > sig.len() || count > MAX_ENTRIES {
        return Err(FormatError::Malformed);
    }
    let sig = &sig[..length];
    let mut best: Option<(u8, CodeDirectory)> = None;
    for i in 0..usize::try_from(count).map_err(|_| FormatError::Malformed)? {
        let slot = be32(sig, 12 + i * 8)?;
        let off = usize::try_from(be32(sig, 16 + i * 8)?).map_err(|_| FormatError::Malformed)?;
        let is_directory = slot == CSSLOT_CODEDIRECTORY
            || (CSSLOT_ALTERNATE_FIRST..=CSSLOT_ALTERNATE_LAST).contains(&slot);
        if !is_directory {
            continue;
        }
        let cd = directory_at(sig, off)?;
        let Some(r) = rank(cd.hash_type) else {
            continue;
        };
        if best.as_ref().is_none_or(|(b, _)| r > *b) {
            best = Some((r, cd));
        }
    }
    best.map(|(_, cd)| cd).ok_or(FormatError::Malformed)
}

/// A NUL-terminated ASCII string inside `blob` at `off`, of at most 1 KiB.
fn c_string(blob: &[u8], off: usize) -> Option<String> {
    let rest = blob.get(off..)?;
    let end = rest.iter().take(1024).position(|b| *b == 0)?;
    let s = &rest[..end];
    (!s.is_empty() && s.iter().all(|b| b.is_ascii_graphic()))
        .then(|| String::from_utf8_lossy(s).into_owned())
}

fn directory_at(sig: &[u8], off: usize) -> Result<CodeDirectory, FormatError> {
    if be32(sig, off)? != CSMAGIC_CODEDIRECTORY {
        return Err(FormatError::Malformed);
    }
    let len = usize::try_from(be32(sig, off + 4)?).map_err(|_| FormatError::Malformed)?;
    let end = off.checked_add(len).ok_or(FormatError::Malformed)?;
    if len < 44 || end > sig.len() {
        return Err(FormatError::Malformed);
    }
    let blob = sig[off..end].to_vec();
    let version = be32(&blob, 8)?;
    let ident = usize::try_from(be32(&blob, 20)?).map_err(|_| FormatError::Malformed)?;
    let hash_type = *blob.get(37).ok_or(FormatError::Malformed)?;
    let team = if version >= 0x20200 {
        let t = usize::try_from(be32(&blob, 48)?).map_err(|_| FormatError::Malformed)?;
        if t == 0 { None } else { c_string(&blob, t) }
    } else {
        None
    };
    Ok(CodeDirectory {
        hash_type,
        identifier: c_string(&blob, ident),
        team,
        blob,
    })
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

/// Whether the ELF file `f` names `$ORIGIN` (or `${ORIGIN}`) in its run
/// path (`DT_RUNPATH`), its legacy run path (`DT_RPATH`) or a needed
/// library (`DT_NEEDED`): the dynamic loader expands it to the directory
/// of the running file, which a sealed in-memory copy does not have. A
/// file without a dynamic section (static) names none.
///
/// # Errors
/// [`FormatError`] for a file that is not well-formed ELF, or is larger
/// than [`MAX_EXECUTABLE`].
pub fn elf_uses_origin(f: &File) -> Result<bool, FormatError> {
    let len = file_len(f)?;
    let mut ident = [0u8; 64];
    read_exact_at(f, &mut ident[..52], 0)?;
    if &ident[..4] != b"\x7fELF" {
        return Err(FormatError::Malformed);
    }
    let wide = match ident[4] {
        1 => false,
        2 => true,
        _ => return Err(FormatError::Malformed),
    };
    let little = match ident[5] {
        1 => true,
        2 => false,
        _ => return Err(FormatError::Malformed),
    };
    if wide {
        read_exact_at(f, &mut ident, 0)?;
    }
    let r = Reader { little };
    let (phoff, phentsize, phnum) = if wide {
        (r.u64(&ident, 32)?, r.u16(&ident, 54)?, r.u16(&ident, 56)?)
    } else {
        (
            u64::from(r.u32(&ident, 28)?),
            r.u16(&ident, 42)?,
            r.u16(&ident, 44)?,
        )
    };
    let need = if wide { 56 } else { 32 };
    if usize::from(phentsize) < need || u32::from(phnum) > MAX_ENTRIES {
        return Err(FormatError::Malformed);
    }
    let table_len = u64::from(phentsize) * u64::from(phnum);
    if phoff.checked_add(table_len).is_none_or(|end| end > len) {
        return Err(FormatError::Malformed);
    }
    let mut table = vec![0u8; usize::try_from(table_len).map_err(|_| FormatError::Malformed)?];
    read_exact_at(f, &mut table, phoff)?;
    // (type, file offset, virtual address, file size)
    let mut loads = Vec::new();
    let mut dynamic = None;
    for e in table.chunks_exact(usize::from(phentsize)) {
        let kind = r.u32(e, 0)?;
        let (offset, vaddr, filesz) = if wide {
            (r.u64(e, 8)?, r.u64(e, 16)?, r.u64(e, 32)?)
        } else {
            (
                u64::from(r.u32(e, 4)?),
                u64::from(r.u32(e, 8)?),
                u64::from(r.u32(e, 16)?),
            )
        };
        if offset.checked_add(filesz).is_none_or(|end| end > len) {
            return Err(FormatError::Malformed);
        }
        match kind {
            PT_LOAD => loads.push((offset, vaddr, filesz)),
            PT_DYNAMIC if dynamic.replace((offset, filesz)).is_some() => {
                return Err(FormatError::Malformed);
            }
            _ => {}
        }
    }
    let Some((dyn_off, dyn_size)) = dynamic else {
        return Ok(false);
    };
    if dyn_size > MAX_TABLE {
        return Err(FormatError::Malformed);
    }
    let mut dyns = vec![0u8; usize::try_from(dyn_size).map_err(|_| FormatError::Malformed)?];
    read_exact_at(f, &mut dyns, dyn_off)?;
    let entry = if wide { 16 } else { 8 };
    let mut strtab = None;
    let mut strsz = None;
    let mut names = Vec::new();
    for (i, e) in dyns.chunks_exact(entry).enumerate() {
        if i >= MAX_ENTRIES as usize {
            return Err(FormatError::Malformed);
        }
        let (tag, val) = if wide {
            (r.u64(e, 0)?, r.u64(e, 8)?)
        } else {
            (u64::from(r.u32(e, 0)?), u64::from(r.u32(e, 4)?))
        };
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = Some(val),
            DT_STRSZ => strsz = Some(val),
            DT_NEEDED | DT_RPATH | DT_RUNPATH => names.push(val),
            _ => {}
        }
    }
    if names.is_empty() {
        return Ok(false);
    }
    let (Some(addr), Some(size)) = (strtab, strsz) else {
        return Err(FormatError::Malformed);
    };
    if size > MAX_TABLE {
        return Err(FormatError::Malformed);
    }
    // The string table's address, as a file offset through the load
    // segment that maps it.
    let offset = loads
        .iter()
        .find(|(_, vaddr, filesz)| addr >= *vaddr && addr - vaddr < *filesz)
        .map(|(off, vaddr, _)| off + (addr - vaddr))
        .ok_or(FormatError::Malformed)?;
    if offset.checked_add(size).is_none_or(|end| end > len) {
        return Err(FormatError::Malformed);
    }
    let mut strings = vec![0u8; usize::try_from(size).map_err(|_| FormatError::Malformed)?];
    read_exact_at(f, &mut strings, offset)?;
    for at in names {
        let at = usize::try_from(at).map_err(|_| FormatError::Malformed)?;
        let rest = strings.get(at..).ok_or(FormatError::Malformed)?;
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or(FormatError::Malformed)?;
        let s = &rest[..end];
        if contains(s, b"$ORIGIN") || contains(s, b"${ORIGIN}") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Reads ELF fields in the file's byte order.
#[derive(Clone, Copy)]
struct Reader {
    little: bool,
}

impl Reader {
    fn u16(self, b: &[u8], at: usize) -> Result<u16, FormatError> {
        let s = b.get(at..at + 2).ok_or(FormatError::Malformed)?;
        let a = [s[0], s[1]];
        Ok(if self.little {
            u16::from_le_bytes(a)
        } else {
            u16::from_be_bytes(a)
        })
    }

    fn u32(self, b: &[u8], at: usize) -> Result<u32, FormatError> {
        let s = b.get(at..at + 4).ok_or(FormatError::Malformed)?;
        let a = [s[0], s[1], s[2], s[3]];
        Ok(if self.little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }

    fn u64(self, b: &[u8], at: usize) -> Result<u64, FormatError> {
        let s = b.get(at..at + 8).ok_or(FormatError::Malformed)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(if self.little {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn file_of(bytes: &[u8]) -> File {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    #[test]
    fn formats_are_read_from_the_first_bytes() {
        for (bytes, want) in [
            (&b"\x7fELF\x02\x01\x01"[..], ExecutableFormat::Elf),
            (&b"#!/bin/sh\n"[..], ExecutableFormat::Script),
            (&b"#!"[..], ExecutableFormat::Script),
            (&[0xcf, 0xfa, 0xed, 0xfe, 0, 0][..], ExecutableFormat::MachO),
            (
                &[0xca, 0xfe, 0xba, 0xbe, 0, 0][..],
                ExecutableFormat::MachOUniversal,
            ),
            (&b"MZ\x90\x00"[..], ExecutableFormat::Other),
            (&b""[..], ExecutableFormat::Other),
            (&b"\x7f"[..], ExecutableFormat::Other),
        ] {
            assert_eq!(
                executable_format(&file_of(bytes)).unwrap(),
                want,
                "{bytes:?}"
            );
        }
    }

    /// Hostile input: every prefix of a real executable, and the
    /// executable with each of its first 256 bytes changed, is either
    /// read or refused, never a panic.
    #[test]
    fn truncated_and_damaged_executables_are_refused_not_misread() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let head = &exe[..exe.len().min(8192)];
        for cut in (0..head.len()).step_by(97) {
            let f = file_of(&head[..cut]);
            let _ = elf_uses_origin(&f);
            let _ = code_directory(&f);
        }
        for i in 0..256.min(head.len()) {
            let mut b = head.to_vec();
            b[i] ^= 0xa5;
            let f = file_of(&b);
            let _ = elf_uses_origin(&f);
            let _ = code_directory(&f);
        }
        assert_eq!(
            elf_uses_origin(&file_of(b"#!/bin/sh\n")),
            Err(FormatError::Truncated)
        );
    }

    /// The test binary itself: on macOS a signed Mach-O file (the linker
    /// signs every arm64 binary), on Linux an ELF file that names no
    /// `$ORIGIN`.
    #[test]
    fn this_test_binary_reads_as_its_own_format() {
        let f = File::open(std::env::current_exe().unwrap()).unwrap();
        if cfg!(target_os = "macos") {
            assert_eq!(executable_format(&f).unwrap(), ExecutableFormat::MachO);
            if cfg!(target_arch = "aarch64") {
                let cd = code_directory(&f)
                    .unwrap()
                    .expect("arm64 binaries are signed");
                assert!(matches!(cd.hash_type, 1..=4));
            }
        } else {
            assert_eq!(executable_format(&f).unwrap(), ExecutableFormat::Elf);
            assert!(!elf_uses_origin(&f).unwrap());
        }
    }
}
