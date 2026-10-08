//! Private, memory-only undo receipts. No source bytes enter CLI JSON.
use super::*;
use zeroize::Zeroizing;

/// Bounded private source bytes, tied to a directory and one binding.
/// Deliberately neither Clone nor Serialize. The app keeps the encoded
/// receipt in wiping memory, never preferences or the system undo stack.
pub struct UndoRecord {
    device: u64,
    inode: u64,
    name: String,
    profile: Option<String>,
    before: Zeroizing<Vec<u8>>,
    after: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for UndoRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UndoRecord { .. }")
    }
}

impl UndoRecord {
    pub(super) fn new(device: u64, inode: u64, before: Vec<u8>, after: String) -> Self {
        Self {
            device,
            inode,
            name: String::new(),
            profile: None,
            before: Zeroizing::new(before),
            after: Zeroizing::new(after.into_bytes()),
        }
    }

    fn identify(&mut self, name: &EnvName, profile: Option<&ProfileName>) {
        self.name = name.as_str().to_owned();
        self.profile = profile.map(|p| p.as_str().to_owned());
    }

    /// Write to the caller's explicit private descriptor, never stdout.
    pub fn write(&self, output: &mut impl Write) -> Result<(), EditError> {
        output.write_all(b"ECUNDO1\n").map_err(|e| io(&e))?;
        for number in [self.device, self.inode] {
            output
                .write_all(&number.to_be_bytes())
                .map_err(|e| io(&e))?;
        }
        for bytes in [
            self.name.as_bytes(),
            self.profile.as_deref().unwrap_or("").as_bytes(),
            &self.before,
            &self.after,
        ] {
            output
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .map_err(|e| io(&e))?;
            output.write_all(bytes).map_err(|e| io(&e))?;
        }
        Ok(())
    }

    /// Bounded, strict private transport. Malformed records disclose no input.
    pub fn read(input: &mut impl Read) -> Result<Self, EditError> {
        let mut header = [0; 24];
        input.read_exact(&mut header).map_err(|e| io(&e))?;
        if &header[..8] != b"ECUNDO1\n" {
            return Err(EditError::Changed);
        }
        let mut field = |limit: usize| -> Result<Zeroizing<Vec<u8>>, EditError> {
            let mut length = [0; 4];
            input.read_exact(&mut length).map_err(|e| io(&e))?;
            let size = u32::from_be_bytes(length) as usize;
            if size > limit {
                return Err(EditError::TooLarge);
            }
            let mut bytes = Zeroizing::new(vec![0; size]);
            input.read_exact(&mut bytes).map_err(|e| io(&e))?;
            Ok(bytes)
        };
        let name = field(256)?;
        let profile = field(256)?;
        let before = field(Manifest::MAX_LEN)?;
        let after = field(Manifest::MAX_LEN)?;
        let mut extra = [0];
        if input.read(&mut extra).map_err(|e| io(&e))? != 0 {
            return Err(EditError::Changed);
        }
        let name = std::str::from_utf8(&name)
            .map_err(|_| EditError::Changed)?
            .to_owned();
        EnvName::new(&name).map_err(|_| EditError::Changed)?;
        let profile = std::str::from_utf8(&profile).map_err(|_| EditError::Changed)?;
        let profile = if profile.is_empty() {
            None
        } else {
            Some(
                ProfileName::new(profile)
                    .map_err(|_| EditError::Changed)?
                    .as_str()
                    .to_owned(),
            )
        };
        let mut dev = [0; 8];
        dev.copy_from_slice(&header[8..16]);
        let mut ino = [0; 8];
        ino.copy_from_slice(&header[16..24]);
        let record = Self {
            device: u64::from_be_bytes(dev),
            inode: u64::from_be_bytes(ino),
            name,
            profile,
            before,
            after,
        };
        record.validate()?;
        Ok(record)
    }

    /// The inverse binding must pass the same daemon check as ordinary ref.
    pub fn previous_binding(&self) -> Result<Option<Binding>, EditError> {
        let manifest = parse_manifest(&self.before).map_err(EditError::Manifest)?;
        let profile = self
            .profile
            .as_deref()
            .map(ProfileName::new)
            .transpose()
            .map_err(|_| EditError::Changed)?;
        let bindings = match profile {
            None => Some(&manifest.env),
            Some(p) => manifest.profiles.get(&p),
        };
        Ok(bindings
            .and_then(|list| list.iter().find(|b| b.env_name.as_str() == self.name))
            .cloned())
    }

    fn validate(&self) -> Result<(), EditError> {
        // A private fd is transport, not authority to restore unrelated policy
        // or project data. Only one selected binding may differ semantically.
        let strip = |bytes: &[u8]| -> Result<Manifest, EditError> {
            let mut manifest = parse_manifest(bytes).map_err(EditError::Manifest)?;
            if let Some(p) = &self.profile {
                let p = ProfileName::new(p).map_err(|_| EditError::Changed)?;
                if let Some(list) = manifest.profiles.get_mut(&p) {
                    list.retain(|b| b.env_name.as_str() != self.name);
                    if list.is_empty() {
                        manifest.profiles.remove(&p);
                    }
                }
            } else {
                manifest.env.retain(|b| b.env_name.as_str() != self.name);
            }
            manifest.sha256 = [0; 32];
            Ok(manifest)
        };
        if strip(&self.before)? != strip(&self.after)? {
            return Err(EditError::OthersChanged);
        }
        Ok(())
    }
}

/// Record the exact input the successful writer used, only after sync.
pub fn record_ref(
    path: &Path,
    binding: &Binding,
    profile: Option<&ProfileName>,
) -> Result<(RefEdit, Option<UndoRecord>), EditError> {
    let mut record = None;
    let edit = edit_with_record(path, binding, profile, || {}, Some(&mut record))?;
    if let Some(r) = &mut record {
        r.identify(&binding.env_name, profile);
    }
    Ok((edit, record))
}

/// Remove a binding while retaining its original source representation.
pub fn record_unset(
    path: &Path,
    name: &EnvName,
    profile: Option<&ProfileName>,
) -> Result<(Reference, Option<UndoRecord>), EditError> {
    let mut record = None;
    let reference = unset_with_record(path, name, profile, || {}, Some(&mut record))?;
    if let Some(r) = &mut record {
        r.identify(name, profile);
    }
    Ok((reference, record))
}

/// Restore original bytes only when the held directory and current document
/// match. The caller consumes a receipt once; LIFO restores earlier states.
/// As in ordinary ref, a sync failure can follow a successful rename.
pub fn restore_ref(path: &Path, record: UndoRecord) -> Result<(), EditError> {
    record.validate()?;
    edit_document(
        path,
        |_, text, dir| {
            if (dir.dev(), dir.ino()) != (record.device, record.inode) {
                return Err(EditError::Changed);
            }
            if text.as_bytes() != &*record.after {
                return Err(EditError::Changed);
            }
            let original = std::str::from_utf8(&record.before)
                .map_err(|_| EditError::Changed)?
                .to_owned();
            Ok((Some(original), ()))
        },
        || {},
        None,
    )
}
