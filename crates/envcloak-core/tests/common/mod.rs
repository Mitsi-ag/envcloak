//! Helpers shared by the vault tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    unwrap_vmk_with, wrap_vmk_with,
};
use envcloak_core::vault::{
    FieldName, INITIAL_EPOCH, ItemDetails, LockedVault, NewItem, Slug, Vault, VaultPaths,
};
use envcloak_testkit::TestHome;

/// The passphrase of every fixture vault's passphrase unlocker.
pub const PASSPHRASE: &[u8] = b"a test passphrase, not a fixture";

/// A vault in its own test home, and the VMK's bytes to reopen it with.
pub struct Fixture {
    pub home: TestHome,
    pub paths: VaultPaths,
    /// The VMK's bytes (test support: never done with a real key).
    pub vmk: Vec<u8>,
    pub vault_id: VaultId,
}

impl Fixture {
    /// Creates a vault with one passphrase unlocker at the minimum KDF
    /// parameters.
    pub fn create() -> (Fixture, Vault) {
        let home = TestHome::new();
        let paths = VaultPaths::under(home.root().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let bytes = vmk.export_for_testing();
        let env = wrap_vmk_with(
            &vmk,
            &SecretBytes::copy_from(PASSPHRASE),
            UnlockerKind::Passphrase,
            &EnvelopeCtx {
                vault_id,
                unlocker_id: UnlockerId::generate(),
                epoch: INITIAL_EPOCH,
            },
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();
        let vault = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();
        (
            Fixture {
                home,
                paths,
                vmk: bytes,
                vault_id,
            },
            vault,
        )
    }

    pub fn vmk(&self) -> Vmk {
        Vmk::import_for_testing(&self.vmk).unwrap()
    }

    /// The data directory as text, for a child's environment.
    pub fn data(&self) -> String {
        self.paths.data_dir.to_str().unwrap().to_owned()
    }

    /// Opens and unlocks the vault.
    pub fn unlock(&self) -> Vault {
        LockedVault::open(&self.paths)
            .unwrap()
            .unlock(self.vmk())
            .map_err(|(_, e)| e)
            .unwrap()
    }

    /// Opens the vault the way the daemon will: lists the envelopes without
    /// the key, unwraps the passphrase envelope with the vault id and epoch
    /// the file reports, and unlocks with the VMK that gives.
    pub fn unlock_with_passphrase(&self) -> Vault {
        let locked = LockedVault::open(&self.paths).unwrap();
        let envs = locked.unlockers().unwrap();
        let env = envs
            .iter()
            .find(|e| e.kind() == UnlockerKind::Passphrase)
            .expect("the passphrase envelope is listed");
        let ctx = EnvelopeCtx {
            vault_id: locked.vault_id(),
            unlocker_id: env.unlocker_id(),
            epoch: locked.epoch(),
        };
        let vmk = unwrap_vmk_with(env, &SecretBytes::copy_from(PASSPHRASE), &ctx, &Argon2id)
            .expect("the passphrase unwraps the VMK");
        locked.unlock(vmk).map_err(|(_, e)| e).unwrap()
    }

    /// The path of the database file, canonicalized as the vault opens it.
    pub fn db(&self) -> std::path::PathBuf {
        std::fs::canonicalize(&self.paths.vault_dir)
            .unwrap()
            .join("vault.db")
    }

    /// A raw SQLite connection to the database, as another program would
    /// open it. The vault must be closed.
    pub fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.db()).unwrap()
    }
}

pub fn slug(s: &str) -> Slug {
    Slug::new(s).unwrap()
}

pub fn name(s: &str) -> FieldName {
    FieldName::new(s).unwrap()
}

pub fn secret_item(s: &str) -> NewItem {
    NewItem {
        class: ItemClass::Secret,
        slug: slug(s),
        details: ItemDetails {
            title: format!("title of {s}"),
            ..ItemDetails::default()
        },
    }
}

/// A small deterministic generator for workloads and timings.
#[derive(Debug, Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n` > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// Printable ASCII of length `len`.
    pub fn text(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| b'!' + (self.below(94) as u8)).collect()
    }
}

/// Re-runs this test binary as a child that executes only `test`, with
/// `env` set and `stdin` written to it. The child's stdout is piped.
pub fn spawn_self(home: &TestHome, test: &str, env: &[(&str, &str)], stdin: &[u8]) -> Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    home.apply(&mut cmd)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin).unwrap();
    drop(input);
    child
}

/// Reads the child's stdout up to the first line carrying `marker` and
/// returns what follows the marker on that line, or `None` at end of file.
pub fn wait_for(out: &mut BufReader<ChildStdout>, marker: &str) -> Option<String> {
    let mut line = String::new();
    loop {
        line.clear();
        if out.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        if let Some(at) = line.find(marker) {
            return Some(line[at + marker.len()..].trim().to_owned());
        }
    }
}

/// SIGKILL: what `kill -9` sends.
pub const SIGKILL: i32 = 9;

/// Kills the child with SIGKILL and checks that it was still running: a
/// child that ended on its own failed an assertion, and its stderr, which
/// this panic shows, says which.
pub fn kill_child(child: &mut Child, what: &str) {
    use std::os::unix::process::ExitStatusExt;
    let _ = child.kill();
    let status = child.wait().unwrap();
    if status.signal() != Some(SIGKILL) {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        panic!("the {what} child ended on its own ({status:?}): {err}");
    }
}

/// Everything left on the child's stdout.
pub fn rest(out: &mut BufReader<ChildStdout>) -> String {
    let mut s = String::new();
    let _ = out.read_to_string(&mut s);
    s
}

/// The last number printed after `marker` in `text`.
pub fn last_number(text: &str, marker: &str) -> Option<u64> {
    text.lines()
        .filter_map(|l| l.find(marker).map(|at| &l[at + marker.len()..]))
        .filter_map(|n| n.trim().parse().ok())
        .next_back()
}

/// Reads everything on stdin, in a child.
pub fn read_stdin() -> Vec<u8> {
    let mut b = Vec::new();
    std::io::stdin().read_to_end(&mut b).unwrap();
    b
}

/// The names in a directory, sorted.
pub fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Copies every regular file of `from` into `to` (created), for snapshots
/// of a closed vault directory.
pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}
