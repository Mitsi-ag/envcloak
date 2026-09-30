//! Shared helpers for the daemon's integration tests.
#![allow(dead_code, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::{Client, RunPaths};
use envcloak_testkit::{Canary, Daemon, TestHome, by_label, daemon_run_dir, labels};

/// Argon2id memory for test vaults: the 64 MiB floor.
pub const TEST_KDF_KIB: u32 = 64 * 1024;

pub fn exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_envcloakd"))
}

pub fn run_paths(home: &TestHome) -> RunPaths {
    RunPaths::under(daemon_run_dir(home)).unwrap()
}

pub fn start(home: &TestHome) -> Daemon {
    Daemon::start(home, exe(), &[])
}

pub fn client(home: &TestHome) -> Client {
    Client::connect(&run_paths(home)).unwrap()
}

/// Makes this test process a terminal session (a new session with a
/// pseudo-terminal as its controlling terminal), so the daemon takes its
/// proofs: SPEC §10b takes a proof (`unlock`, `approve`) only from a
/// terminal subject with no agent in its ancestry. Idempotent. CI has no
/// agent above the tests; under a developer's agent the proofs are still
/// refused, as they must be (run the tests outside its tree).
pub fn terminal_session() {
    envcloak_sys::testing::enter_terminal_session()
        .expect("this test process could not become a terminal session");
}

pub fn passphrase(cs: &[Canary]) -> SecretBytes {
    SecretBytes::copy_from(by_label(cs, labels::VAULT_PASSPHRASE).value())
}

/// Creates the vault with the canary passphrase and a new kit, whose text
/// is returned as a canary to sweep for.
pub fn create_vault(home: &TestHome, cs: &[Canary]) -> Canary {
    let kit = RecoveryKit::generate();
    let text = kit.to_display();
    let mut c = client(home);
    let v = c
        .vault_create(
            passphrase(cs),
            SecretBytes::copy_from(text.as_bytes()),
            Some(TEST_KDF_KIB),
        )
        .unwrap();
    assert!(!v.locked);
    Canary::new("RECOVERY_KIT", text.to_string())
}

/// A raw connection to the daemon, for frames no client would send.
pub fn raw(home: &TestHome) -> UnixStream {
    let s = UnixStream::connect(run_paths(home).socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s
}

/// Sends `v` as one frame.
pub fn send_json(s: &mut UnixStream, v: &serde_json::Value) {
    let body = serde_json::to_vec(v).unwrap();
    s.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&body).unwrap();
}

/// Reads one response frame as JSON, or `None` at end of stream.
pub fn read_json(s: &mut UnixStream) -> Option<serde_json::Value> {
    let mut header = [0u8; 4];
    if s.read_exact(&mut header).is_err() {
        return None;
    }
    let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
    s.read_exact(&mut body).unwrap();
    Some(serde_json::from_slice(&body).unwrap())
}

/// The `data.kind` token of an error response.
pub fn error_kind(v: &serde_json::Value) -> String {
    v["error"]["data"]["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("not an error response: {v}"))
        .to_owned()
}

/// Whether the peer closed the connection: a read returns end of stream,
/// or, when the peer closed with unread bytes from us (Linux), a reset.
pub fn closed(s: &mut UnixStream) -> bool {
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => true,
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionReset,
        Ok(_) => false,
    }
}

/// `status` from the daemon, retried while it is at its connection limit
/// (it closes connections past the limit at once).
pub fn status_when_free(home: &TestHome) -> envcloak_ipc::view::StatusView {
    let end = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match Client::connect(&run_paths(home)).and_then(|mut c| c.status()) {
            Ok(s) => return s,
            Err(_) if std::time::Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("the daemon did not answer: {e:?}"),
        }
    }
}

/// Resident memory of `pid` in KiB, from `ps`.
pub fn rss_kib(pid: i32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

/// The data directory of `home`, as the daemon resolves it.
pub fn data_dir(home: &TestHome) -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        home.home().join("Library/Application Support/EnvCloak")
    } else {
        home.root().join("data/envcloak")
    }
}

/// The slugs of the seeded items, in the order of [`seed_vault`].
pub const SLUGS: [&str; 4] = [
    "openai/acme-web",
    "stripe/acme-web",
    "github/acme-web",
    "short/acme-web",
];

/// Creates the vault in `home` with the canary passphrase, before any
/// daemon runs, and seeds it with one secret item per canary of the
/// story: `openai/acme-web`, `stripe/acme-web`, `github/acme-web` and
/// `short/acme-web`, each with a `value` field. The vault is left locked
/// on disk; the daemon opens it. Returns the kit's text as a canary.
pub fn seed_vault(home: &TestHome, cs: &[Canary]) -> Canary {
    let kit = RecoveryKit::generate();
    let text = kit.to_display();
    let paths = VaultPaths::under(data_dir(home));
    let mut v = create_vault_with_kit(&paths, &passphrase(cs), &kit, KdfParams::minimum()).unwrap();
    let values = [
        labels::OPENAI_API_KEY,
        labels::STRIPE_SECRET_KEY,
        labels::GITHUB_TOKEN,
        labels::SHORT_TOKEN,
    ];
    v.transact(|t| {
        for (slug, label) in SLUGS.iter().zip(values) {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new(slug).unwrap(),
                details: ItemDetails {
                    title: (*slug).to_owned(),
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(by_label(cs, label).value()),
            )?;
        }
        Ok(())
    })
    .unwrap();
    drop(v);
    Canary::new("RECOVERY_KIT", text.to_string())
}

/// The manifest of the story's project: two bindings in the default
/// profile, one more in `short`.
pub const MANIFEST: &str = "[project]
name = \"acme-web\"

[env]
OPENAI_API_KEY = \"openai/acme-web\"
STRIPE_SECRET_KEY = \"stripe/acme-web\"

[env.short]
SHORT_TOKEN = \"short/acme-web\"
";

/// Writes a project directory `name` in `home` with `manifest`, and
/// returns the manifest's path.
pub fn project(home: &TestHome, name: &str, manifest: &str) -> std::path::PathBuf {
    let dir = home.root().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("envcloak.toml");
    std::fs::write(&path, manifest).unwrap();
    path
}

/// Every sealed field value in `home`'s vault file, in the order the
/// items were seeded ([`SLUGS`]). Read before the daemon opens the file,
/// which it then holds exclusively.
pub fn sealed_values(home: &TestHome) -> Vec<Vec<u8>> {
    let raw = rusqlite::Connection::open(VaultPaths::under(data_dir(home)).db).unwrap();
    let sealed = raw
        .prepare("SELECT sealed_value FROM fields ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(raw);
    sealed
}

/// Flips one ciphertext bit (past the 24-byte nonce) in each of `sealed`
/// wherever it is stored: the vault file and its write-ahead log. Returns
/// how many values it found at least once.
pub fn flip_sealed_values(db: &std::path::Path, sealed: &[Vec<u8>]) -> usize {
    use std::os::unix::fs::FileExt;
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    let mut found = vec![false; sealed.len()];
    for path in [db.to_path_buf(), std::path::PathBuf::from(wal)] {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        for (i, s) in sealed.iter().enumerate() {
            for (at, _) in bytes
                .windows(s.len())
                .enumerate()
                .filter(|(_, w)| *w == s.as_slice())
            {
                let at = at + 30;
                file.write_at(&[bytes[at] ^ 0x10], at as u64).unwrap();
                found[i] = true;
            }
        }
        file.sync_all().unwrap();
    }
    found.iter().filter(|f| **f).count()
}
