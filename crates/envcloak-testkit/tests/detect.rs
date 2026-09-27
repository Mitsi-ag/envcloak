//! The canary toolkit: generation, every listed encoding is detected
//! (including output of independent encoders), failure messages carry no
//! value, and directory sweeps neither follow symlinks nor hang.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use envcloak_testkit::{
    Canary, Detector, Hit, TEST_ENV_VARS, TestHome, assert_no_canary, by_label, canaries,
    encodings, find, fresh_seed, labels, sweep_dir,
};

fn panic_message(f: impl FnOnce()) -> Option<String> {
    let err = catch_unwind(AssertUnwindSafe(f)).err()?;
    Some(
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default(),
    )
}

/// Bytes that cannot contain a canary: a run of `~`.
fn noise(n: usize) -> Vec<u8> {
    vec![b'~'; n]
}

#[test]
fn canaries_are_deterministic_and_shaped_like_the_story_fixtures() {
    let seed = fresh_seed();
    let a = canaries(seed);
    let b = canaries(seed);
    let c = canaries(seed.wrapping_add(1));
    assert_eq!(a.len(), 7);
    for (x, y) in a.iter().zip(&b) {
        assert_eq!(x.label, y.label);
        assert_eq!(x.value(), y.value());
    }
    for (x, y) in a.iter().zip(&c) {
        assert_ne!(x.value(), y.value(), "{} must depend on the seed", x.label);
    }
    let values: std::collections::HashSet<&[u8]> = a.iter().map(Canary::value).collect();
    assert_eq!(values.len(), a.len(), "canaries must be distinct");

    let openai = by_label(&a, labels::OPENAI_API_KEY).as_str();
    assert_eq!(openai.len(), 64);
    assert!(openai.starts_with(concat!("sk", "-proj-")));
    assert_eq!(
        by_label(&a, labels::OPENAI_API_KEY_ROTATED).value().len(),
        64
    );
    assert!(
        by_label(&a, labels::STRIPE_SECRET_KEY)
            .as_str()
            .starts_with(concat!("sk", "_test_"))
    );
    assert!(
        by_label(&a, labels::GITHUB_TOKEN)
            .as_str()
            .starts_with(concat!("gh", "p_"))
    );
    let url = by_label(&a, labels::DATABASE_URL).as_str();
    let password = url
        .strip_prefix("postgres://acme:")
        .and_then(|r| r.split_once("@db.acme.internal"))
        .map(|(p, _)| p)
        .unwrap();
    for special in ['/', '"', '+', ' '] {
        assert!(password.contains(special), "password needs {special:?}");
    }
    assert!(!password.is_ascii());
    assert_eq!(by_label(&a, labels::SHORT_TOKEN).value().len(), 10);
    assert!(
        by_label(&a, labels::VAULT_PASSPHRASE)
            .as_str()
            .contains(' ')
    );
}

#[test]
fn debug_output_never_shows_a_value() {
    let cs = canaries(fresh_seed());
    for c in &cs {
        let shown = format!("{c:?} {c:#?}");
        assert!(shown.contains(&c.label));
        assert!(find(shown.as_bytes(), &cs).is_empty(), "{}", c.label);
    }
    let detector = format!("{:?}", Detector::new(&cs));
    assert!(find(detector.as_bytes(), &cs).is_empty());
}

#[test]
fn assert_no_canary_detects_every_encoding() {
    let cs = canaries(fresh_seed());
    let detector = Detector::new(&cs);
    let mut checked = 0;
    for c in &cs {
        let encs = encodings(c);
        // Identical encodings are listed once (a value with no characters to
        // escape has the same bytes raw and percent- or JSON-encoded), but
        // raw, hex and base64 always differ. (Upper-case hex can equal the
        // lower-case form when no byte has a hex letter.)
        for name in ["raw", "hex-lower", "base64", "base64-at-1", "base64-at-2"] {
            assert!(
                encs.iter().any(|(n, _)| *n == name),
                "{} lacks {name}",
                c.label
            );
        }
        for (name, bytes) in &encs {
            let mut hay = noise(33);
            hay.extend_from_slice(bytes);
            hay.extend_from_slice(&noise(17));
            let found = detector.find(&hay);
            assert!(
                found
                    .iter()
                    .any(|f| f.label == c.label && f.encoding == *name),
                "{} as {name} was not detected",
                c.label
            );
            let msg = panic_message(|| assert_no_canary(&hay, &cs))
                .unwrap_or_else(|| panic!("{} as {name} did not fail the assertion", c.label));
            assert!(msg.contains(&c.label), "message must name the label");
            assert!(msg.contains("canary leak"), "{msg}");
            assert!(
                find(msg.as_bytes(), &cs).is_empty(),
                "message leaked a value"
            );
            checked += 1;
        }
    }
    assert!(checked >= 7 * 12, "only {checked} encodings checked");
}

#[test]
fn clean_and_near_miss_haystacks_pass() {
    let cs = canaries(fresh_seed());
    assert_no_canary(&noise(4096), &cs);
    assert_no_canary(b"", &cs);
    let c = by_label(&cs, labels::GITHUB_TOKEN);
    let mut near = c.value().to_vec();
    let last = near.len() - 1;
    near[last] = b'~';
    assert!(
        !find(&near, &cs).iter().any(|f| f.encoding == "raw"),
        "a changed byte is not the value"
    );
}

#[test]
fn independent_encoders_are_detected() {
    let cs = canaries(fresh_seed());
    let detector = Detector::new(&cs);
    for c in &cs {
        let v = c.value();
        let hit = |hay: &[u8], what: &str| {
            assert!(
                detector.find(hay).iter().any(|f| f.label == c.label),
                "{} not detected in {what}",
                c.label
            );
        };
        for (engine, what) in [
            (&STANDARD, "base64"),
            (&STANDARD_NO_PAD, "base64 no pad"),
            (&URL_SAFE, "base64url"),
            (&URL_SAFE_NO_PAD, "base64url no pad"),
        ] {
            hit(engine.encode(v).as_bytes(), what);
            // Embedded in a larger payload at each alignment.
            for offset in 0..3 {
                let mut payload = vec![0xA5u8; offset + 5];
                payload.extend_from_slice(v);
                payload.extend_from_slice(&[0x5A; 7]);
                hit(engine.encode(&payload).as_bytes(), what);
            }
        }
        hit(
            serde_json::to_string(c.as_str()).unwrap().as_bytes(),
            "serde_json",
        );
        let form: String = form_urlencoded::byte_serialize(v).collect();
        hit(form.as_bytes(), "form_urlencoded");
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        hit(hex.as_bytes(), "hex");
        hit(hex.to_uppercase().as_bytes(), "HEX");
    }
}

#[test]
fn sweep_dir_reports_hits_and_never_follows_symlinks_or_hangs() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let outside = TestHome::new();
    let stripe = by_label(&cs, labels::STRIPE_SECRET_KEY);
    let github = by_label(&cs, labels::GITHUB_TOKEN);

    let root = home.home();
    std::fs::write(root.join("clean.txt"), noise(100)).unwrap();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    let hex: String = stripe.value().iter().map(|b| format!("{b:02X}")).collect();
    std::fs::write(root.join("a/b/log.txt"), format!("noise {hex} noise")).unwrap();

    // A symlink to a file outside the tree that holds a canary: not followed.
    let secret_outside = outside.root().join("secret.txt");
    std::fs::write(&secret_outside, github.value()).unwrap();
    std::os::unix::fs::symlink(&secret_outside, root.join("link")).unwrap();
    // A directory symlink loop: not followed.
    std::os::unix::fs::symlink(&root, root.join("a/loop")).unwrap();
    // A FIFO with no writer: skipped, not opened.
    let fifo = root.join("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    let hits = sweep_dir(home.root(), &cs);
    let canary_hits: Vec<_> = hits
        .iter()
        .filter_map(|h| match h {
            Hit::Canary { path, found } => Some((path, found)),
            Hit::Unreadable { .. } => None,
        })
        .collect();
    assert!(!canary_hits.is_empty());
    for (path, found) in &canary_hits {
        assert!(path.ends_with("a/b/log.txt"), "{path:?}");
        assert_eq!(found.label, labels::STRIPE_SECRET_KEY);
        assert_eq!(found.encoding, "hex-upper");
    }
    assert!(
        !hits.iter().any(|h| matches!(h, Hit::Unreadable { .. })),
        "{hits:?}"
    );
    assert_eq!(home.sweep(&cs), hits);

    // An unreadable file is reported, since the sweep cannot vouch for it.
    let locked = root.join("locked.txt");
    std::fs::write(&locked, b"x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read anything, so the check only applies to other users.
    if std::fs::read(&locked).is_err() {
        let hits = sweep_dir(home.root(), &cs);
        assert!(
            hits.iter()
                .any(|h| matches!(h, Hit::Unreadable { path, .. } if path == &locked)),
            "{hits:?}"
        );
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn test_home_is_short_isolated_and_complete() {
    let home = TestHome::new();
    let root = home.root();
    assert!(root.starts_with("/tmp"));
    assert!(
        root.as_os_str().len() <= 16,
        "{root:?} is too long for socket paths"
    );
    for sub in ["home", "config", "data", "state", "cache", "tmp", "run"] {
        assert!(root.join(sub).is_dir(), "{sub}");
    }
    let mode = std::fs::metadata(root.join("run"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);

    let out = home
        .apply(&mut Command::new("sh"))
        .args([
            "-c",
            "printf '%s\\n' \"$HOME\" \"$XDG_RUNTIME_DIR\" \"$TMPDIR\"",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], home.home().to_str().unwrap());
    assert_eq!(lines[1], root.join("run").to_str().unwrap());
    assert_eq!(lines[2], root.join("tmp").to_str().unwrap());
    let kept = root.to_path_buf();
    drop(home);
    assert!(!kept.exists(), "the tree is removed on drop");
}

const ISOLATION_CHILD: &str = "ENVCLOAK_TESTKIT_ISOLATION_CHILD";
const PARENT_ONLY: &str = "ENVCLOAK_TESTKIT_PARENT_ONLY";

/// Runs only as the child started by the test below, whose environment
/// holds a marker the child's own children must not see.
#[test]
fn isolation_child() {
    if std::env::var_os(ISOLATION_CHILD).is_none() {
        return;
    }
    let marker = std::env::var(PARENT_ONLY).unwrap();
    let env_of = |cmd: &mut Command| {
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    };

    // Control: by default a child inherits the marker.
    let inherited = env_of(&mut Command::new("/usr/bin/env"));
    assert!(
        inherited.contains(&marker),
        "control: the marker must be inherited"
    );

    let home = TestHome::new();
    let isolated = env_of(home.apply(&mut Command::new("/usr/bin/env")));
    assert!(
        !isolated.contains(&marker),
        "a parent-only variable reached the child"
    );
    let names: Vec<&str> = isolated
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        .collect();
    for name in &names {
        assert!(TEST_ENV_VARS.contains(name), "unexpected variable {name}");
    }
    assert_eq!(names.len(), TEST_ENV_VARS.len(), "{names:?}");
    println!("isolation: checked");
}

#[test]
fn test_home_children_inherit_nothing_from_the_parent() {
    // A fabricated marker stands in for an exported credential.
    let marker = format!("parent-only-{:016x}", fresh_seed());
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolation_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ISOLATION_CHILD, "1")
        .env(PARENT_ONLY, &marker)
        .output()
        .unwrap();
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("isolation: checked"),
        "the child did not run the check: {out:?}"
    );
}
