//! A covered `run.request`'s answer and the frame it goes out in (F-77;
//! gates 30 and 32, and 33's audit before release): the answer is framed,
//! as it will be sent, before its entry is written or its grant used, so
//! values that make an answer larger than one frame (1 MiB) release
//! nothing, leave the grant as it was and are audited as refused, while
//! an answer of exactly one frame goes out whole.
//!
//! The caller is this test process, a terminal session (see
//! `tests/grants.rs`); the covered requests go over a raw connection, so
//! the test chooses the request's id and reads the answer's frame header.
//! Every value is generated here, and swept for in the daemon's log and
//! the home.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Read;
use std::time::Duration;

use base64::Engine as _;
use common::{client, data_dir, passphrase, raw, send_json, start};
use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::proto::{ErrorKind, ReleasedValue, RunAnswer, RunRequestParams, result_frame};
use envcloak_ipc::view::DecisionView;
use envcloak_ipc::{ClientError, MAX_FRAME, WireSecret};
use envcloak_policy::{ApprovalOptions, Mode, statement_digest};
use envcloak_testkit::{Canary, Daemon, TestHome, assert_no_canary, canaries, fresh_seed};

/// The large item's value: 48 KiB, 64 KiB as base64.
const BIG: usize = 48 * 1024;
/// How many variables the large item is bound under.
const ALIASES: usize = 15;
/// The JSON-RPC id of every covered request here.
const ID: u64 = 7;
/// The shortest name of the variable the tuning item is bound under.
const TUNE_MIN: usize = 8;

/// `n` bytes of lower-case hex from `seed`, never key-shaped.
fn generated(seed: &mut u64, n: usize) -> String {
    (0..n)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            char::from(b"0123456789abcdef"[(*seed & 15) as usize])
        })
        .collect()
}

/// The variable the tuning item is bound under, `n` characters long.
fn tune_name(n: usize) -> String {
    format!("TUNE_VAR{}", "X".repeat(n - TUNE_MIN))
}

fn big_name(i: usize) -> String {
    format!("BIG_{i:02}")
}

/// The length of the frame answering request [`ID`] with `values`
/// (variable, slug, value length) under a grant: computed with values of
/// the same lengths, as the daemon frames them.
fn answer_len(values: &[(String, &str, usize)]) -> usize {
    let answer = RunAnswer {
        decision: DecisionView::Covered {
            grant: "0".repeat(26),
            redact: true,
            mode: Mode::Inject,
            manifest_changed: false,
        },
        values: values
            .iter()
            .map(|(env_name, slug, len)| ReleasedValue {
                env_name: env_name.clone(),
                slug: (*slug).to_owned(),
                allow_short: false,
                value: WireSecret::new(SecretBytes::copy_from(&vec![b'a'; *len])),
            })
            .collect(),
    };
    result_frame(ID, &answer).unwrap().len()
}

/// The sizes: the tuning item's value length, and the name length of its
/// variable at which the answer to all the bindings is one byte under a
/// frame (one more is exactly a frame, two more one byte over).
fn sizes() -> (usize, usize) {
    // Every value 3 bytes (4 of base64), the tuning name its shortest.
    let mut small: Vec<(String, &str, usize)> = (0..ALIASES)
        .map(|i| (big_name(i), "big/value", 3))
        .collect();
    small.push((tune_name(TUNE_MIN), "tune/value", 3));
    let base = answer_len(&small);
    // Each large value adds its base64 less the 4 counted; the tuning
    // value of 3m bytes adds 4m less the 4 counted; a name, its length.
    let fixed = base + ALIASES * (BIG / 3 * 4 - 4) - 4;
    let m = (MAX_FRAME - 1 - fixed) / 4;
    let name = MAX_FRAME - 1 - fixed - 4 * m + TUNE_MIN;
    (3 * m, name)
}

/// A vault with the large item and the tuning item, a daemon with it
/// unlocked, and the project.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
    big: Vec<u8>,
    tune: Vec<u8>,
    name: usize,
}

impl Fixture {
    fn new() -> Self {
        common::terminal_session();
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let (tune_len, name) = sizes();
        let mut seed = fresh_seed() | 1;
        let big = generated(&mut seed, BIG);
        let tune = generated(&mut seed, tune_len);
        cs.push(Canary::new("BIG_VALUE", big.clone()));
        cs.push(Canary::new("TUNE_VALUE", tune.clone()));
        let kit = RecoveryKit::generate();
        cs.push(Canary::new("RECOVERY_KIT", kit.to_display().to_string()));
        let paths = VaultPaths::under(data_dir(&home));
        let mut v =
            create_vault_with_kit(&paths, &passphrase(&cs), &kit, KdfParams::minimum()).unwrap();
        v.transact(|t| {
            for (slug, value) in [("big/value", &big), ("tune/value", &tune)] {
                let id = t.create_item(NewItem {
                    class: ItemClass::Secret,
                    slug: Slug::new(slug).unwrap(),
                    details: ItemDetails::default(),
                })?;
                t.add_field(
                    id,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(value.as_bytes()),
                )?;
            }
            Ok(())
        })
        .unwrap();
        drop(v);
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        let manifest = common::project(&home, "budget", "[project]\nname = \"budget\"\n");
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
            big: big.into_bytes(),
            tune: tune.into_bytes(),
            name,
        }
    }

    /// A request for the large item under `aliases` variables and the
    /// tuning item under a name `extra` characters longer than the one
    /// whose answer is a byte under a frame.
    fn params(&self, aliases: usize, extra: usize, argv: &str) -> RunRequestParams {
        let mut refs: Vec<String> = (0..aliases)
            .map(|i| format!("{}=big/value", big_name(i)))
            .collect();
        refs.push(format!("{}=tune/value", tune_name(self.name + extra)));
        RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs,
            env_file: None,
            argv: vec!["./emit".to_owned(), argv.to_owned()],
            claims: Vec::new(),
        }
    }

    /// Opens `p` as a pending request and approves it with `opts`.
    /// Returns the grant.
    fn approved(&self, p: &RunRequestParams, opts: ApprovalOptions) -> String {
        let mut c = client(&self.home);
        let id = match c.run_request(p).unwrap().decision {
            DecisionView::Pending { request } => request,
            other => panic!("expected pending, got {other:?}"),
        };
        let d = c.pending_get(&id, &[]).unwrap();
        let digest = statement_digest(&d, &opts);
        c.approve(&id, opts, &digest, passphrase(&self.cs), &[])
            .unwrap()
            .grant
    }

    /// Sends `p` as request [`ID`] over a raw connection, and returns the
    /// answer's frame length and body.
    fn raw_run(&self, p: &RunRequestParams) -> (usize, serde_json::Value) {
        let mut s = raw(&self.home);
        send_json(
            &mut s,
            &serde_json::json!({"jsonrpc": "2.0", "id": ID, "method": "run.request", "params": p}),
        );
        let mut header = [0u8; 4];
        s.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        (len, serde_json::from_slice(&body).unwrap())
    }

    /// Checks a covered answer: under `grant`, each variable with its
    /// item's value, as `p` bound them.
    fn delivered(&self, answer: &serde_json::Value, p: &RunRequestParams, grant: &str) {
        let r = &answer["result"];
        assert_eq!(r["decision"]["decision"], "covered", "{}", r["decision"]);
        assert_eq!(r["decision"]["grant"], grant);
        let values = r["values"].as_array().unwrap();
        assert_eq!(values.len(), p.refs.len());
        for (v, binding) in values.iter().zip(&p.refs) {
            let (name, slug) = binding.split_once('=').unwrap();
            assert_eq!(v["env_name"], name);
            let want = if slug == "big/value" {
                &self.big
            } else {
                &self.tune
            };
            let got = base64::engine::general_purpose::STANDARD
                .decode(v["value"].as_str().unwrap())
                .unwrap();
            assert!(got == *want, "{name}: not its item's value");
        }
    }

    fn holds(&self, grant: &str) -> bool {
        client(&self.home)
            .grants_list()
            .unwrap()
            .grants
            .iter()
            .any(|g| g.id == grant)
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn once() -> ApprovalOptions {
    ApprovalOptions::once(Duration::from_secs(600))
}

/// F-77 (gates 30 and 32): answers of one byte under a frame and of
/// exactly a frame are delivered whole under a `once` grant, which each
/// uses; one byte over is refused `frame_too_large` before anything is
/// committed: no value goes out, no delivery is audited (the refusal is,
/// with its grant), and the `once` grant stays, so a smaller request
/// (one variable fewer) is covered by it, once.
///
/// Mutation: frame the answer after the grant is used and the delivery
/// audited (as before the fix): the oversized answer is still refused,
/// but the `once` grant is gone and the smaller request is pending.
#[test]
fn an_answer_over_a_frame_releases_nothing_and_keeps_the_once_grant() {
    let f = Fixture::new();
    for (extra, len) in [(0, MAX_FRAME - 1), (1, MAX_FRAME)] {
        let p = f.params(ALIASES, extra, &format!("fits-{extra}"));
        let grant = f.approved(&p, once());
        let (got, answer) = f.raw_run(&p);
        assert_eq!(got, len, "the model of the answer's size is off");
        f.delivered(&answer, &p, &grant);
        assert!(!f.holds(&grant), "a once grant is used by its delivery");
    }

    let over = f.params(ALIASES, 2, "over");
    let grant = f.approved(&over, once());
    let (_, answer) = f.raw_run(&over);
    assert_eq!(
        answer["error"]["data"]["kind"], "frame_too_large",
        "{answer}"
    );
    assert!(answer.get("result").is_none());
    assert!(
        f.holds(&grant),
        "the once grant was used by an answer never sent"
    );
    // Over a client, the same refusal.
    let e = client(&f.home).run_request(&over).unwrap_err();
    assert!(
        matches!(e, ClientError::Rpc(ref r) if r.kind == ErrorKind::FrameTooLarge),
        "{e:?}"
    );
    assert!(f.holds(&grant));
    let log = f.d.log();
    assert_eq!(
        log.matches(&format!("request decision=frame_too_large id={grant} "))
            .count(),
        2,
        "{log}"
    );
    assert!(!log.contains(&format!("request decision=covered id={grant} ")));

    // One variable fewer: covered by the grant the refusal kept, once.
    let smaller = f.params(ALIASES - 1, 2, "over");
    let (_, answer) = f.raw_run(&smaller);
    f.delivered(&answer, &smaller, &grant);
    assert!(!f.holds(&grant));
    let again = client(&f.home).run_request(&smaller).unwrap();
    assert!(matches!(again.decision, DecisionView::Pending { .. }));
    assert_eq!(
        f.d.log()
            .matches(&format!("request decision=covered id={grant} "))
            .count(),
        1
    );
    f.sweep();
}

/// F-77 under a `session` grant: an answer over a frame is refused each
/// time and the grant stays; smaller requests are covered by it as often
/// as asked; revoked, it covers nothing more.
#[test]
fn an_answer_over_a_frame_leaves_a_session_grant_as_it_was() {
    let f = Fixture::new();
    let over = f.params(ALIASES, 2, "session");
    let grant = f.approved(&over, ApprovalOptions::session(Duration::from_secs(600)));
    for _ in 0..2 {
        let (_, answer) = f.raw_run(&over);
        assert_eq!(
            answer["error"]["data"]["kind"], "frame_too_large",
            "{answer}"
        );
        assert!(f.holds(&grant));
    }
    let smaller = f.params(ALIASES - 1, 2, "session");
    for _ in 0..2 {
        let (_, answer) = f.raw_run(&smaller);
        f.delivered(&answer, &smaller, &grant);
        assert!(f.holds(&grant));
    }
    assert_eq!(
        client(&f.home).grants_revoke(Some(&grant)).unwrap().revoked,
        1
    );
    let after = client(&f.home).run_request(&smaller).unwrap();
    assert!(matches!(after.decision, DecisionView::Pending { .. }));
    f.sweep();
}
