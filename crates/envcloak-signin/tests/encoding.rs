//! The sign-in scope's and statement's canonical encodings (SPEC §6.8
//! "Sign-in scope" and "Approval"; R-M2b-11, R-M2b-12, R-M2b-14, SI-07):
//! golden vectors built from typed fields, an independent encoder of
//! docs/GRANTS.md's format, set order and duplicates, every field reaching
//! the encoding and the fingerprint, and the nonce and reserved context
//! staying out of the lookup fingerprint. Also the parsers of the typed
//! parts under hostile input (L-06) and the type-level rule that no field
//! can hold a secret.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use envcloak_core::vault::ItemId;
use envcloak_signin::{
    Account, AdapterId, CheckKind, ContextId, DaemonInstance, DeclaredCookie, DeclaredStorage,
    Delivery, DeliveryMode, Environment, Epochs, Host, IdentityCheck, Instance, KeyError, Label,
    Limits, Nonce, OperationKey, Options, OptionsError, Origin, ProjectScope, RequestId, Scheme,
    ScopeError, SignInScope, SignInStatement, SortedSet, Subject, Target, TargetId, Tier,
    TransferScope,
};
use proptest::prelude::*;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
enum RawHost {
    Name(String),
    V4([u8; 4]),
    V6([u8; 16]),
}

type RawOrigin = (Scheme, RawHost, u16);

/// A scope as typed fields, with every set in the order the test lists it.
#[derive(Debug, Clone)]
struct Raw {
    root: Instance,
    evidence: [u8; 32],
    dir: Vec<u8>,
    dev: u64,
    ino: u64,
    config: [u8; 32],
    login: [u8; 16],
    login_rev: u64,
    account: String,
    tenant: Option<String>,
    role: String,
    env: Environment,
    target: [u8; 16],
    target_rev: u64,
    adapter: [u8; 16],
    adapter_rev: u64,
    origins: Vec<RawOrigin>,
    check: (CheckKind, String),
    cookies: Vec<(RawHost, String)>,
    storage: Vec<(RawOrigin, String)>,
    requester: Instance,
    browser: u64,
    tier: Tier,
    attempts: u8,
    approval: u64,
    attempt_timeout: u64,
    session: u64,
    daemon: [u8; 16],
    vault: u64,
    policy: u64,
}

/// Fields in a scope's encoding.
const FIELDS: u16 = 31;

fn host(h: &RawHost) -> Result<Host, ScopeError> {
    match h {
        RawHost::Name(n) => Host::name(n),
        RawHost::V4(a) => Ok(Host::V4(*a)),
        RawHost::V6(a) => Ok(Host::V6(*a)),
    }
}

fn origin(o: &RawOrigin) -> Result<Origin, ScopeError> {
    Origin::new(o.0, host(&o.1)?, o.2)
}

fn host_json(h: &RawHost) -> Value {
    match h {
        RawHost::Name(n) => json!({ "name": n }),
        RawHost::V4(a) => json!({ "v4": a }),
        RawHost::V6(a) => json!({ "v6": hex(a) }),
    }
}

fn origin_json(o: &RawOrigin) -> Value {
    json!({
        "scheme": if o.0 == Scheme::Http { "http" } else { "https" },
        "host": host_json(&o.1),
        "port": o.2,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn inst_json(i: &Instance) -> Value {
    json!({ "pid": i.pid, "start_time": i.start_time })
}

impl Raw {
    fn scope(&self) -> Result<SignInScope, ScopeError> {
        SignInScope::new(
            Subject {
                root: self.root,
                evidence: self.evidence,
            },
            ProjectScope {
                dir: self.dir.clone(),
                dev: self.dev,
                ino: self.ino,
                config: self.config,
            },
            Account {
                login_item: ItemId::from_bytes(self.login),
                authorization_revision: self.login_rev,
                account: Label::new(&self.account)?,
                tenant: self.tenant.as_deref().map(Label::new).transpose()?,
                role: Label::new(&self.role)?,
                environment: self.env,
            },
            Target {
                id: TargetId::from_bytes(self.target),
                revision: self.target_rev,
                adapter: AdapterId::from_bytes(self.adapter),
                adapter_revision: self.adapter_rev,
                entry_origins: SortedSet::new(
                    self.origins.iter().map(origin).collect::<Result<_, _>>()?,
                )?,
                identity_check: IdentityCheck {
                    kind: self.check.0,
                    locator: Label::new(&self.check.1)?,
                },
                transfer: TransferScope {
                    cookies: SortedSet::new(
                        self.cookies
                            .iter()
                            .map(|(h, n)| {
                                Ok(DeclaredCookie {
                                    host: host(h)?,
                                    name: Label::new(n)?,
                                })
                            })
                            .collect::<Result<_, ScopeError>>()?,
                    )?,
                    storage: SortedSet::new(
                        self.storage
                            .iter()
                            .map(|(o, k)| {
                                Ok(DeclaredStorage {
                                    origin: origin(o)?,
                                    key: Label::new(k)?,
                                })
                            })
                            .collect::<Result<_, ScopeError>>()?,
                    )?,
                },
            },
            Delivery {
                mode: DeliveryMode::BrowserSession,
                requester: self.requester,
                browser: self.browser,
            },
            Limits::new(
                self.tier,
                self.attempts,
                Duration::from_secs(self.approval),
                Duration::from_secs(self.attempt_timeout),
                Duration::from_secs(self.session),
            )?,
            Epochs {
                daemon: DaemonInstance::from_bytes(self.daemon),
                vault: self.vault,
                policy: self.policy,
            },
        )
    }

    fn json(&self) -> Value {
        json!({
            "subject": { "root": inst_json(&self.root), "evidence": hex(&self.evidence) },
            "project": {
                "dir": hex(&self.dir), "dev": self.dev, "ino": self.ino,
                "config": hex(&self.config),
            },
            "account": {
                "login_item": hex(&self.login),
                "authorization_revision": self.login_rev,
                "account": self.account,
                "tenant": self.tenant,
                "role": self.role,
                "environment": if self.env == Environment::Test { "test" } else { "live" },
            },
            "target": {
                "id": hex(&self.target), "revision": self.target_rev,
                "adapter": hex(&self.adapter), "adapter_revision": self.adapter_rev,
                "entry_origins": self.origins.iter().map(origin_json).collect::<Vec<_>>(),
                "identity_check": {
                    "kind": if self.check.0 == CheckKind::Endpoint { "endpoint" } else { "element" },
                    "locator": self.check.1,
                },
                "cookies": self.cookies.iter()
                    .map(|(h, n)| json!({ "host": host_json(h), "name": n }))
                    .collect::<Vec<_>>(),
                "storage": self.storage.iter()
                    .map(|(o, k)| json!({ "origin": origin_json(o), "key": k }))
                    .collect::<Vec<_>>(),
            },
            "delivery": { "requester": inst_json(&self.requester), "browser": self.browser },
            "limits": {
                "tier": if self.tier == Tier::Each { "each" } else { "dev" },
                "attempts": self.attempts, "approval": self.approval,
                "attempt_timeout": self.attempt_timeout, "session_lifetime": self.session,
            },
            "epochs": { "daemon": hex(&self.daemon), "vault": self.vault, "policy": self.policy },
        })
    }
}

fn app(port: u16) -> RawOrigin {
    (Scheme::Http, RawHost::Name("app.localhost".into()), port)
}

/// The golden scope: every field a distinct, recognizable value.
fn golden() -> Raw {
    Raw {
        root: Instance {
            pid: 4321,
            start_time: 0x0102_0304_0506_0708,
        },
        evidence: [0xe1; 32],
        dir: b"/home/dev/app".to_vec(),
        dev: 0x2a,
        ino: 0x1234,
        config: [0xc0; 32],
        login: [0x10; 16],
        login_rev: 3,
        account: "editor@fixture.test".into(),
        tenant: Some("acme".into()),
        role: "editor".into(),
        env: Environment::Test,
        target: [0x20; 16],
        target_rev: 5,
        adapter: [0x30; 16],
        adapter_rev: 7,
        origins: vec![
            (
                Scheme::Https,
                RawHost::Name("login.example.test".into()),
                443,
            ),
            app(3000),
        ],
        check: (CheckKind::Endpoint, "/api/me".into()),
        cookies: vec![
            (RawHost::Name("app.localhost".into()), "session".into()),
            (RawHost::Name("app.localhost".into()), "csrf".into()),
        ],
        storage: vec![(app(3000), "token-meta".into())],
        requester: Instance {
            pid: 4400,
            start_time: 9,
        },
        browser: 2,
        tier: Tier::Dev,
        attempts: 3,
        approval: 8 * 3600,
        attempt_timeout: 600,
        session: 3600,
        daemon: [0xd0; 16],
        vault: 11,
        policy: 13,
    }
}

fn golden_statement(scope: SignInScope) -> SignInStatement {
    SignInStatement {
        scope,
        request: RequestId::from_bytes([0xab; 16]),
        nonce: Nonce::from_bytes([0x5a; 32]),
        created_unix: 1_700_000_000,
        expires_unix: 1_700_000_600,
        options: Options::Dev {
            window: Duration::from_secs(4 * 3600),
            attempts: 3,
        },
        context: ContextId::new(9),
    }
}

/// The encoding's fields: (number, value), after checking the domain line.
fn parse_fields<'a>(domain: &[u8], mut b: &'a [u8]) -> Vec<(u16, &'a [u8])> {
    assert!(b.starts_with(domain));
    b = &b[domain.len()..];
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = u16::from_be_bytes([b[0], b[1]]);
        let len = u32::from_be_bytes([b[2], b[3], b[4], b[5]]) as usize;
        out.push((n, &b[6..6 + len]));
        b = &b[6 + len..];
    }
    out
}

/// Golden vectors: the golden scope's encoding field by field as
/// docs/GRANTS.md lays it out, and the digests of it and of its
/// statement, which any change of format changes.
#[test]
fn golden_scope_and_statement_vectors() {
    let scope = golden().scope().unwrap();
    let enc = scope.encode();
    let fields = parse_fields(b"envcloak-signin-scope/1\n", &enc);
    assert_eq!(
        fields.iter().map(|f| f.0).collect::<Vec<_>>(),
        (1..=FIELDS).collect::<Vec<_>>()
    );
    let f = |n: u16| fields[usize::from(n) - 1].1;
    let mut root = 4321i32.to_be_bytes().to_vec();
    root.extend(0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(f(1), &root[..]);
    assert_eq!(f(3), b"/home/dev/app");
    assert_eq!(f(4), 0x2au64.to_be_bytes());
    assert_eq!(f(9), b"editor@fixture.test");
    assert_eq!(f(10), b"\x01acme");
    assert_eq!(f(12), [1]);
    // Origins sorted by their bytes: http (1) before https (2).
    let o = f(17);
    assert_eq!(&o[..4], 2u32.to_be_bytes());
    assert_eq!(&o[4..8], 37u32.to_be_bytes());
    assert_eq!(&o[8..13], b"\x00\x00\x00\x01\x01");
    // Cookies sorted: "csrf" before "session".
    let c = f(19);
    assert!(c.windows(4).position(|w| w == b"csrf") < c.windows(7).position(|w| w == b"session"));
    assert_eq!(f(21), [1]);
    assert_eq!(f(24), [2]);
    assert_eq!(f(25), [3]);
    assert_eq!(f(26), (8u64 * 3600).to_be_bytes());
    assert_eq!(f(29), [0xd0; 16]);
    assert_eq!(f(31), 13u64.to_be_bytes());
    let st = golden_statement(scope.clone());
    let canon = st.canonical();
    let sf = parse_fields(b"envcloak-signin-statement/1\n", &canon);
    assert_eq!(
        sf.iter().map(|f| f.0).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert_eq!(sf[0].1, &enc[..]);
    let mut dev = vec![2];
    dev.extend((4u64 * 3600).to_be_bytes());
    dev.push(3);
    assert_eq!(sf[5].1, &dev[..]);
    assert_eq!(sf[6].1, 9u64.to_be_bytes());
    assert_eq!(
        hex(scope.fingerprint().as_bytes()),
        "734594f854bf1ba62a84cabb19d30e66e4a54a33fd827aa9a289f04ce16b707d"
    );
    assert_eq!(
        hex(&st.digest()),
        "854d180e3be8a5dc885ccab708a54d6de6c61cec22a06768516f7faa5ebc45bd"
    );
}

/// Cases for the oracle: the golden scope, sets listed out of order,
/// multibyte and long labels, no tenant, negative pids, addresses as
/// hosts, the `each` tier, a live identity, extreme numbers.
fn oracle_cases() -> Vec<(Raw, SignInStatement)> {
    let mut cases = Vec::new();
    let g = golden();
    let mut push = |r: Raw| {
        let s = r.scope().unwrap();
        cases.push((r, golden_statement(s)));
    };
    push(g.clone());
    let mut r = g.clone();
    r.origins.reverse();
    r.cookies.reverse();
    r.storage.push((app(3001), "a".into()));
    push(r);
    let mut r = g.clone();
    r.account = "名前@例え.テスト".into();
    r.role = "é".repeat(128);
    r.tenant = None;
    r.root.pid = -1;
    r.requester.pid = i32::MIN;
    r.check = (CheckKind::Element, "#who \\ am i".into());
    r.dir = vec![0xff, 0x00, b'/', 0x80];
    push(r);
    let mut r = g.clone();
    r.origins = vec![
        (
            Scheme::Https,
            RawHost::V6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            8443,
        ),
        (Scheme::Http, RawHost::V4([127, 0, 0, 1]), 80),
        (
            Scheme::Http,
            RawHost::V6(std::net::Ipv6Addr::LOCALHOST.octets()),
            65535,
        ),
        (Scheme::Https, RawHost::V4([10, 0, 0, 1]), 1),
    ];
    r.cookies = vec![(RawHost::V4([127, 0, 0, 1]), "sid".into())];
    r.storage = Vec::new();
    r.tier = Tier::Each;
    r.attempts = 1;
    r.env = Environment::Live;
    r.dev = u64::MAX;
    r.vault = u64::MAX;
    r.browser = 0;
    push(r);
    cases
}

fn run_oracle(input: &Value) -> Vec<Value> {
    let oracle =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/signin_encoding.py");
    let mut child = std::process::Command::new("python3")
        .arg("-I")
        .arg(&oracle)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("python3 is needed on PATH");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(input).unwrap())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The encodings against an independent encoder of docs/GRANTS.md's
/// format (`tests/oracles/signin_encoding.py`, Python), byte for byte. The
/// oracle's unsorted encoding is its positive control: it differs from
/// the crate exactly for the case that lists its sets out of order, so the
/// comparison would see an encoding that kept the caller's order.
#[test]
fn the_encodings_match_an_independent_encoder() {
    let cases = oracle_cases();
    let input = Value::Array(
        cases
            .iter()
            .map(|(r, st)| {
                json!({
                    "scope": r.json(),
                    "statement": {
                        "request": hex(st.request.as_bytes()),
                        "nonce": hex(st.nonce.as_bytes()),
                        "created": st.created_unix,
                        "expires": st.expires_unix,
                        "options": match st.options {
                            Options::Once => json!("once"),
                            Options::Dev { window, attempts } =>
                                json!({ "window": window.as_secs(), "attempts": attempts }),
                        },
                        "context": st.context.get(),
                    },
                })
            })
            .collect(),
    );
    let got = run_oracle(&input);
    assert_eq!(got.len(), cases.len());
    let mut out_of_order = 0;
    for ((r, st), g) in cases.iter().zip(&got) {
        assert_eq!(hex(&st.scope.encode()), g["scope"], "{r:?}");
        assert_eq!(hex(&st.canonical()), g["statement"], "{r:?}");
        if g["unsorted"] != g["scope"] {
            out_of_order += 1;
        }
    }
    // The golden scope lists its origins and cookies out of order, and so
    // do the cases built from it and the address case; the second case
    // lists every set in order, where the control agrees.
    assert_eq!(out_of_order, 3);
    assert_eq!(got[1]["unsorted"], got[1]["scope"]);
    // Duplicates: the oracle refuses them as the crate does.
    let mut dup = golden();
    dup.cookies.push(dup.cookies[0].clone());
    assert_eq!(dup.scope().unwrap_err(), ScopeError::Duplicate);
    let input = json!([{ "scope": dup.json(), "statement": {} }]);
    assert_eq!(run_oracle(&input)[0]["duplicate"], true);
}

/// Listing a set in another order changes nothing; listing an element
/// twice is refused, in every set.
#[test]
fn set_order_does_not_change_the_encoding_and_duplicates_are_refused() {
    let g = golden();
    let mut r = g.clone();
    r.origins.reverse();
    r.cookies.reverse();
    assert_eq!(r.scope().unwrap().encode(), g.scope().unwrap().encode());
    let mut r = g.clone();
    r.origins.push(r.origins[1].clone());
    assert_eq!(r.scope().unwrap_err(), ScopeError::Duplicate);
    let mut r = g.clone();
    r.storage.push(r.storage[0].clone());
    assert_eq!(r.scope().unwrap_err(), ScopeError::Duplicate);
    let mut r = g.clone();
    r.cookies.push(r.cookies[1].clone());
    assert_eq!(r.scope().unwrap_err(), ScopeError::Duplicate);
    // An element differing only in a byte is not a duplicate.
    let mut r = g.clone();
    r.cookies
        .push((RawHost::Name("app.localhost".into()), "csrF".into()));
    assert!(r.scope().is_ok());
    let mut r = g;
    r.origins = (1..=65).map(app).collect();
    assert_eq!(r.scope().unwrap_err(), ScopeError::TooMany);
}

/// A raw scope from a seed: every field drawn, sets in drawn order.
fn raw_from(seed: u64) -> Raw {
    let mut x = seed | 1;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut g = golden();
    let pick =
        |n: u64, alphabet: &[&str]| alphabet[(n % alphabet.len() as u64) as usize].to_owned();
    let words = [
        "a", "editor", "ß", "名", "x-y", "Admin", "admin", "\\", "z9",
    ];
    g.root = Instance {
        pid: next() as i32,
        start_time: next(),
    };
    g.evidence = [next() as u8; 32];
    g.dev = next();
    g.ino = next();
    g.login_rev = next();
    g.account = format!("{}{}", pick(next(), &words), pick(next(), &words));
    g.tenant = (next() % 2 == 0).then(|| pick(next(), &words));
    g.role = pick(next(), &words);
    g.target_rev = next();
    g.adapter_rev = next();
    g.origins = (0..1 + next() % 4)
        .rev()
        .map(|i| app(1000 + i as u16))
        .collect();
    g.requester = Instance {
        pid: next() as i32,
        start_time: next(),
    };
    g.browser = next();
    g.vault = next();
    g.policy = next();
    g
}

/// `r` with field `n` (its number in the encoding) changed to another
/// valid value.
fn change(r: &Raw, n: u16) -> Raw {
    let mut r = r.clone();
    let other = |i: Instance| Instance {
        pid: i.pid.wrapping_add(1),
        start_time: i.start_time,
    };
    match n {
        1 => r.root = other(r.root),
        2 => r.evidence[31] ^= 1,
        3 => r.dir.push(b'x'),
        4 => r.dev ^= 1,
        5 => r.ino ^= 1,
        6 => r.config[0] ^= 1,
        7 => r.login[15] ^= 1,
        8 => r.login_rev ^= 1,
        9 => r.account.push('x'),
        10 => {
            r.tenant = if r.tenant.is_some() {
                None
            } else {
                Some("t".into())
            }
        }
        11 => r.role.push('s'),
        12 => {
            r.env = match r.env {
                Environment::Test => Environment::Live,
                Environment::Live => Environment::Test,
            }
        }
        13 => r.target[0] ^= 1,
        14 => r.target_rev ^= 1,
        15 => r.adapter[0] ^= 1,
        16 => r.adapter_rev ^= 1,
        17 => r
            .origins
            .push((Scheme::Https, RawHost::Name("other.test".into()), 443)),
        18 => r.check.1.push('/'),
        19 => r
            .cookies
            .push((RawHost::Name("app.localhost".into()), "extra".into())),
        20 => r.storage.push((app(3000), "extra".into())),
        22 => r.requester = other(r.requester),
        23 => r.browser ^= 1,
        24 => {
            r.tier = match r.tier {
                Tier::Each => Tier::Dev,
                Tier::Dev => Tier::Each,
            }
        }
        25 => r.attempts = if r.attempts == 2 { 3 } else { 2 },
        26 => r.approval += 1,
        27 => r.attempt_timeout += 1,
        28 => r.session += 1,
        29 => r.daemon[0] ^= 1,
        30 => r.vault ^= 1,
        31 => r.policy ^= 1,
        _ => unreachable!(),
    }
    r
}

/// The field numbers whose values differ between two encodings.
fn changed_fields(a: &[u8], b: &[u8]) -> Vec<u16> {
    let fa = parse_fields(b"envcloak-signin-scope/1\n", a);
    let fb = parse_fields(b"envcloak-signin-scope/1\n", b);
    assert_eq!(fa.len(), fb.len());
    fa.iter()
        .zip(&fb)
        .filter(|(x, y)| x.1 != y.1)
        .map(|(x, _)| x.0)
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Changing any one scope field changes exactly that field of the
    /// encoding, and so the encoding and the fingerprint; every field but
    /// the delivery mode (which has one value) is reached. A statement's
    /// nonce and reserved context never change the lookup fingerprint,
    /// though they change its digest.
    #[test]
    fn changing_any_one_field_changes_the_encoding_and_the_fingerprint(seed in any::<u64>()) {
        let base = raw_from(seed);
        let scope = base.scope().unwrap();
        let mut reached = BTreeSet::new();
        for n in (1..=FIELDS).filter(|n| *n != 21) {
            // A live identity needs the `each` tier, and `each` one
            // attempt: fields 12 and 24 are changed from a base with one
            // attempt on `each`, so only they move.
            let from = if n == 12 || n == 24 {
                let mut each = base.clone();
                each.tier = Tier::Each;
                each.attempts = 1;
                each
            } else {
                base.clone()
            };
            let to = change(&from, n);
            let a = from.scope().unwrap();
            let b = to.scope().unwrap();
            prop_assert_ne!(a.encode(), b.encode());
            prop_assert_ne!(a.fingerprint(), b.fingerprint());
            prop_assert_eq!(changed_fields(&a.encode(), &b.encode()), vec![n]);
            reached.insert(n);
        }
        prop_assert_eq!(reached.len(), usize::from(FIELDS) - 1);

        let st = golden_statement(scope.clone());
        let mut other = st.clone();
        other.nonce = Nonce::from_bytes([seed as u8 ^ 0x5b; 32]);
        other.context = ContextId::new(st.context.get() + 1 + seed % 7);
        prop_assert_eq!(st.lookup_fingerprint(), other.lookup_fingerprint());
        prop_assert_eq!(st.lookup_fingerprint(), scope.fingerprint());
        prop_assert_ne!(st.digest(), other.digest());
        let mut request = st.clone();
        request.request = RequestId::from_bytes([seed as u8; 16]);
        prop_assert_eq!(st.lookup_fingerprint(), request.lookup_fingerprint());
    }
}

/// Labels: 1 to 256 bytes, no control, invisible or direction-changing
/// character; the errors never hold the input.
#[test]
fn labels_refuse_hostile_text() {
    assert_eq!(Label::new("").unwrap_err(), ScopeError::EmptyLabel);
    assert!(Label::new(&"a".repeat(256)).is_ok());
    assert_eq!(
        Label::new(&"a".repeat(257)).unwrap_err(),
        ScopeError::LabelTooLong
    );
    // 128 two-byte characters fit; 129 do not.
    assert!(Label::new(&"é".repeat(128)).is_ok());
    assert_eq!(
        Label::new(&"é".repeat(129)).unwrap_err(),
        ScopeError::LabelTooLong
    );
    for bad in [
        "a\nb",
        "\u{0}",
        "a\u{202e}b",
        "a\u{200b}",
        "\u{7f}",
        "x\u{2028}",
        "\u{feff}",
    ] {
        assert_eq!(
            Label::new(bad).unwrap_err(),
            ScopeError::LabelCharacter,
            "{bad:?}"
        );
    }
    assert!(!ScopeError::LabelCharacter.to_string().contains('\u{202e}'));
}

/// Hosts as the browser serializes them, and http only for loopback.
#[test]
fn hosts_and_origins_take_only_the_registered_form() {
    for ok in [
        "a",
        "app.localhost",
        "xn--bcher-kva.example",
        "a-b.c9",
        &"a".repeat(63),
        "a.0xg",
        "0x1.a",
        "a.1x",
        "a.x0",
    ] {
        assert!(Host::name(ok).is_ok(), "{ok:?}");
    }
    let three = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63));
    assert!(Host::name(&format!("{three}.{}", "d".repeat(61))).is_ok());
    assert_eq!(
        Host::name(&format!("{three}.{}", "d".repeat(62))).unwrap_err(),
        ScopeError::Host
    );
    for bad in [
        "",
        "A.example",
        "a..b",
        ".a",
        "a.",
        "-a",
        "a-",
        "a_b",
        "a b",
        "a:1",
        "a/b",
        "1.2.3.4",
        "a.123",
        "a.0x",
        "a.0x1",
        "a.0xff",
        "0x1",
        "a.09",
        "bücher.example",
        "a\u{0}",
        &"a".repeat(64),
        "a@b",
    ] {
        assert_eq!(Host::name(bad).unwrap_err(), ScopeError::Host, "{bad:?}");
    }
    let h = |s: &str| Host::name(s).unwrap();
    assert!(Origin::new(Scheme::Http, h("app.localhost"), 80).is_ok());
    assert!(Origin::new(Scheme::Http, Host::V4([127, 0, 0, 1]), 80).is_ok());
    assert!(
        Origin::new(
            Scheme::Http,
            Host::V6(std::net::Ipv6Addr::LOCALHOST.octets()),
            80
        )
        .is_ok()
    );
    for bad in [
        h("localhost"),
        h("example.test"),
        h("localhost.example"),
        Host::V4([127, 0, 0, 2]),
        Host::V4([10, 0, 0, 1]),
    ] {
        assert_eq!(
            Origin::new(Scheme::Http, bad.clone(), 80).unwrap_err(),
            ScopeError::Scheme,
            "{bad:?}"
        );
        assert!(Origin::new(Scheme::Https, bad, 443).is_ok());
    }
    assert_eq!(
        Origin::new(Scheme::Https, h("a"), 0).unwrap_err(),
        ScopeError::Port
    );
}

/// Node, found on the test's `PATH`, run with a cleared environment. A
/// missing Node fails the test: the oracle is never skipped.
fn run_node(script: &str, input: &Value) -> Value {
    let node = std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|d| d.join("node"))
        .find(|p| p.is_file())
        .expect("node is needed on PATH for the host oracle");
    let oracle = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(script);
    let mut child = std::process::Command::new(node)
        .arg(&oracle)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(input).unwrap())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Every host name the crate accepts is one the browser serializes as
/// itself: Node's WHATWG URL parser (`tests/oracles/host_serialization.mjs`,
/// adapted from the origin-parsing oracle) reads each generated name the
/// crate accepted and must give it back byte for byte (plan D-26: hosts
/// "as the browser serializes them"; L-02, L-06). Positive controls: the
/// oracle rewrites or refuses names the crate must refuse (upper case,
/// Unicode, a last label it reads as a number), and the rule before this
/// one (only an all-digit last label refused) accepts names of this corpus
/// that the oracle refuses, so the comparison would catch it.
#[test]
fn every_accepted_host_name_is_one_the_browser_serializes_as_itself() {
    let labels = [
        "a",
        "app",
        "x0",
        "1x",
        "0x",
        "0x1",
        "0xg",
        "0xff",
        "0x0x",
        "1",
        "09",
        "123",
        "a-b",
        "xn--bcher-kva",
        "localhost",
        "-a",
        "a-",
        "A",
        "a_b",
        "",
    ];
    let mut names: Vec<String> = Vec::new();
    for a in labels {
        names.push(a.to_owned());
        for b in labels {
            names.push(format!("{a}.{b}"));
            for c in ["a", "0x1", "12", "localhost"] {
                names.push(format!("{a}.{b}.{c}"));
            }
        }
    }
    let accepted: Vec<&String> = names.iter().filter(|n| Host::name(n).is_ok()).collect();
    let refused = names.len() - accepted.len();
    assert!(
        accepted.len() > 500 && refused > 1000,
        "{} {refused}",
        accepted.len()
    );
    let got = run_node("tests/oracles/host_serialization.mjs", &json!(accepted));
    let hostnames = got["hostnames"].as_array().unwrap();
    assert_eq!(hostnames.len(), accepted.len());
    let differ: Vec<&&String> = accepted
        .iter()
        .zip(hostnames)
        .filter(|(n, h)| h.as_str() != Some(n.as_str()))
        .map(|(n, _)| n)
        .collect();
    assert!(
        differ.is_empty(),
        "the browser rewrites or refuses {differ:?}"
    );
    // The oracle tells a non-canonical name apart.
    let controls = [
        "App.example",
        "b\u{fc}cher.example",
        "a.0x1",
        "a.123",
        "a.0x",
        "0x7f.1",
    ];
    let got = run_node("tests/oracles/host_serialization.mjs", &json!(controls));
    for (name, h) in controls.iter().zip(got["hostnames"].as_array().unwrap()) {
        assert_ne!(h.as_str(), Some(*name), "{name:?}");
        assert!(Host::name(name).is_err(), "{name:?}");
    }
    // The earlier rule, applied to the same corpus, accepts names the
    // oracle refuses.
    let earlier = |s: &str| {
        let labels: Vec<&str> = s.split('.').collect();
        labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }) && !labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    };
    let wider: Vec<&String> = names.iter().filter(|n| earlier(n)).collect();
    let got = run_node("tests/oracles/host_serialization.mjs", &json!(wider));
    let caught = wider
        .iter()
        .zip(got["hostnames"].as_array().unwrap())
        .filter(|(n, h)| h.as_str() != Some(n.as_str()))
        .count();
    assert!(caught > 0);
}

/// Limits, options and the scope's own rules.
#[test]
fn limits_and_options_are_bounded() {
    let d = Duration::from_secs;
    assert!(Limits::new(Tier::Each, 1, d(60), d(60), d(60)).is_ok());
    assert_eq!(
        Limits::new(Tier::Each, 2, d(60), d(60), d(60)).unwrap_err(),
        ScopeError::Attempts
    );
    assert_eq!(
        Limits::new(Tier::Dev, 0, d(60), d(60), d(60)).unwrap_err(),
        ScopeError::Attempts
    );
    assert_eq!(
        Limits::new(Tier::Dev, 6, d(60), d(60), d(60)).unwrap_err(),
        ScopeError::Attempts
    );
    assert!(Limits::new(Tier::Dev, 5, d(24 * 3600), d(3600), d(24 * 3600)).is_ok());
    for (a, t, s) in [
        (d(24 * 3600 + 1), d(60), d(60)),
        (d(60), d(3601), d(60)),
        (d(60), d(60), d(24 * 3600 + 1)),
        (d(0), d(60), d(60)),
        (Duration::from_millis(1500), d(60), d(60)),
    ] {
        assert_eq!(
            Limits::new(Tier::Dev, 3, a, t, s).unwrap_err(),
            ScopeError::Duration
        );
    }
    let dev = Limits::new(Tier::Dev, 4, d(3600), d(60), d(60)).unwrap();
    let each = Limits::new(Tier::Each, 1, d(3600), d(60), d(60)).unwrap();
    assert_eq!(
        Options::default_for(&dev),
        Options::Dev {
            window: d(3600),
            attempts: 3
        }
    );
    assert_eq!(Options::default_for(&each), Options::Once);
    let two = Limits::new(Tier::Dev, 2, d(3600), d(60), d(60)).unwrap();
    assert_eq!(
        Options::default_for(&two),
        Options::Dev {
            window: d(3600),
            attempts: 2
        }
    );
    assert_eq!(Options::Once.allowed_by(&dev), Ok(()));
    let opt = |w, a| Options::Dev {
        window: d(w),
        attempts: a,
    };
    assert_eq!(opt(3600, 4).allowed_by(&dev), Ok(()));
    assert_eq!(opt(3600, 5).allowed_by(&dev), Err(OptionsError::Attempts));
    assert_eq!(opt(3600, 0).allowed_by(&dev), Err(OptionsError::Attempts));
    assert_eq!(opt(3601, 1).allowed_by(&dev), Err(OptionsError::Window));
    assert_eq!(opt(0, 1).allowed_by(&dev), Err(OptionsError::Window));
    assert_eq!(opt(60, 1).allowed_by(&each), Err(OptionsError::NotDev));
    let mut r = golden();
    r.env = Environment::Live;
    assert_eq!(r.scope().unwrap_err(), ScopeError::LiveDev);
    let mut r = golden();
    r.origins.clear();
    assert_eq!(r.scope().unwrap_err(), ScopeError::NoOrigin);
}

/// `operation_key`: 1 to 128 of `[A-Za-z0-9._-]`; refused input is never
/// echoed, and the key shows nowhere in `Debug`.
#[test]
fn operation_keys_are_bounded_and_never_shown() {
    assert!(OperationKey::parse("a").is_ok());
    assert!(OperationKey::parse(&"Az09._-".repeat(19)[..128]).is_ok());
    assert_eq!(OperationKey::parse("").unwrap_err(), KeyError::Empty);
    assert_eq!(
        OperationKey::parse(&"a".repeat(129)).unwrap_err(),
        KeyError::TooLong
    );
    for bad in ["a b", "a/b", "é", "a\u{0}", "a\n", "a+b", "\u{202e}"] {
        let e = OperationKey::parse(bad).unwrap_err();
        assert_eq!(e, KeyError::Character, "{bad:?}");
        assert!(!format!("{e} {e:?}").contains(bad));
    }
    let k = OperationKey::parse("intent-marker-7c1").unwrap();
    assert_eq!(format!("{k:?}"), "OperationKey(..)");
    assert_eq!(k, OperationKey::parse("intent-marker-7c1").unwrap());
    assert_ne!(k, OperationKey::parse("intent-marker-7c").unwrap());
    assert_ne!(k, OperationKey::parse("intent-marker-7c10").unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The parsers take any text without panicking and accept exactly
    /// their grammar, checked here by a separate reading of it.
    #[test]
    fn parsers_accept_exactly_their_grammar(s in "\\PC{0,140}|[a-z0-9.-]{0,70}|[A-Za-z0-9._-]{0,130}|[a-z0-9-]{1,6}(\\.(0x[0-9a-fA-F]{0,3}|[0-9]{1,3}|[a-z0-9-]{1,6})){0,3}") {
        let key_ok = !s.is_empty()
            && s.len() <= 128
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        prop_assert_eq!(OperationKey::parse(&s).is_ok(), key_ok);
        let labels: Vec<&str> = s.split('.').collect();
        let host_ok = !s.is_empty()
            && s.len() <= 253
            && labels.iter().all(|l| {
                (1..=63).contains(&l.len())
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            && !{
                // The URL standard's "ends in a number": decimal, or 0x
                // and hex digits (none at all included).
                let last = labels.last().unwrap();
                last.bytes().all(|b| b.is_ascii_digit())
                    || (last.starts_with("0x")
                        && last[2..].bytes().all(|b| b.is_ascii_hexdigit()))
            };
        prop_assert_eq!(Host::name(&s).is_ok(), host_ok);
        let label_ok = !s.is_empty()
            && s.len() <= 256
            && !s.chars().any(|c| c.is_control() || envcloak_policy::display_escaped(c));
        prop_assert_eq!(Label::new(&s).is_ok(), label_ok);
    }
}

/// No scope field can hold a secret: the scope derives `Clone`, `Eq`,
/// `Ord` and `Hash`, which the secret wrappers do not implement.
#[test]
fn no_scope_field_can_hold_a_secret() {
    static_assertions::assert_impl_all!(SignInScope: Clone, Eq, Ord, std::hash::Hash, Send, Sync);
    static_assertions::assert_not_impl_any!(envcloak_core::SecretBytes: Clone, PartialEq, Ord, std::hash::Hash);
    static_assertions::assert_not_impl_any!(envcloak_core::SecretBuf: Clone, PartialEq, Ord, std::hash::Hash);
}
