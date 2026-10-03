//! Shared by the sign-in contract tests: a world the test moves by hand,
//! a clock, and scopes built from typed fields.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envcloak_core::vault::ItemId;
use envcloak_policy::Now;
use envcloak_signin::{
    Account, AdapterId, CheckKind, DaemonInstance, DeclaredCookie, DeclaredStorage, Delivery,
    DeliveryMode, Environment, Epochs, Host, IdentityCheck, IdentityResponse, Instance, Label,
    Limits, Origin, ProjectScope, Revisions, Scheme, SignInScope, SortedSet, Subject, Target,
    TargetId, Tier, TransferScope, World,
};

pub const DAEMON: DaemonInstance = DaemonInstance::from_bytes([7; 16]);

/// The clock `t` seconds after the test's origin: wall and awake time
/// move together.
pub fn at(t: u64) -> Now {
    Now {
        wall: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + t),
        awake: Duration::from_secs(t),
        including_sleep: Duration::from_secs(t),
    }
}

pub fn wall(t: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000 + t)
}

/// The world: one set of epochs and revisions, and the processes that
/// exited.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestWorld {
    pub epochs: Epochs,
    pub login: u64,
    pub target: u64,
    pub adapter: u64,
    pub browser: u64,
    pub exited: BTreeSet<Instance>,
}

impl TestWorld {
    pub fn new() -> Self {
        TestWorld {
            epochs: Epochs {
                daemon: DAEMON,
                vault: 1,
                policy: 1,
            },
            login: 1,
            target: 1,
            adapter: 1,
            browser: 1,
            exited: BTreeSet::new(),
        }
    }
}

impl World for TestWorld {
    fn epochs(&self) -> Epochs {
        self.epochs
    }

    fn revisions(&self, scope: &SignInScope) -> Revisions {
        Revisions {
            login: self.login,
            target: self.target,
            adapter: self.adapter,
            browser: self.browser,
            requester_alive: !self.exited.contains(&scope.delivery().requester),
        }
    }

    fn alive(&self, instance: &Instance) -> bool {
        !self.exited.contains(instance)
    }
}

pub const ROOT: Instance = Instance {
    pid: 100,
    start_time: 1000,
};
pub const MCP: Instance = Instance {
    pid: 101,
    start_time: 1010,
};
/// Another `envcloak mcp` in the same root.
pub const SIBLING: Instance = Instance {
    pid: 102,
    start_time: 1020,
};
pub const OTHER_ROOT: Instance = Instance {
    pid: 200,
    start_time: 2000,
};
pub const OTHER_MCP: Instance = Instance {
    pid: 201,
    start_time: 2010,
};

pub const LOGIN: [u8; 16] = [0x11; 16];

pub fn label(s: &str) -> Label {
    Label::new(s).unwrap()
}

pub fn origin(scheme: Scheme, host: &str, port: u16) -> Origin {
    Origin::new(scheme, Host::name(host).unwrap(), port).unwrap()
}

/// What a test varies in a scope; the rest is fixed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Spec {
    pub root: Instance,
    pub requester: Instance,
    pub role: &'static str,
    pub tier: Tier,
    pub attempts: u8,
    pub approval: Duration,
    pub attempt_timeout: Duration,
    pub session_lifetime: Duration,
}

impl Spec {
    pub fn dev() -> Self {
        Spec {
            root: ROOT,
            requester: MCP,
            role: "editor",
            tier: Tier::Dev,
            attempts: 5,
            approval: Duration::from_secs(4 * 3600),
            attempt_timeout: Duration::from_secs(900),
            session_lifetime: Duration::from_secs(3600),
        }
    }

    pub fn each() -> Self {
        Spec {
            tier: Tier::Each,
            attempts: 1,
            ..Spec::dev()
        }
    }
}

/// The scope `spec` resolves to in `world`.
pub fn scope(spec: &Spec, world: &TestWorld) -> SignInScope {
    let app = origin(Scheme::Http, "app.localhost", 3000);
    SignInScope::new(
        Subject {
            root: spec.root,
            evidence: [0x21; 32],
        },
        ProjectScope {
            dir: b"/work/app".to_vec(),
            dev: 64,
            ino: 4242,
            config: [0x31; 32],
        },
        Account {
            login_item: ItemId::from_bytes(LOGIN),
            authorization_revision: world.login,
            account: label("editor@fixture.test"),
            tenant: Some(label("acme")),
            role: label(spec.role),
            environment: Environment::Test,
        },
        Target {
            id: TargetId::from_bytes([0x41; 16]),
            revision: world.target,
            adapter: AdapterId::from_bytes([0x51; 16]),
            adapter_revision: world.adapter,
            entry_origins: SortedSet::new(vec![app.clone()]).unwrap(),
            identity_check: IdentityCheck {
                kind: CheckKind::Endpoint,
                locator: label("/api/me"),
            },
            transfer: TransferScope {
                cookies: SortedSet::new(vec![DeclaredCookie {
                    host: Host::name("app.localhost").unwrap(),
                    name: label("session"),
                }])
                .unwrap(),
                storage: SortedSet::new(vec![DeclaredStorage {
                    origin: app,
                    key: label("csrf"),
                }])
                .unwrap(),
            },
        },
        Delivery {
            mode: DeliveryMode::BrowserSession,
            requester: spec.requester,
            browser: world.browser,
        },
        Limits::new(
            spec.tier,
            spec.attempts,
            spec.approval,
            spec.attempt_timeout,
            spec.session_lifetime,
        )
        .unwrap(),
        world.epochs,
    )
    .unwrap()
}

/// The identity the fixture app names for `spec`'s account.
pub fn identity(role: &str) -> IdentityResponse {
    IdentityResponse {
        account: label("editor@fixture.test"),
        tenant: Some(label("acme")),
        role: label(role),
    }
}
