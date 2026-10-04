//! Shared by the sign-in contract tests: a world the test moves by hand,
//! a clock, and scopes built from typed fields.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use envcloak_core::vault::ItemId;
use envcloak_policy::Now;
use envcloak_signin::{
    Account, AdapterId, CheckKind, CookieDomain, CookiePartition, CookiePath, Current,
    DaemonInstance, DeclaredCookie, DeclaredStorage, Delivery, DeliveryMode, Environment, Epochs,
    Host, IdentityCheck, IdentityResponse, Instance, Label, Limits, LoginNow, Origin, ProjectScope,
    Requester, Scheme, SignInScope, Site, SortedSet, Subject, Target, TargetId, TargetNow, Tier,
    TransferScope, World,
};

pub const DAEMON: DaemonInstance = DaemonInstance::from_bytes([7; 16]);

/// The clock `t` seconds after the test's origin: wall and awake time
/// move together.
pub fn at(t: u64) -> Now {
    clock(t, t)
}

/// The clock with the wall clock `wall` seconds after the test's origin
/// and `awake` seconds of time awake: the two apart, as after a sleep
/// (awake time stands still) or a wall clock set back.
pub fn clock(wall: u64, awake: u64) -> Now {
    Now {
        wall: UNIX_EPOCH + Duration::from_secs(1_700_000_000 + wall),
        awake: Duration::from_secs(awake),
        including_sleep: Duration::from_secs(awake.max(wall)),
    }
}

pub fn wall(t: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000 + t)
}

/// The world: one set of epochs and revisions, the project, the login
/// item, the target and its adapter, the limits a person edited, the
/// processes that exited, and the process tree as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TestWorld {
    pub epochs: Epochs,
    pub login: u64,
    pub target: u64,
    pub adapter: u64,
    pub browser: u64,
    pub exited: BTreeSet<Instance>,
    /// The project as the daemon opens it now: what a new request takes.
    pub project: ProjectScope,
    /// The project's directory no longer opens.
    pub project_gone: bool,
    /// The login item was deleted.
    pub login_deleted: bool,
    /// The login item's class now.
    pub environment: Environment,
    /// The target was removed.
    pub target_removed: bool,
    /// The target's adapter now.
    pub adapter_id: AdapterId,
    /// A person changed the limits a scope resolves to: from the first to
    /// the second.
    pub limits_edit: Option<(Limits, Limits)>,
    /// Each process's parent, as the kernel reports it.
    pub parents: BTreeMap<Instance, Instance>,
    /// The processes running a known agent's executable.
    pub agents: BTreeSet<Instance>,
}

/// The fixture's project, as the daemon first opens it.
pub fn fixture_project() -> ProjectScope {
    ProjectScope {
        dir: b"/work/app".to_vec(),
        dev: 64,
        ino: 4242,
        config: [0x31; 32],
    }
}

pub const ADAPTER: AdapterId = AdapterId::from_bytes([0x51; 16]);

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
            project: fixture_project(),
            project_gone: false,
            login_deleted: false,
            environment: Environment::Test,
            target_removed: false,
            adapter_id: ADAPTER,
            limits_edit: None,
            parents: [
                (SHELL, ROOT),
                (MCP, SHELL),
                (SIBLING, ROOT),
                (OTHER_MCP, OTHER_ROOT),
            ]
            .into_iter()
            .collect(),
            agents: [ROOT, OTHER_ROOT].into_iter().collect(),
        }
    }

    /// The process between the root and the requesting instance exits: the
    /// kernel reparents the requesting instance to init, out of the root's
    /// tree, while both still run.
    pub fn leave_root(&mut self) {
        self.exited.insert(SHELL);
        self.parents.remove(&SHELL);
        self.parents.insert(MCP, INIT);
    }

    /// The process between the root and the requesting instance starts a
    /// known agent's executable: an agent now sits between them.
    pub fn agent_between(&mut self) {
        self.agents.insert(SHELL);
    }

    /// What a scope resolved with `limits` resolves to now.
    pub fn limits_for(&self, limits: &Limits) -> Limits {
        match &self.limits_edit {
            Some((from, to)) if from == limits => to.clone(),
            _ => limits.clone(),
        }
    }

    /// Where `requester` stands against `root` (SPEC §10b "Match" rules 3
    /// and 4), read from the tree as a separate reading of the rules: the
    /// root in its ancestry, pid and start time alike, and no known agent
    /// between them, the requester included, unless the root is that
    /// agent.
    fn requester(&self, requester: Instance, root: Instance) -> Requester {
        if self.exited.contains(&requester) {
            return Requester::Exited;
        }
        let mut at = requester;
        for _ in 0..64 {
            if at == root {
                return Requester::Covered;
            }
            if self.agents.contains(&at) {
                return Requester::Uncovered;
            }
            match self.parents.get(&at) {
                Some(p) if !self.exited.contains(p) => at = *p,
                _ => return Requester::Uncovered,
            }
        }
        Requester::Uncovered
    }
}

impl World for TestWorld {
    fn epochs(&self) -> Epochs {
        self.epochs
    }

    fn current(&self, scope: &SignInScope) -> Current {
        Current {
            project: (!self.project_gone).then(|| self.project.clone()),
            login: (!self.login_deleted).then_some(LoginNow {
                revision: self.login,
                environment: self.environment,
            }),
            target: (!self.target_removed).then_some(TargetNow {
                revision: self.target,
                adapter: self.adapter_id,
                adapter_revision: self.adapter,
            }),
            limits: self.limits_for(scope.limits()),
            browser: self.browser,
            requester: self.requester(scope.delivery().requester, scope.owner()),
        }
    }

    fn alive(&self, instance: &Instance) -> bool {
        !self.exited.contains(instance)
    }
}

/// The root: an agent.
pub const ROOT: Instance = Instance {
    pid: 100,
    start_time: 1000,
};
/// A process the agent started, between it and its `envcloak mcp`.
pub const SHELL: Instance = Instance {
    pid: 150,
    start_time: 1500,
};
/// The requesting `envcloak mcp`.
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
/// The process a reparented process gets as its parent.
pub const INIT: Instance = Instance {
    pid: 1,
    start_time: 0,
};

pub const LOGIN: [u8; 16] = [0x11; 16];

pub fn label(s: &str) -> Label {
    Label::new(s).unwrap()
}

pub fn origin(scheme: Scheme, host: &str, port: u16) -> Origin {
    Origin::new(scheme, Host::name(host).unwrap(), port).unwrap()
}

/// What a test varies in a scope; the rest is fixed. `vary`, if set,
/// changes one more part of the scope alone ([`varied`]).
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
    pub vary: Option<Vary>,
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
            vary: None,
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

/// A partition by the top-level site `https://<site>`.
pub fn partition(site: &str, cross_site_ancestor: bool) -> CookiePartition {
    CookiePartition::Partitioned {
        site: Site {
            scheme: Scheme::Https,
            host: Host::name(site).unwrap(),
        },
        cross_site_ancestor,
    }
}

/// The fixture's declared cookies: the session cookie, host-only on the
/// app's host at `/` and unpartitioned, and a partitioned one the app sets
/// when it is embedded under `app.example`.
pub fn fixture_cookies() -> Vec<DeclaredCookie> {
    let host_only = CookieDomain::HostOnly(Host::name("app.localhost").unwrap());
    let root = CookiePath::new("/").unwrap();
    vec![
        DeclaredCookie {
            name: label("session"),
            domain: host_only.clone(),
            path: root.clone(),
            partition: CookiePartition::Unpartitioned,
        },
        DeclaredCookie {
            name: label("embed"),
            domain: host_only,
            path: root,
            partition: partition("app.example", true),
        },
    ]
}

/// The scope `spec` resolves to in `world`.
pub fn scope(spec: &Spec, world: &TestWorld) -> SignInScope {
    let s = base_scope(spec, world);
    match spec.vary {
        None => s,
        Some(v) => varied(&s, v).expect("a variation valid for this scope"),
    }
}

fn base_scope(spec: &Spec, world: &TestWorld) -> SignInScope {
    let app = origin(Scheme::Http, "app.localhost", 3000);
    SignInScope::new(
        Subject {
            root: spec.root,
            evidence: [0x21; 32],
        },
        world.project.clone(),
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
            adapter: world.adapter_id,
            adapter_revision: world.adapter,
            entry_origins: SortedSet::new(vec![app.clone()]).unwrap(),
            identity_check: IdentityCheck {
                kind: CheckKind::Endpoint,
                locator: label("/api/me"),
            },
            transfer: TransferScope {
                cookies: SortedSet::new(fixture_cookies()).unwrap(),
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
        world.limits_for(
            &Limits::new(
                spec.tier,
                spec.attempts,
                spec.approval,
                spec.attempt_timeout,
                spec.session_lifetime,
            )
            .unwrap(),
        ),
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

/// One part of a scope changed alone, to another valid value: each field
/// of the encoding by its number (docs/GRANTS.md), and inside the declared
/// cookies, the declared storage key and the credential-entry origin, each
/// part of what they name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Vary {
    Field(u16),
    CookieName,
    /// A host-only cookie made a domain cookie of the same host.
    CookieDomainKind,
    /// A host-only cookie on another host.
    CookieHost,
    CookiePath,
    /// An unpartitioned cookie partitioned.
    CookiePartition,
    /// A partitioned cookie's top-level site.
    CookiePartitionSite,
    /// A partitioned cookie's cross-site ancestor bit, alone.
    CookieAncestor,
    StorageOrigin,
    StorageKey,
    OriginPort,
}

/// Every variation, in a fixed order. Field 21 (the delivery mode) has one
/// value and is not among them.
pub fn variations() -> Vec<Vary> {
    let mut v: Vec<Vary> = (1..=31u16).filter(|n| *n != 21).map(Vary::Field).collect();
    v.extend([
        Vary::CookieName,
        Vary::CookieDomainKind,
        Vary::CookieHost,
        Vary::CookiePath,
        Vary::CookiePartition,
        Vary::CookiePartitionSite,
        Vary::CookieAncestor,
        Vary::StorageOrigin,
        Vary::StorageKey,
        Vary::OriginPort,
    ]);
    v
}

/// `s` with the part `v` changed alone, or `None` where that part cannot
/// change alone in a valid scope: the environment of a `dev` scope (a
/// live identity takes `each`), and the tier or the attempt count where
/// the other tier allows no other count. The cookie variations change the
/// first unpartitioned cookie, or for the partition's own parts the first
/// partitioned one; the storage ones the first storage key; the port the
/// first credential-entry origin.
pub fn varied(s: &SignInScope, v: Vary) -> Option<SignInScope> {
    let mut subject = s.subject().clone();
    let mut project = s.project().clone();
    let mut account = s.account().clone();
    let mut target = s.target().clone();
    let mut delivery = s.delivery().clone();
    let mut epochs = *s.epochs();
    let l = s.limits();
    let (mut tier, mut attempts) = (l.tier(), l.attempts());
    let (mut approval, mut timeout, mut lifetime) =
        (l.approval(), l.attempt_timeout(), l.session_lifetime());
    let mut cookies: Vec<DeclaredCookie> = target.transfer.cookies.iter().cloned().collect();
    let mut storage: Vec<DeclaredStorage> = target.transfer.storage.iter().cloned().collect();
    let mut origins: Vec<Origin> = target.entry_origins.iter().cloned().collect();
    let plain = cookies
        .iter()
        .position(|c| c.partition == CookiePartition::Unpartitioned)
        .expect("an unpartitioned cookie");
    let parted = cookies
        .iter()
        .position(|c| c.partition != CookiePartition::Unpartitioned)
        .expect("a partitioned cookie");
    match v {
        // Another root of the same requesting instance: the process between
        // them (or the agent above it), so the scope stays one a grant
        // rooted there covers.
        Vary::Field(1) => subject.root = if subject.root == SHELL { ROOT } else { SHELL },
        Vary::Field(2) => subject.evidence[31] ^= 1,
        Vary::Field(3) => project.dir.push(b'x'),
        Vary::Field(4) => project.dev ^= 1,
        Vary::Field(5) => project.ino ^= 1,
        Vary::Field(6) => project.config[0] ^= 1,
        Vary::Field(7) => {
            let mut b = *account.login_item.as_bytes();
            b[15] ^= 1;
            account.login_item = ItemId::from_bytes(b);
        }
        Vary::Field(8) => account.authorization_revision ^= 1,
        Vary::Field(9) => account.account = label(&format!("{}x", account.account.as_str())),
        Vary::Field(10) => {
            account.tenant = match account.tenant {
                Some(_) => None,
                None => Some(label("t")),
            }
        }
        Vary::Field(11) => account.role = label(&format!("{}s", account.role.as_str())),
        Vary::Field(12) => {
            account.environment = match account.environment {
                Environment::Test => Environment::Live,
                Environment::Live => Environment::Test,
            }
        }
        Vary::Field(13) => {
            let mut b = *target.id.as_bytes();
            b[0] ^= 1;
            target.id = TargetId::from_bytes(b);
        }
        Vary::Field(14) => target.revision ^= 1,
        Vary::Field(15) => {
            let mut b = *target.adapter.as_bytes();
            b[0] ^= 1;
            target.adapter = AdapterId::from_bytes(b);
        }
        Vary::Field(16) => target.adapter_revision ^= 1,
        Vary::Field(17) => origins.push(origin(Scheme::Https, "other.test", 443)),
        Vary::Field(18) => {
            target.identity_check.locator =
                label(&format!("{}/", target.identity_check.locator.as_str()));
        }
        Vary::Field(19) => {
            let extra = DeclaredCookie {
                name: label("extra"),
                ..cookies[plain].clone()
            };
            cookies.push(extra);
        }
        Vary::Field(20) => storage.push(DeclaredStorage {
            origin: origins[0].clone(),
            key: label("extra"),
        }),
        // Another requesting instance in the same root.
        Vary::Field(22) => {
            delivery.requester = if delivery.requester == SIBLING {
                MCP
            } else {
                SIBLING
            }
        }
        Vary::Field(23) => delivery.browser ^= 1,
        Vary::Field(24) => {
            tier = match tier {
                Tier::Each => Tier::Dev,
                Tier::Dev => Tier::Each,
            }
        }
        Vary::Field(25) => attempts = if attempts == 2 { 3 } else { 2 },
        Vary::Field(26) => approval += Duration::from_secs(1),
        Vary::Field(27) => timeout += Duration::from_secs(1),
        Vary::Field(28) => lifetime += Duration::from_secs(1),
        Vary::Field(29) => {
            let mut b = *epochs.daemon.as_bytes();
            b[0] ^= 1;
            epochs.daemon = DaemonInstance::from_bytes(b);
        }
        Vary::Field(30) => epochs.vault ^= 1,
        Vary::Field(31) => epochs.policy ^= 1,
        Vary::Field(n) => panic!("no field {n}"),
        Vary::CookieName => {
            let c = &mut cookies[plain];
            c.name = label(&format!("{}2", c.name.as_str()));
        }
        Vary::CookieDomainKind => {
            let c = &mut cookies[plain];
            let CookieDomain::HostOnly(Host::Name(n)) = &c.domain else {
                panic!("the unpartitioned cookie is host-only on a name");
            };
            c.domain = CookieDomain::Domain(n.clone());
        }
        Vary::CookieHost => {
            cookies[plain].domain = CookieDomain::HostOnly(Host::name("api.localhost").unwrap());
        }
        Vary::CookiePath => {
            let c = &mut cookies[plain];
            c.path = CookiePath::new(&format!("{}app", c.path.as_str())).unwrap();
        }
        Vary::CookiePartition => cookies[plain].partition = partition("app.example", true),
        Vary::CookiePartitionSite => {
            let CookiePartition::Partitioned {
                cross_site_ancestor,
                ..
            } = cookies[parted].partition
            else {
                unreachable!()
            };
            cookies[parted].partition = partition("other.example", cross_site_ancestor);
        }
        Vary::CookieAncestor => {
            let CookiePartition::Partitioned {
                site,
                cross_site_ancestor,
            } = cookies[parted].partition.clone()
            else {
                unreachable!()
            };
            cookies[parted].partition = CookiePartition::Partitioned {
                site,
                cross_site_ancestor: !cross_site_ancestor,
            };
        }
        Vary::StorageOrigin => storage[0].origin = origin(Scheme::Http, "app.localhost", 3001),
        Vary::StorageKey => {
            let k = &mut storage[0];
            k.key = label(&format!("{}2", k.key.as_str()));
        }
        Vary::OriginPort => {
            let o = origins[0].clone();
            origins[0] = Origin::new(o.scheme(), o.host().clone(), o.port() + 1).unwrap();
        }
    }
    target.transfer.cookies = SortedSet::new(cookies).ok()?;
    target.transfer.storage = SortedSet::new(storage).ok()?;
    target.entry_origins = SortedSet::new(origins).ok()?;
    let limits = Limits::new(tier, attempts, approval, timeout, lifetime).ok()?;
    SignInScope::new(subject, project, account, target, delivery, limits, epochs).ok()
}
