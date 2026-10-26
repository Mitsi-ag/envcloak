//! Isolated sign-in driver process (`envcloakd --signin-driver`, SPEC §6.8,
//! M2 plan D-25, D-34, D-36, task `M2b-09`).
//!
//! Started per attempt from the daemon's retained startup image
//! ([`EntryImageAnchor`]) with a cleared environment and only the control
//! socketpair (descriptor 3) and the driver's ends of the CDP pipes
//! (descriptors 4 and 5). Parses all page-influenced CDP and loopback-proxy
//! traffic outside the VMK-holding daemon process.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use envcloak_browser::{
    AttemptFlow, AttemptOutcome, AttemptSpec, DaemonToDriver, Driver, DriverMessage, DriverPipe,
    EntryImageAnchor, ExpectedIdentity, GuardViolation, LoginFieldHints, LoopbackOriginProxy,
    MAX_DRIVER_MESSAGE_BYTES, TargetScope, WorkerSessionFormat, recv_from_driver, send_to_driver,
};
use envcloak_signin::origin::parse_registered;
use envcloak_signin::{
    CheckKind, CookieDomain, CookiePartition, CookiePath, DeclaredCookie, DeclaredStorage, Host,
    HostName, IdentityCheck, Label, Origin, SortedSet, TransferScope,
};
use envcloak_sys::OwnedChild;
use envcloak_sys::fdpass::{DescriptorKind, descriptor_kind};

/// Inherited descriptor for the daemon <-> driver control socketpair.
pub const DRIVER_CONTROL_FD: i32 = 3;
/// Inherited descriptor for the read end of the CDP pipe from Chrome.
pub const DRIVER_CDP_READ_FD: i32 = 4;
/// Inherited descriptor for the write end of the CDP pipe to Chrome.
pub const DRIVER_CDP_WRITE_FD: i32 = 5;

/// Private environment variable carrying the spawning daemon's PID.
pub const DRIVER_PARENT_ENV: &str = "ENVCLOAKD_SIGNIN_PARENT_PID";

/// Wire representation of a [`DeclaredCookie`] in [`DriverBootstrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverCookieWire {
    pub name: String,
    pub domain: String,
    pub host_only: bool,
    pub path: String,
    pub partition_site: Option<String>,
    pub partition_cross_site_ancestor: bool,
}

impl DriverCookieWire {
    pub fn from_declared(d: &DeclaredCookie) -> Self {
        let (domain, host_only) = match &d.domain {
            CookieDomain::HostOnly(h) => (h.to_string(), true),
            CookieDomain::Domain(n) => (n.as_str().to_owned(), false),
        };
        let (partition_site, partition_cross_site_ancestor) = match &d.partition {
            CookiePartition::Unpartitioned => (None, false),
            CookiePartition::Partitioned {
                site,
                cross_site_ancestor,
            } => (
                Some(format!("{}://{}", site.scheme.as_str(), site.host)),
                *cross_site_ancestor,
            ),
        };
        Self {
            name: d.name.as_str().to_owned(),
            domain,
            host_only,
            path: d.path.as_str().to_owned(),
            partition_site,
            partition_cross_site_ancestor,
        }
    }

    pub fn into_declared(self) -> Result<DeclaredCookie, &'static str> {
        let name = Label::new(&self.name).map_err(|_| "invalid cookie name")?;
        let path = CookiePath::new(&self.path).map_err(|_| "invalid cookie path")?;
        let domain = if self.host_only {
            CookieDomain::HostOnly(
                Host::parse(&self.domain).map_err(|_| "invalid host-only cookie domain")?,
            )
        } else {
            let trimmed = self.domain.strip_prefix('.').unwrap_or(&self.domain);
            CookieDomain::Domain(
                HostName::new(trimmed).map_err(|_| "invalid domain cookie hostname")?,
            )
        };
        let partition = match self.partition_site {
            None => CookiePartition::Unpartitioned,
            Some(site_str) => {
                let origin =
                    parse_registered(&site_str).map_err(|_| "invalid cookie partition site")?;
                CookiePartition::Partitioned {
                    site: envcloak_signin::Site {
                        scheme: origin.scheme(),
                        host: origin.host().clone(),
                    },
                    cross_site_ancestor: self.partition_cross_site_ancestor,
                }
            }
        };
        Ok(DeclaredCookie {
            name,
            domain,
            path,
            partition,
        })
    }
}

/// Wire representation of a [`DeclaredStorage`] in [`DriverBootstrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverStorageWire {
    pub origin: String,
    pub key: String,
}

impl DriverStorageWire {
    pub fn from_declared(d: &DeclaredStorage) -> Self {
        Self {
            origin: d.origin.to_string(),
            key: d.key.as_str().to_owned(),
        }
    }

    pub fn into_declared(self) -> Result<DeclaredStorage, &'static str> {
        let origin = parse_registered(&self.origin).map_err(|_| "invalid storage origin")?;
        let key = Label::new(&self.key).map_err(|_| "invalid storage key")?;
        Ok(DeclaredStorage { origin, key })
    }
}

/// Wire representation of [`AttemptFlow`] in [`DriverBootstrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverFlowWire {
    BrowserLogin {
        login_url: String,
        username_selector: Option<String>,
        password_selector: Option<String>,
        code_selector: Option<String>,
        submit_selector: Option<String>,
    },
    TestSession {
        endpoint_origin: String,
        ttl_secs: u64,
    },
}

/// Initial bootstrap message sent from the daemon to `envcloakd --signin-driver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverBootstrap {
    pub app_origins: Vec<String>,
    pub credential_origins: Vec<String>,
    pub identity_provider_origins: Vec<String>,
    pub callback_origins: Vec<String>,
    pub identity_check_kind: String,
    pub identity_check_locator: String,
    pub expected_account: String,
    pub expected_tenant: Option<String>,
    pub expected_role: String,
    pub cookies: Vec<DriverCookieWire>,
    pub storage: Vec<DriverStorageWire>,
    pub session_format: WorkerSessionFormat,
    pub flow: DriverFlowWire,
}

impl DriverBootstrap {
    /// Builds a [`DriverBootstrap`] from an [`AttemptSpec`].
    pub fn from_spec(spec: &AttemptSpec) -> Self {
        let identity_check_kind = match spec.identity_check.kind {
            CheckKind::Endpoint => "endpoint".to_owned(),
            CheckKind::Element => "dom".to_owned(),
        };
        let identity_check_locator = spec.identity_check.locator.as_str().to_owned();
        let flow = match &spec.flow {
            AttemptFlow::BrowserLogin { login_url, hints } => DriverFlowWire::BrowserLogin {
                login_url: login_url.clone(),
                username_selector: hints.username_selector.clone(),
                password_selector: hints.password_selector.clone(),
                code_selector: hints.code_selector.clone(),
                submit_selector: hints.submit_selector.clone(),
            },
            AttemptFlow::TestSession {
                endpoint_origin,
                ttl_secs,
            } => DriverFlowWire::TestSession {
                endpoint_origin: endpoint_origin.clone(),
                ttl_secs: *ttl_secs,
            },
        };
        Self {
            app_origins: spec.scope.app.iter().map(ToString::to_string).collect(),
            credential_origins: spec
                .scope
                .credential_entry
                .iter()
                .map(ToString::to_string)
                .collect(),
            identity_provider_origins: spec
                .scope
                .identity_provider
                .iter()
                .map(ToString::to_string)
                .collect(),
            callback_origins: spec
                .scope
                .callback
                .iter()
                .map(ToString::to_string)
                .collect(),
            identity_check_kind,
            identity_check_locator,
            expected_account: spec.expected_identity.account.as_str().to_owned(),
            expected_tenant: spec
                .expected_identity
                .tenant
                .as_ref()
                .map(|t| t.as_str().to_owned()),
            expected_role: spec.expected_identity.role.as_str().to_owned(),
            cookies: spec
                .transfer
                .cookies
                .iter()
                .map(DriverCookieWire::from_declared)
                .collect(),
            storage: spec
                .transfer
                .storage
                .iter()
                .map(DriverStorageWire::from_declared)
                .collect(),
            session_format: spec.session_format,
            flow,
        }
    }

    /// Reconstructs the [`AttemptSpec`] in the child driver process.
    pub fn into_spec(self) -> Result<AttemptSpec, &'static str> {
        let parse_origins = |list: &[String]| -> Result<SortedSet<Origin>, &'static str> {
            let mut parsed = Vec::with_capacity(list.len());
            for item in list {
                parsed.push(parse_registered(item).map_err(|_| "invalid registered origin")?);
            }
            SortedSet::new(parsed).map_err(|_| "duplicate registered origin")
        };
        let scope = TargetScope {
            app: parse_origins(&self.app_origins)?,
            credential_entry: parse_origins(&self.credential_origins)?,
            identity_provider: parse_origins(&self.identity_provider_origins)?,
            callback: parse_origins(&self.callback_origins)?,
        };
        let check_kind = match self.identity_check_kind.as_str() {
            "endpoint" => CheckKind::Endpoint,
            "dom" | "element" => CheckKind::Element,
            _ => return Err("unknown identity check kind"),
        };
        let identity_check = IdentityCheck {
            kind: check_kind,
            locator: Label::new(&self.identity_check_locator)
                .map_err(|_| "invalid identity check locator")?,
        };
        let expected_identity = ExpectedIdentity {
            account: Label::new(&self.expected_account).map_err(|_| "invalid expected account")?,
            tenant: match self.expected_tenant {
                Some(t) => Some(Label::new(&t).map_err(|_| "invalid expected tenant")?),
                None => None,
            },
            role: Label::new(&self.expected_role).map_err(|_| "invalid expected role")?,
        };
        let mut cookies = Vec::with_capacity(self.cookies.len());
        for c in self.cookies {
            cookies.push(c.into_declared()?);
        }
        let mut storage = Vec::with_capacity(self.storage.len());
        for s in self.storage {
            storage.push(s.into_declared()?);
        }
        let transfer = TransferScope {
            cookies: SortedSet::new(cookies).map_err(|_| "duplicate cookie declaration")?,
            storage: SortedSet::new(storage).map_err(|_| "duplicate storage declaration")?,
        };
        let flow = match self.flow {
            DriverFlowWire::BrowserLogin {
                login_url,
                username_selector,
                password_selector,
                code_selector,
                submit_selector,
            } => AttemptFlow::BrowserLogin {
                login_url,
                hints: LoginFieldHints {
                    username_selector,
                    password_selector,
                    code_selector,
                    submit_selector,
                },
            },
            DriverFlowWire::TestSession {
                endpoint_origin,
                ttl_secs,
            } => AttemptFlow::TestSession {
                endpoint_origin,
                ttl_secs,
            },
        };
        Ok(AttemptSpec {
            scope,
            identity_check,
            expected_identity,
            transfer,
            session_format: self.session_format,
            flow,
        })
    }
}

/// Handshake reply sent from `envcloakd --signin-driver` to the daemon after
/// reading [`DriverBootstrap`] and starting the loopback origin proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverReady {
    pub proxy_addr: Option<String>,
}

fn write_frame<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> io::Result<()> {
    let payload = Zeroizing::new(
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
    );
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_DRIVER_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid driver frame length",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn not_started_by_daemon() -> ExitCode {
    eprintln!(
        "envcloak: not_started_by_daemon: envcloakd --signin-driver is started only by \
         envcloakd; nothing was started"
    );
    ExitCode::from(125)
}

/// Entry point for `envcloakd --signin-driver`.
pub fn main() -> ExitCode {
    let parent_pid = match i32::try_from(std::os::unix::process::parent_id()) {
        Ok(p) if p > 1 => p,
        _ => return not_started_by_daemon(),
    };
    let expected_parent: i32 = match std::env::var(DRIVER_PARENT_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(p) if p == parent_pid => p,
        _ => return not_started_by_daemon(),
    };

    let Ok(ctrl_fd) = envcloak_sys::take_inherited_fd(DRIVER_CONTROL_FD) else {
        return not_started_by_daemon();
    };
    let Ok((kind, _)) = descriptor_kind(ctrl_fd.as_fd()) else {
        return not_started_by_daemon();
    };
    if kind != DescriptorKind::Socket {
        return not_started_by_daemon();
    }
    let Ok(peer) = envcloak_sys::peer_identity(ctrl_fd.as_fd()) else {
        return not_started_by_daemon();
    };
    if peer.pid != expected_parent {
        return not_started_by_daemon();
    }

    let cdp_r = envcloak_sys::take_inherited_fd(DRIVER_CDP_READ_FD).ok();
    let cdp_w = envcloak_sys::take_inherited_fd(DRIVER_CDP_WRITE_FD).ok();

    let mut ctrl_read = UnixStream::from(ctrl_fd);
    let _ = ctrl_read.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = ctrl_read.set_write_timeout(Some(Duration::from_secs(30)));
    let Ok(mut ctrl_write) = ctrl_read.try_clone() else {
        return ExitCode::from(125);
    };

    let Ok(bootstrap) = read_frame::<_, DriverBootstrap>(&mut ctrl_read) else {
        return not_started_by_daemon();
    };
    let Ok(spec) = bootstrap.into_spec() else {
        return not_started_by_daemon();
    };

    let (proxy_guard, proxy_addr, proxy_blocked) = match &spec.flow {
        AttemptFlow::BrowserLogin { .. } => match LoopbackOriginProxy::start(spec.scope.clone()) {
            Ok(p) => {
                let addr = Some(p.addr().to_owned());
                let blocked = Some(p.blocked_handle());
                (Some(p), addr, blocked)
            }
            Err(_) => return ExitCode::from(1),
        },
        AttemptFlow::TestSession { .. } => (None, None, None),
    };

    if write_frame(&mut ctrl_write, &DriverReady { proxy_addr }).is_err() {
        return ExitCode::from(1);
    }

    let cdp_pipes = match (cdp_r, cdp_w) {
        (Some(r), Some(w)) => Some((r, w)),
        _ => None,
    };

    let mut pipe = DriverPipe::new(&mut ctrl_read, &mut ctrl_write);
    let outcome = Driver::run(&mut pipe, spec, cdp_pipes, proxy_blocked);
    drop(proxy_guard);

    match outcome {
        AttemptOutcome::Captured(_) | AttemptOutcome::Stopped(_) => ExitCode::SUCCESS,
    }
}

/// Daemon-side handle to a running `envcloakd --signin-driver` child.
pub struct DriverSession {
    pub child: OwnedChild,
    pub reader: UnixStream,
    pub writer: UnixStream,
    pub proxy_addr: Option<String>,
}

impl DriverSession {
    /// Sends a [`DaemonToDriver`] message to the driver.
    pub fn send(&mut self, msg: &DaemonToDriver) -> io::Result<()> {
        send_to_driver(&mut self.writer, msg)
    }

    /// Receives the next [`DriverMessage`] from the driver.
    pub fn recv(&mut self) -> io::Result<DriverMessage> {
        recv_from_driver(&mut self.reader)
    }
}

/// Spawns `envcloakd --signin-driver` from `anchor`, sends [`DriverBootstrap`],
/// and waits for [`DriverReady`].
pub fn spawn_driver(
    anchor: &EntryImageAnchor,
    spec: &AttemptSpec,
    cdp_r: Option<BorrowedFd<'_>>,
    cdp_w: Option<BorrowedFd<'_>>,
) -> io::Result<DriverSession> {
    let (mut daemon_ctrl, child_ctrl) = UnixStream::pair()?;
    daemon_ctrl.set_read_timeout(Some(Duration::from_secs(30)))?;
    daemon_ctrl.set_write_timeout(Some(Duration::from_secs(30)))?;

    let parent_env = format!("{DRIVER_PARENT_ENV}={}", std::process::id());
    let mut env_bytes: Vec<Vec<u8>> = vec![parent_env.into_bytes()];
    for (k, v) in envcloak_sys::test_hook_vars() {
        let mut entry = k.into_encoded_bytes();
        entry.push(b'=');
        entry.extend_from_slice(&v.into_encoded_bytes());
        env_bytes.push(entry);
    }
    let env_slices: Vec<&[u8]> = env_bytes.iter().map(Vec::as_slice).collect();
    let argv: [&[u8]; 2] = [b"envcloakd", b"--signin-driver"];

    let mut fds: Vec<(BorrowedFd<'_>, i32)> = vec![(child_ctrl.as_fd(), DRIVER_CONTROL_FD)];
    if let (Some(r), Some(w)) = (cdp_r, cdp_w) {
        fds.push((r, DRIVER_CDP_READ_FD));
        fds.push((w, DRIVER_CDP_WRITE_FD));
    }

    let child = anchor
        .spawn_bound(&argv, &env_slices, &fds)
        .map_err(|e| io::Error::other(e.to_string()))?;
    drop(child_ctrl);

    let bootstrap = DriverBootstrap::from_spec(spec);
    if let Err(e) = write_frame(&mut daemon_ctrl, &bootstrap) {
        let _ = child.kill_and_reap();
        return Err(e);
    }
    let ready: DriverReady = match read_frame(&mut daemon_ctrl) {
        Ok(r) => r,
        Err(e) => {
            let _ = child.kill_and_reap();
            return Err(e);
        }
    };
    let writer = daemon_ctrl.try_clone()?;

    // Silence unused-import warning when GuardViolation is only referenced by type.
    let _ = GuardViolation::UnregisteredOrigin;

    Ok(DriverSession {
        child,
        reader: daemon_ctrl,
        writer,
        proxy_addr: ready.proxy_addr,
    })
}
