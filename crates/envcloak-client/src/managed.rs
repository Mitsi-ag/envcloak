//! What a client checks of a managed server's declaration before it
//! contacts the daemon (SPEC §6.6; M2 plan D-33, CR-2; task M2-27;
//! gate 13): no argument, variable value, working directory or `PATH` of a
//! launch, and no origin or header name of a bridged server, may look like
//! a key. A secret a host config held as a launch argument or a variable
//! becomes a binding of the managed manifest, never part of the registered
//! launch, which the record keeps and the receipt shows.
//!
//! The managed methods' client entry points are here, each checking first
//! and connecting only then ([`register`], [`plan_update`], [`update`]):
//! `migrate-mcp` (M2-20) calls these, never the connection's own
//! `register_managed`, `plan_managed_update` or `update_managed`. The
//! daemon refuses such a declaration too (`key_shaped`), behind this.

use envcloak_core::SecretBytes;
use envcloak_ipc::Client;
use envcloak_ipc::proto::{ManagedRegisterParams, ManagedServerDecl};
use envcloak_ipc::view::{ManagedRegisteredView, ManagedUpdatePlanView, ManagedUpdatedView};
use envcloak_policy::managed::LaunchChanges;

use crate::fail::Failure;
use crate::render::looks_like_value;

fn refused() -> Failure {
    Failure::new(
        "value_on_argv",
        "a launch argument or variable looks like a key: put the key in the vault and bind it \
         in the managed manifest; nothing was sent",
    )
}

/// Refuses a launch whose `argv` element, `env` value, working directory
/// or `PATH` looks like a key ([`looks_like_value`]). Nothing is echoed.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped_launch(
    argv: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
    path_env: Option<&str>,
) -> Result<(), Failure> {
    if argv.iter().any(|a| looks_like_value(a))
        || env.iter().any(|(_, v)| looks_like_value(v))
        || cwd.is_some_and(looks_like_value)
        || path_env.is_some_and(looks_like_value)
    {
        return Err(refused());
    }
    Ok(())
}

/// [`refuse_key_shaped_launch`] for an argv and variables alone.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped(argv: &[String], env: &[(String, String)]) -> Result<(), Failure> {
    refuse_key_shaped_launch(argv, env, None, None)
}

/// [`refuse_key_shaped_launch`] for the changes of an update: a new argv,
/// working directory and `PATH`, and the variables it sets.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped_changes(changes: &LaunchChanges) -> Result<(), Failure> {
    refuse_key_shaped_launch(
        changes.argv.as_deref().unwrap_or(&[]),
        &changes.set_env,
        changes.cwd.as_deref(),
        changes.path_env.as_deref(),
    )
}

/// A registration's declaration: a stdio launch as
/// [`refuse_key_shaped_launch`], a bridged server's origin and header
/// names likewise.
///
/// # Errors
/// `value_on_argv`.
pub fn refuse_key_shaped_server(server: &ManagedServerDecl) -> Result<(), Failure> {
    match server {
        ManagedServerDecl::Stdio { launch } => refuse_key_shaped_launch(
            &launch.argv,
            &launch.env,
            launch.cwd.as_deref(),
            launch.path_env.as_deref(),
        ),
        ManagedServerDecl::Bridge {
            origin,
            header_names,
        } => {
            if looks_like_value(origin) || header_names.iter().any(|h| looks_like_value(h)) {
                return Err(refused());
            }
            Ok(())
        }
    }
}

/// `managed.register`, its declaration checked
/// ([`refuse_key_shaped_server`]) before `connect` is called.
///
/// # Errors
/// `value_on_argv`, with no daemon contact; `connect`'s; the call's.
pub fn register(
    connect: impl FnOnce() -> Result<Client, Failure>,
    p: &ManagedRegisterParams,
) -> Result<ManagedRegisteredView, Failure> {
    refuse_key_shaped_server(&p.server)?;
    connect()?.register_managed(p).map_err(Failure::from)
}

/// `managed.update_plan`, its changes checked
/// ([`refuse_key_shaped_changes`]) before `connect` is called.
///
/// # Errors
/// `value_on_argv`, with no daemon contact; `connect`'s; the call's.
pub fn plan_update(
    connect: impl FnOnce() -> Result<Client, Failure>,
    launch: &str,
    changes: &LaunchChanges,
    claims: &[String],
) -> Result<ManagedUpdatePlanView, Failure> {
    refuse_key_shaped_changes(changes)?;
    connect()?
        .plan_managed_update(launch, changes, claims)
        .map_err(Failure::from)
}

/// `managed.update`, its changes checked ([`refuse_key_shaped_changes`])
/// before `connect` is called.
///
/// # Errors
/// `value_on_argv`, with no daemon contact; `connect`'s; the call's.
pub fn update(
    connect: impl FnOnce() -> Result<Client, Failure>,
    launch: &str,
    changes: &LaunchChanges,
    digest: &str,
    passphrase: SecretBytes,
    claims: &[String],
) -> Result<ManagedUpdatedView, Failure> {
    refuse_key_shaped_changes(changes)?;
    connect()?
        .update_managed(launch, changes, digest, passphrase, claims)
        .map_err(Failure::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key made at run time, shaped as a generated one: no key-shaped
    /// literal is in the source.
    fn key() -> String {
        let mut x = u64::from(std::process::id()) ^ 0x9e37_79b9_7f4a_7c15;
        let tail: String = (0..40)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(
                    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                        [usize::try_from(x % 57).unwrap()],
                )
            })
            .collect();
        format!("{}_{tail}", concat!("s", "k"))
    }

    /// Gate 13 for managed launches: a key-shaped argument or variable
    /// value is refused before anything is sent, in a registration and in
    /// an update's changes; names and paths pass.
    #[test]
    fn key_shaped_arguments_and_values_are_refused() {
        let k = key();
        let argv = vec![
            "/usr/local/bin/server".to_owned(),
            "--port".to_owned(),
            "8080".to_owned(),
        ];
        assert!(refuse_key_shaped(&argv, &[("MODE".into(), "prod".into())]).is_ok());
        let mut with_key = argv.clone();
        with_key.push(format!("--api-key={k}"));
        assert_eq!(
            refuse_key_shaped(&with_key, &[]).unwrap_err().token(),
            "value_on_argv"
        );
        assert!(refuse_key_shaped(&argv, &[("API".into(), k.clone())]).is_err());
        let changes = LaunchChanges {
            set_env: vec![("API".into(), k)],
            ..LaunchChanges::default()
        };
        assert!(refuse_key_shaped_changes(&changes).is_err());
        assert!(refuse_key_shaped_changes(&LaunchChanges::default()).is_ok());
    }

    /// Gate 13 before any daemon contact: the client's managed entry
    /// points check the declaration before they connect. A registration
    /// (stdio: an argument, a value, the working directory, `PATH`;
    /// bridge: a header name), an update plan and an update holding a key
    /// are refused `value_on_argv` and never reach the socket, which
    /// accepts no connection; the same calls without the key do connect
    /// (the positive control: each reaches the socket once).
    ///
    /// Mutation checked: `register` connecting before its check (the
    /// guards left to their callers, as before): the socket accepts a
    /// connection for the refused registration, and this fails.
    #[test]
    fn a_declaration_holding_a_key_never_reaches_the_socket() {
        use envcloak_ipc::proto::LaunchDeclParams;
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = tempfile::Builder::new()
            .prefix("ecm")
            .tempdir_in("/tmp")
            .unwrap();
        let sock = dir.path().join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let contacts = || {
            let mut n = 0;
            while listener.accept().is_ok() {
                n += 1;
            }
            n
        };
        let connect = || -> Result<Client, Failure> {
            let _contact = UnixStream::connect(&sock).unwrap();
            Err(Failure::new("test_connected", "connected"))
        };
        let k = key();
        let stdio = |argv: &[&str], env: &[(&str, &str)], cwd: Option<&str>, path: Option<&str>| {
            ManagedRegisterParams {
                name: "claude-code/x".into(),
                manifest: "/srv/p/envcloak.toml".into(),
                server: ManagedServerDecl::Stdio {
                    launch: LaunchDeclParams {
                        argv: argv.iter().map(|a| (*a).to_owned()).collect(),
                        cwd: cwd.map(str::to_owned),
                        env: env
                            .iter()
                            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                            .collect(),
                        path_env: path.map(str::to_owned),
                    },
                },
                passphrase: envcloak_ipc::WireSecret::new(SecretBytes::copy_from(b"pass")),
                claims: Vec::new(),
            }
        };
        let server = "/usr/local/bin/server";
        let in_cwd = format!("/srv/{k}");
        let in_path = format!("/usr/bin:/opt/{k}");
        for p in [
            stdio(&[server, k.as_str()], &[], None, None),
            stdio(&[server], &[("API", k.as_str())], None, None),
            stdio(&[server], &[], Some(in_cwd.as_str()), None),
            stdio(&[server], &[], None, Some(in_path.as_str())),
            ManagedRegisterParams {
                server: ManagedServerDecl::Bridge {
                    origin: "https://api.example.test".into(),
                    header_names: vec![k.clone()],
                },
                ..stdio(&[server], &[], None, None)
            },
        ] {
            assert_eq!(register(connect, &p).unwrap_err().token(), "value_on_argv");
        }
        let with_key = LaunchChanges {
            set_env: vec![("API".into(), k.clone())],
            ..LaunchChanges::default()
        };
        let launch = "0123456789abcdefghjkmnpqrs";
        assert_eq!(
            plan_update(connect, launch, &with_key, &[])
                .unwrap_err()
                .token(),
            "value_on_argv"
        );
        let digest = "00".repeat(32);
        assert_eq!(
            update(
                connect,
                launch,
                &with_key,
                &digest,
                SecretBytes::copy_from(b"p"),
                &[]
            )
            .unwrap_err()
            .token(),
            "value_on_argv"
        );
        assert_eq!(contacts(), 0, "a refused declaration reached the socket");
        // The positive control.
        let fine = stdio(
            &[server, "--port", "8080"],
            &[("MODE", "prod")],
            Some("/srv"),
            None,
        );
        assert_eq!(
            register(connect, &fine).unwrap_err().token(),
            "test_connected"
        );
        let plain = LaunchChanges::default();
        assert_eq!(
            plan_update(connect, launch, &plain, &[])
                .unwrap_err()
                .token(),
            "test_connected"
        );
        assert_eq!(
            update(
                connect,
                launch,
                &plain,
                &digest,
                SecretBytes::copy_from(b"p"),
                &[]
            )
            .unwrap_err()
            .token(),
            "test_connected"
        );
        assert_eq!(contacts(), 3);
    }
}
