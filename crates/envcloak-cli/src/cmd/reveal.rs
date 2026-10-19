//! `envcloak reveal <slug>[#field]`: one freshly proven secret on the
//! controlling terminal on Linux, or in the EnvCloak app on macOS (SPEC §6.7).

use std::process::ExitCode;

use envcloak_client::fail::{Failure, RUN_FAILURE, USAGE, usage};
use envcloak_core::vault::{FieldName, Slug};

pub fn run(args: &[&str]) -> ExitCode {
    let [target] = args else {
        return usage("envcloak reveal <slug>[#field]");
    };
    let (slug, field) = target
        .split_once('#')
        .map_or((*target, None), |(s, f)| (s, Some(f)));
    if Slug::new(slug).is_err() || field.is_some_and(|f| FieldName::new(f).is_err()) {
        return usage("envcloak reveal <slug>[#field]");
    }
    let mut names = vec![slug];
    names.extend(field);
    if let Err(f) = super::refuse_value_like(&names) {
        return f.report(USAGE);
    }
    reveal(slug, field).unwrap_or_else(|f| f.report(RUN_FAILURE))
}

#[cfg(target_os = "macos")]
fn reveal(slug: &str, field: Option<&str>) -> Result<ExitCode, Failure> {
    use std::time::Duration;

    use envcloak_client::claims::refuse_if_claimed;
    use envcloak_client::connect::run_paths;
    use envcloak_client::fail::refuse_if_traced;
    use envcloak_client::tty::Terminal;
    use envcloak_ipc::proto::ErrorKind;
    use envcloak_ipc::{Client, ClientError, RevealWaitOutcome, RpcError};

    const MAX_WAIT: Duration = Duration::from_secs(600);

    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    let _tty = Terminal::open().map_err(|_| {
        Failure::new(
            "app_required",
            "revealing a value on macOS uses the EnvCloak app; it is never printed to the terminal",
        )
    })?;
    match Client::wait_for_reveal(&run_paths()?, slug, field, &claims_now, MAX_WAIT) {
        Ok(RevealWaitOutcome::Shown) => {
            println!("Shown in EnvCloak");
            Ok(ExitCode::SUCCESS)
        }
        Ok(RevealWaitOutcome::Declined) => Err(Failure::new(
            "declined",
            "the reveal request was declined in the EnvCloak app",
        )),
        Ok(RevealWaitOutcome::Expired) => Err(Failure::new(
            "expired",
            "the reveal request expired before it was shown in the EnvCloak app",
        )),
        Err(ClientError::Rpc(RpcError {
            kind: ErrorKind::NoUnlocker,
            ..
        })) => Err(Failure::new(
            "app_required",
            "revealing a value on macOS uses the EnvCloak app; it is never printed to the terminal",
        )),
        Err(e) => Err(Failure::from(e)),
    }
}

#[cfg(target_os = "linux")]
fn reveal(slug: &str, field: Option<&str>) -> Result<ExitCode, Failure> {
    use envcloak_client::claims::{claims, refuse_if_claimed};
    use envcloak_client::connect::connect;
    use envcloak_client::fail::refuse_if_traced;
    use envcloak_client::tty::Terminal;

    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    // No request, even for metadata, until the only permitted output
    // destination is open. There is no stdout/stderr fallback.
    let mut tty = Terminal::open()
        .map_err(|_| Failure::new("no_terminal", "reveal needs a controlling terminal"))?;
    let target = connect()?.items_target(slug, field, &claims_now)?;
    let field = target
        .field
        .as_deref()
        .ok_or_else(|| Failure::new("ambiguous_field", "name one field with <slug>#<field>"))?;
    tty.say(
        "Warning: a terminal an agent drives can read what is shown here; scrollback keeps it.\n",
    )?;
    let passphrase = tty.read_secret("Vault passphrase to reveal this: ")?;
    let value = connect()?.items_reveal(slug, Some(field), passphrase, &claims())?;
    tty.write_secret(&value)?;
    drop(value);
    tty.say("\n")?;
    drop(tty.read_secret("Press Enter to finish: ")?);
    Ok(ExitCode::SUCCESS)
}
