//! `envcloak reveal <slug>[#field]`: one freshly proven secret on the
//! controlling terminal only (SPEC §6.7). macOS needs the M3 app.

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
    #[cfg(target_os = "macos")]
    {
        Failure::new(
            "app_required",
            "reveal on macOS requires the EnvCloak app (M3)",
        )
        .report(RUN_FAILURE)
    }
    #[cfg(target_os = "linux")]
    reveal(slug, field).unwrap_or_else(|f| f.report(RUN_FAILURE))
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
