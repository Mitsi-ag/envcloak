//! `envcloak run [--profile NAME] [--ref NAME=slug[#field]]... -- <cmd...>`
//! (SPEC §6.1 steps 1 to 4): the request for a run's values, and the
//! decision. The runner and the redactor (steps 5 to 8) arrive in T12;
//! this build stops after the decision.
//!
//! 1. Under a tracer the CLI refuses at once, with exit 125 and `traced`
//!    (gate 19), before any contact with the daemon. Only a verified
//!    daemon is then asked; with none, run says how to start one and
//!    starts nothing.
//! 2. It finds the nearest `envcloak.toml` upward from the working
//!    directory, and sends its path. The daemon opens the manifest itself.
//! 3. It sends the profile and `--ref` bindings, the command line as
//!    display text, and the names of the agent markers in its environment.
//! 4. The daemon answers with the decision. When no grant covers the
//!    request, it is pending: exit 125 with `approval_required
//!    request=<id>`, naming `envcloak approve <id>`. Approval input is
//!    never read here: the terminal this command runs in may be an
//!    agent's.
//!
//! No argument is ever echoed, and no value is ever accepted on the
//! command line (gate 13): `--ref` names an item, never a value.

use std::path::Path;
use std::process::ExitCode;

use envcloak_ipc::proto::RunRequestParams;
use envcloak_ipc::view::DecisionView;
use envcloak_policy::{Binding, GrantId, Mode, PendingId, find_manifest};

use super::claims;
use crate::connect::connect;
use crate::fail::{Failure, RUN_FAILURE, USAGE, refuse_if_traced, usage};

const USAGE_TEXT: &str = "envcloak run [--profile NAME] [--ref NAME=slug[#field]]... -- <cmd...>";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct RunArgs {
    profile: Option<String>,
    refs: Vec<String>,
    argv: Vec<String>,
}

/// Parses the options up to `--` and the command after it. Values are
/// never accepted here: a `--ref` is a name and a reference.
fn parse(args: &[&str]) -> Result<RunArgs, &'static str> {
    let mut a = RunArgs::default();
    let mut it = args.iter();
    loop {
        match it.next() {
            None => return Err("run needs a command: envcloak run ... -- <cmd...>"),
            Some(&"--") => break,
            Some(&"--profile") => {
                if a.profile.is_some() {
                    return Err("--profile is given twice");
                }
                a.profile = Some((*it.next().ok_or("--profile needs a name")?).to_owned());
            }
            Some(&"--ref") => {
                let r = *it.next().ok_or("--ref needs NAME=<slug>[#field]")?;
                // Checked here, so a malformed one (a pasted value, say)
                // is refused before anything is sent, and never echoed.
                if Binding::parse_arg(r).is_err() {
                    return Err("--ref needs NAME=<slug>[#field]");
                }
                a.refs.push(r.to_owned());
            }
            Some(&"--env-file") => {
                return Err("--env-file is not in this build yet; use --ref or the manifest");
            }
            Some(&"--wait") => return Err("--wait is not in this build yet"),
            Some(_) => return Err("unknown option; see envcloak run --help"),
        }
    }
    a.argv = it.map(|s| (*s).to_owned()).collect();
    if a.argv.is_empty() {
        return Err("run needs a command after --");
    }
    Ok(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    match request(a) {
        Ok(code) => code,
        Err(f) => f.report(RUN_FAILURE),
    }
}

fn request(a: RunArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    // Only a verified daemon is ever asked; with none, run says how to
    // start one and starts nothing.
    let mut client = connect()?;
    let manifest = match find_manifest(Path::new(".")) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(Failure::new(
                "manifest_invalid",
                "no envcloak.toml in this directory or above it; run `envcloak init` first",
            ));
        }
        Err(_) => {
            return Err(Failure::new(
                "manifest_invalid",
                "the working directory could not be read while looking for envcloak.toml",
            ));
        }
    };
    let Some(manifest) = manifest.to_str().map(str::to_owned) else {
        return Err(Failure::new(
            "manifest_invalid",
            "the manifest's path is not valid UTF-8, which this build cannot send",
        ));
    };
    let decision = client.run_request(&RunRequestParams {
        manifest,
        profile: a.profile,
        refs: a.refs,
        argv: a.argv,
        claims: claims(),
    })?;
    drop(client);
    match decision {
        DecisionView::Pending { request } => {
            // The id is printed only in its canonical form: a program
            // answering in the daemon's place could send anything.
            let id = PendingId::parse(&request).ok_or_else(protocol)?;
            Err(Failure::new(
                "approval_required",
                format!("request={id}: run \"envcloak approve {id}\" in a terminal you control"),
            ))
        }
        DecisionView::Denied { .. } => {
            let message = decision
                .deny_reason()
                .map(|r| r.message())
                .ok_or_else(protocol)?;
            Err(Failure::new("approval_denied", message))
        }
        DecisionView::Covered {
            grant,
            redact,
            mode,
            ..
        } => {
            let grant = GrantId::parse(&grant).ok_or_else(protocol)?;
            // The runner (T12) goes here.
            eprintln!(
                "envcloak: run cannot start commands in this build yet; grant {grant} covers \
                 this request ({} mode, output {})",
                match mode {
                    Mode::Inject => "inject",
                    Mode::Proxy => "proxy",
                },
                if redact { "redacted" } else { "not redacted" }
            );
            Ok(ExitCode::from(USAGE))
        }
    }
}

fn protocol() -> Failure {
    Failure::new("protocol_error", "the daemon's answer was malformed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_come_before_the_command() {
        assert_eq!(
            parse(&["--", "./emit", "-x"]).unwrap(),
            RunArgs {
                profile: None,
                refs: vec![],
                argv: vec!["./emit".into(), "-x".into()],
            }
        );
        assert_eq!(
            parse(&[
                "--profile",
                "short",
                "--ref",
                "A=openai/x",
                "--ref",
                "B=stripe/x#value",
                "--",
                "true"
            ])
            .unwrap(),
            RunArgs {
                profile: Some("short".into()),
                refs: vec!["A=openai/x".into(), "B=stripe/x#value".into()],
                argv: vec!["true".into()],
            }
        );
        // Options after `--` belong to the command.
        assert_eq!(
            parse(&["--", "sh", "--profile", "x"]).unwrap().argv,
            vec!["sh", "--profile", "x"]
        );
        for bad in [
            &[][..],
            &["--"],
            &["true"],
            &["--profile", "--", "true"],
            &["--profile", "a", "--profile", "b", "--", "true"],
            &["--ref"],
            &["--ref", "not a reference", "--", "true"],
            &["--ref", "A=", "--", "true"],
            &["--env-file", "x", "--", "true"],
            &["--wait", "1m", "--", "true"],
            &["--bogus", "--", "true"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
