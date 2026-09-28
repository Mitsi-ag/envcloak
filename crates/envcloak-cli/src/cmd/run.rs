//! `envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file
//! FILE] -- <cmd...>` (SPEC §6.1 steps 1 to 4): the request for a run's
//! values, and the decision. The runner and the redactor (steps 5 to 8)
//! arrive in T12; this build stops after the decision.
//!
//! 1. Under a tracer the CLI refuses at once, with exit 125 and `traced`
//!    (gate 19), before any contact with the daemon. Only a verified
//!    daemon is then asked; with none, run says how to start one and
//!    starts nothing.
//! 2. It finds the nearest `envcloak.toml` upward from the working
//!    directory, and sends its path. The daemon opens the manifest itself.
//! 3. It sends the profile and `--ref` bindings, the `--env-file`'s
//!    references and the names of its ordinary variables (never their
//!    values, which the runner will set for the command), the command
//!    line as display text, and the names of the agent markers in its
//!    environment. The env file can hold values, so its bytes are read
//!    only into a [`SecretBuf`], and an error names its kind and line,
//!    never text from the file (docs/MANIFEST.md "Env files").
//! 4. The daemon answers with the decision. When no grant covers the
//!    request, it is pending: exit 125 with `approval_required
//!    request=<id>`, naming `envcloak approve <id>`. Approval input is
//!    never read here: the terminal this command runs in may be an
//!    agent's.
//!
//! No argument is ever echoed, and no value is ever accepted on the
//! command line (gate 13): `--ref` names an item, never a value.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use envcloak_core::SecretBuf;
use envcloak_ipc::proto::{EnvFileParams, RunRequestParams};
use envcloak_ipc::view::DecisionView;
use envcloak_policy::{
    Binding, EnvFileRefs, GrantId, MAX_ENV_FILE, Mode, PendingId, find_manifest,
    parse_env_file_refs,
};
use zeroize::Zeroize;

use super::claims;
use crate::connect::connect;
use crate::fail::{Failure, RUN_FAILURE, USAGE, refuse_if_traced, usage};

const USAGE_TEXT: &str =
    "envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file FILE] -- <cmd...>";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct RunArgs {
    profile: Option<String>,
    refs: Vec<String>,
    env_file: Option<String>,
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
                if a.env_file.is_some() {
                    return Err("--env-file is given twice");
                }
                a.env_file = Some((*it.next().ok_or("--env-file needs a file")?).to_owned());
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
    // Its ordinary variables' values stay here: the runner (T12) sets them
    // for the command.
    let env_file = a.env_file.as_deref().map(read_env_file).transpose()?;
    let decision = client.run_request(&RunRequestParams {
        manifest,
        profile: a.profile,
        refs: a.refs,
        env_file: env_file.as_ref().map(|f| EnvFileParams::from(&f.names())),
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

/// Reads and parses the `--env-file` at `path`. Only a regular file of at
/// most [`MAX_ENV_FILE`] bytes is read, into a [`SecretBuf`] sized for it;
/// it is opened non-blocking, so a FIFO named here cannot hang the run.
/// Errors name the kind and line, never the path's contents.
fn read_env_file(path: &str) -> Result<EnvFileRefs, Failure> {
    let fail = |m: &'static str| Failure::new("binding_unresolved", m);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| fail("the --env-file could not be opened"))?;
    let meta = f
        .metadata()
        .map_err(|_| fail("the --env-file could not be read"))?;
    if !meta.is_file() {
        return Err(fail("the --env-file is not a regular file"));
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if len > MAX_ENV_FILE {
        return Err(fail("the --env-file is larger than 1 MiB"));
    }
    let mut buf = SecretBuf::with_capacity(len);
    buf.read_exact_from(&mut f, len)
        .map_err(|_| fail("the --env-file changed while it was read"))?;
    // Anything past the length it had is a file still being written.
    let mut more = [0u8; 1];
    let grew = f.read(&mut more);
    more.zeroize();
    if !matches!(grew, Ok(0)) {
        return Err(fail("the --env-file changed while it was read"));
    }
    parse_env_file_refs(&buf.freeze())
        .map_err(|e| Failure::new(e.token(), format!("--env-file: {e}")))
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
                env_file: None,
                argv: vec!["./emit".into(), "-x".into()],
            }
        );
        assert_eq!(
            parse(&[
                "--profile",
                "short",
                "--ref",
                "A=openai/x",
                "--env-file",
                ".env.refs",
                "--ref",
                "B=stripe/x#value",
                "--",
                "true"
            ])
            .unwrap(),
            RunArgs {
                profile: Some("short".into()),
                refs: vec!["A=openai/x".into(), "B=stripe/x#value".into()],
                env_file: Some(".env.refs".into()),
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
            &["--env-file"],
            &["--env-file", "a", "--env-file", "b", "--", "true"],
            &["--wait", "1m", "--", "true"],
            &["--bogus", "--", "true"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// `--env-file` is read only from a regular file of at most 1 MiB, a
    /// FIFO does not hang the run, and an error names the kind and line,
    /// never text from the file.
    #[test]
    fn an_env_file_is_read_only_from_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        let message = |p: &str| read_env_file(p).unwrap_err().message.into_owned();

        std::fs::write(
            path("good"),
            "OPENAI_API_KEY=envcloak://openai/acme-web\nexport PLAIN='x y'\n",
        )
        .unwrap();
        let names = read_env_file(&path("good")).unwrap().names();
        assert_eq!(
            EnvFileParams::from(&names),
            EnvFileParams {
                refs: vec![envcloak_ipc::proto::EnvFileLine {
                    line: 1,
                    text: "OPENAI_API_KEY=openai/acme-web".into()
                }],
                plain: vec![envcloak_ipc::proto::EnvFileLine {
                    line: 2,
                    text: "PLAIN".into()
                }],
            }
        );

        let hidden = "do-not-echo-this-text";
        std::fs::write(
            path("bad"),
            format!("A=envcloak://openai/acme-web\nB='{hidden}\n"),
        )
        .unwrap();
        let e = read_env_file(&path("bad")).unwrap_err();
        assert_eq!(e.token, "binding_unresolved");
        assert_eq!(
            e.message,
            "--env-file: env file line 2: a quoted value is not closed"
        );
        assert!(!e.message.contains(hidden));

        std::fs::write(path("big"), vec![b'#'; MAX_ENV_FILE + 1]).unwrap();
        assert_eq!(message(&path("big")), "the --env-file is larger than 1 MiB");
        std::fs::write(path("full"), vec![b'#'; MAX_ENV_FILE]).unwrap();
        assert!(
            read_env_file(&path("full"))
                .unwrap()
                .names()
                .refs
                .is_empty()
        );

        assert_eq!(
            message(dir.path().to_str().unwrap()),
            "the --env-file is not a regular file"
        );
        assert_eq!(
            message(&path("missing")),
            "the --env-file could not be opened"
        );
        // A FIFO with no writer: opened without blocking, then refused.
        let status = std::process::Command::new("mkfifo")
            .arg(path("fifo"))
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            message(&path("fifo")),
            "the --env-file is not a regular file"
        );
    }
}
