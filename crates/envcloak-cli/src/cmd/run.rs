//! `envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file
//! FILE] -- <cmd...>` (SPEC §6.1): the request for a run's values, the
//! decision, and, when a grant covers it, the command with the values in
//! its environment and its output redacted.
//!
//! 1. Under a tracer the CLI refuses at once, with exit 125 and `traced`
//!    (gate 19), before any contact with the daemon. Only a verified
//!    daemon is then asked; with none, run says how to start one and
//!    starts nothing.
//! 2. It finds the nearest `envcloak.toml` upward from the working
//!    directory, and sends its path. The daemon opens the manifest itself.
//! 3. It sends the profile and `--ref` bindings, the `--env-file`'s
//!    references and the names of its ordinary variables (never their
//!    values, which the runner sets for the command), the command line as
//!    display text, and the names of the agent markers in its
//!    environment. The env file can hold values, so its bytes are read
//!    only into a [`SecretBuf`], and an error names its kind and line,
//!    never text from the file (docs/MANIFEST.md "Env files").
//! 4. The daemon answers with the decision. When no grant covers the
//!    request, it is pending: exit 125 with `approval_required
//!    request=<id>`, naming `envcloak approve <id>`. Approval input is
//!    never read here: the terminal this command runs in may be an
//!    agent's.
//! 5. A covered answer carries the bindings' values, which the daemon
//!    sent after their audit entry was on disk. The connection is closed,
//!    and the runner ([`envcloak_exec`]) takes over: values under 8 bytes,
//!    and values of 8 to 15 bytes whose item lacks `allow_short`, are
//!    refused (exit 125, `value_too_short`, naming the slugs); what the
//!    redactor covers less than fully is printed by slug on standard
//!    error; then the command starts with the values and the env file's
//!    ordinary variables in its environment only, its standard output and
//!    standard error each through the redactor, and this command exits
//!    with its code, or 128 plus the signal that ended it (or that stopped
//!    the run after it exited). A command that is not found exits 127, and
//!    one that cannot be run 126, as with `env(1)`. The command sees pipes
//!    rather than a terminal, so programs that color their output only on
//!    a terminal print plain text; PTY mode is M2's (`--pty`, docs/RUN.md).
//!
//! No argument is ever echoed, and no value is ever accepted on the
//! command line (gate 13): `--ref` names an item, never a value. The
//! values never enter this process's environment or argv, or a file.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use envcloak_client::claims::claims;
use envcloak_client::connect::connect;
use envcloak_client::fail::{Failure, RUN_FAILURE, USAGE, refuse_if_traced, usage};
use envcloak_core::vault::Slug;
use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_exec::{CoverageReport, ExecError, Label, RunSpec, ShortPolicy};
use envcloak_ipc::proto::{EnvFileParams, ReleasedValue, RunRequestParams};
use envcloak_ipc::view::DecisionView;
use envcloak_policy::{
    Binding, EnvFileRefs, EnvName, GrantId, MAX_ENV_FILE, Mode, PendingId, PlainVar, find_manifest,
    parse_env_file_refs,
};
use zeroize::Zeroize;

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
    // Names only (gate 13): a `--ref` or `--profile` shaped like a key is
    // refused, unechoed, before anything is sent. The command after `--`
    // is the user's own, which the audit entry masks.
    let mut names: Vec<&str> = a.profile.iter().map(String::as_str).collect();
    names.extend(a.refs.iter().flat_map(|r| r.split(['=', '#'])));
    if let Err(f) = super::refuse_value_like(&names) {
        return f.report(USAGE);
    }
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
    // Its ordinary variables' values stay here: the runner sets them for
    // the command.
    let env_file = a.env_file.as_deref().map(read_env_file).transpose()?;
    let answer = client.run_request(&RunRequestParams {
        manifest,
        profile: a.profile,
        refs: a.refs,
        env_file: env_file.as_ref().map(|f| EnvFileParams::from(&f.names())),
        argv: a.argv.clone(),
        claims: claims(),
    })?;
    drop(client);
    let decision = answer.decision;
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
        DecisionView::Covered { grant, mode, .. } => {
            GrantId::parse(&grant).ok_or_else(protocol)?;
            // Proxy mode is M6's; the daemon refuses it before deciding.
            if mode != Mode::Inject {
                return Err(protocol());
            }
            // The answer's `redact` is always true in M1, which has no way
            // to turn redaction off; the runner redacts whatever it says.
            let plain = env_file.map(|f| f.plain).unwrap_or_default();
            start(answer.values, plain, a.argv)
        }
    }
}

/// Runs `argv` with the released values and the env file's ordinary
/// variables in its environment, its output redacted. Returns the
/// command's exit code.
fn start(
    values: Vec<ReleasedValue>,
    plain: Vec<PlainVar>,
    argv: Vec<String>,
) -> Result<ExitCode, Failure> {
    let mut bound: Vec<(EnvName, Slug, SecretBytes, ShortPolicy)> =
        Vec::with_capacity(values.len());
    for v in values {
        let name = EnvName::new(&v.env_name).map_err(|_| protocol())?;
        let slug = Slug::new(&v.slug).map_err(|_| protocol())?;
        bound.push((
            name,
            slug,
            v.value.into_inner(),
            ShortPolicy::from(v.allow_short),
        ));
    }
    let built = {
        let labels: Vec<Label<'_>> = bound
            .iter()
            .map(|(_, slug, value, short)| Label {
                slug,
                value,
                short: *short,
            })
            .collect();
        envcloak_exec::build_redactor(&labels)
    };
    let (redactor, report) = match built {
        Ok(b) => b,
        Err(ExecError::ValueTooShort(r)) => return Err(too_short(&r)),
        Err(e) => return Ok(exec_failure(&e)),
    };
    // Gate 12: a test build panics here on request, holding the values and
    // the redactor built from them.
    envcloak_sys::panic_point("cli.run.released");
    print_coverage(&report);
    let out = |fd: std::os::fd::BorrowedFd<'_>| {
        fd.try_clone_to_owned().map_err(|_| {
            Failure::new(
                "run_failed",
                "this command's standard output or standard error is not open",
            )
        })
    };
    // The env file's ordinary variables first: a binding of the same name
    // (the daemon refuses one) could not be overridden by them.
    let mut injected: Vec<(EnvName, SecretBytes)> =
        plain.into_iter().map(|p| (p.name, p.value)).collect();
    injected.extend(bound.into_iter().map(|(name, _, value, _)| (name, value)));
    // The idle flush is IDLE_FLUSH, and standard input this process's own.
    let spec = RunSpec::new(
        argv.into_iter().map(OsString::from).collect(),
        injected,
        redactor,
        out(std::io::stdout().as_fd())?,
        out(std::io::stderr().as_fd())?,
    );
    match envcloak_exec::run(spec) {
        Ok(exit) => Ok(ExitCode::from(exit.shell_code())),
        Err(e) => Ok(exec_failure(&e)),
    }
}

/// `value_too_short`, naming the refused items by slug.
fn too_short(r: &CoverageReport) -> Failure {
    let slugs: Vec<&str> = r.refused_short.iter().map(Slug::as_str).collect();
    Failure::new(
        "value_too_short",
        format!(
            "{}: a value under 8 bytes is never injected, and one of 8 to 15 bytes only when \
             its item allows short values; nothing was started",
            slugs.join(", ")
        ),
    )
}

/// Reports a runner failure with its exit code: 127 for a command not
/// found and 126 for one that could not be run, as `env(1)` has them, and
/// 125 for EnvCloak's own.
fn exec_failure(e: &ExecError) -> ExitCode {
    Failure::new(e.token(), e.message()).report(e.exit_code())
}

/// What the redactor covers less than fully, one line per item on
/// standard error, before the command starts.
fn print_coverage(r: &CoverageReport) {
    for s in &r.warned_short {
        eprintln!(
            "envcloak: coverage: {s} is 8 to 15 bytes (allowed short): the value and its \
             whole-value encodings are redacted, but a short value can also match ordinary output"
        );
    }
    for s in &r.partial {
        eprintln!(
            "envcloak: coverage: {s}: inside a longer base64 stream it is redacted at some byte \
             alignments only"
        );
    }
    for s in &r.truncated {
        eprintln!(
            "envcloak: coverage: {s}: JSON escapes are redacted as common serializers write \
             them, not in every combination of options"
        );
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
