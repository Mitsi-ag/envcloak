//! `envcloak add [PROVIDER] [--slug SLUG] [--field NAME] [--account
//! ACCOUNT] [--env NAME] [--allow-short] [--stdin] [--json]` (SPEC §6.3):
//! a new secret item, without the value ever being on the command line.
//!
//! 1. The options are names only: there is no option for the value, and
//!    an argument shaped like a key or token is refused unechoed (gate 13).
//! 2. A verified daemon must have the vault unlocked before the value is
//!    asked for.
//! 3. Under a tracer nothing is read (gate 19). The value is read from
//!    `/dev/tty` with echo off, or from standard input with `--stdin`
//!    (a pipe: a terminal there is refused, since it would show the value).
//! 4. The daemon detects the provider from the value's shape when none is
//!    named, pre-fills the item's links and hosts, picks a free slug when
//!    none is given (`openai`, then `openai-2`, ...), and seals the value.
//!    Adding needs no proof: nothing is bound to a new item yet
//!    (SPEC §10b).
//!
//! The output is the item's metadata and how to reference it; the account
//! is shown, since the person running the command just typed it.

use std::process::ExitCode;
use std::time::Duration;

use envcloak_client::claims::claims;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, RUN_FAILURE, USAGE, refuse_if_traced, usage};
use envcloak_client::render::{print, registry};
use envcloak_client::tty::{InputError, MAX_VALUE, Terminal, read_stdin_value, read_value_from};
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::AddParams;
use envcloak_ipc::wait::MAX_WAIT;
use envcloak_sys::{PasteboardError, read_and_clear_pasteboard};

use super::{refuse_value_like, require_unlocked};

const USAGE_TEXT: &str =
    "envcloak add [PROVIDER] [--slug SLUG] [--field NAME] [--account ACCOUNT] \
     [--env NAME] [--allow-short] [--stdin] [--json]
       the value is typed at a hidden prompt, or piped in with --stdin; never an argument";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct AddArgs {
    provider: Option<String>,
    slug: Option<String>,
    field: Option<String>,
    account: Option<String>,
    env: Option<String>,
    note: Option<String>,
    allow_short: bool,
    stdin: bool,
    from_clipboard: bool,
    ask: bool,
    wait: Option<Duration>,
    json: bool,
}

impl AddArgs {
    /// Every name given, for [`refuse_value_like`].
    fn names(&self) -> Vec<&str> {
        [
            &self.provider,
            &self.slug,
            &self.field,
            &self.account,
            &self.env,
            &self.note,
        ]
        .into_iter()
        .filter_map(|n| n.as_deref())
        .collect()
    }
}

/// `<n>s` or `<n>m`, from 1 second to [`MAX_WAIT`] (10 minutes).
fn parse_wait(s: &str) -> Option<Duration> {
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else {
        (s.strip_suffix('m')?, 60)
    };
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d = Duration::from_secs(digits.parse::<u64>().ok()?.checked_mul(per_unit)?);
    (Duration::from_secs(1)..=MAX_WAIT)
        .contains(&d)
        .then_some(d)
}

fn parse(args: &[&str]) -> Result<AddArgs, &'static str> {
    let mut a = AddArgs::default();
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        let slot = match arg {
            "--slug" => &mut a.slug,
            "--field" => &mut a.field,
            "--account" => &mut a.account,
            "--env" => &mut a.env,
            "--note" => &mut a.note,
            "--allow-short" if !a.allow_short => {
                a.allow_short = true;
                continue;
            }
            "--stdin" if !a.stdin => {
                a.stdin = true;
                continue;
            }
            "--from-clipboard" if !a.from_clipboard => {
                a.from_clipboard = true;
                continue;
            }
            "--ask" if !a.ask => {
                a.ask = true;
                continue;
            }
            "--wait" => {
                if a.wait.is_some() {
                    return Err("an option is given twice");
                }
                let d = it
                    .next()
                    .and_then(|v| parse_wait(v))
                    .ok_or("--wait needs a duration from 1s to 10m, such as 30s or 5m")?;
                a.wait = Some(d);
                continue;
            }
            "--json" if !a.json => {
                a.json = true;
                continue;
            }
            "--value" => {
                return Err("there is no --value: values are never taken on the command line");
            }
            flag if flag.starts_with('-') => return Err("unknown or repeated option"),
            _ if a.provider.is_none() => {
                a.provider = Some(arg.to_owned());
                continue;
            }
            _ => {
                return Err("add takes one PROVIDER; values are never taken on the command line");
            }
        };
        if slot.is_some() {
            return Err("an option is given twice");
        }
        *slot = Some((*it.next().ok_or("an option needs a name after it")?).to_owned());
    }
    if usize::from(a.stdin) + usize::from(a.from_clipboard) + usize::from(a.ask) > 1 {
        return Err("--stdin, --from-clipboard and --ask cannot be combined");
    }
    if (a.wait.is_some() || a.note.is_some()) && !a.ask {
        return Err("--wait and --note are only used with --ask");
    }
    if a.ask {
        if a.provider.is_none() {
            return Err("add --ask needs a PROVIDER: envcloak add <provider> --ask");
        }
        if a.slug.is_some() || a.field.is_some() || a.allow_short {
            return Err("--ask takes only <provider>, --account, --env, --note, --wait and --json");
        }
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
    if let Err(f) = refuse_value_like(&a.names()) {
        return f.report(USAGE);
    }
    if a.ask {
        return add_ask(a);
    }
    add(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn validate_provider(provider: Option<&str>) -> Result<(), Failure> {
    if let (Some(p), Some(r)) = (provider, registry())
        && r.get(p).is_none()
    {
        return Err(Failure::new(
            "invalid_item",
            "no provider has that name; leave it out, and it is detected from the value",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn current_project_dir() -> Option<String> {
    use envcloak_policy::find_manifest;
    use std::path::Path;

    let manifest = find_manifest(Path::new(".")).ok().flatten()?;
    let dir = std::fs::canonicalize(manifest.parent()?).ok()?;
    let s = dir.into_os_string().into_string().ok()?;
    (!s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)).then_some(s)
}

fn add_ask(a: AddArgs) -> ExitCode {
    if let Err(f) = validate_provider(a.provider.as_deref()) {
        return f.report(FAILURE);
    }
    if let Err(f) = refuse_if_traced() {
        return f.report(RUN_FAILURE);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = a;
        Failure::new(
            "app_required",
            "add --ask opens the EnvCloak app on macOS; on Linux, run `envcloak add` in a \
             separate terminal",
        )
        .report(RUN_FAILURE)
    }
    #[cfg(target_os = "macos")]
    {
        use envcloak_client::connect::run_paths;
        use envcloak_client::render::shown;
        use envcloak_ipc::proto::AskParams;
        use envcloak_ipc::{AskWaitOutcome, Client};

        if envcloak_sys::termination_ends_process().is_err() {
            return Failure::new(
                "run_failed",
                "SIGINT and SIGTERM could not be made to end the wait; nothing was sent",
            )
            .report(RUN_FAILURE);
        }
        let paths = match run_paths() {
            Ok(p) => p,
            Err(f) => return f.report(FAILURE),
        };
        let params = AskParams {
            provider: a.provider,
            project_dir: current_project_dir(),
            account: a.account,
            env_hint: a.env,
            note: a.note,
            claims: claims(),
        };
        match Client::wait_for_ask(&paths, &params, a.wait.unwrap_or(MAX_WAIT)) {
            Ok(AskWaitOutcome::Added { slug }) => {
                if a.json {
                    println!("{}", serde_json::json!({ "slug": slug }));
                } else {
                    println!("{}", shown(&slug));
                }
                ExitCode::SUCCESS
            }
            Ok(AskWaitOutcome::Declined) => {
                Failure::new("declined", "the request to add a key was declined")
                    .report(RUN_FAILURE)
            }
            Ok(AskWaitOutcome::Expired) => Failure::new(
                "expired",
                "the request to add a key expired before it was answered",
            )
            .report(RUN_FAILURE),
            Err(e) => Failure::from(e).report(FAILURE),
        }
    }
}

fn read_clipboard_value() -> Result<envcloak_core::SecretBytes, Failure> {
    let pb = read_and_clear_pasteboard(MAX_VALUE + 2).map_err(|e| match e {
        PasteboardError::Unavailable => Failure::new(
            "app_required",
            "--from-clipboard is only available on macOS; pipe the value in with --stdin or type \
             it at the prompt",
        ),
        PasteboardError::Empty => Failure::new("no_input", "the clipboard holds no text"),
        PasteboardError::TooLong => InputError::TooLong.into(),
    })?;
    let parsed = read_value_from(&mut &pb.bytes[..]).map_err(|e| match e {
        InputError::Empty => Failure::new("no_input", "the clipboard holds no value"),
        e => e.into(),
    });
    let cleared = pb.cleared;
    drop(pb);
    if cleared {
        eprintln!(
            "envcloak: warning: cleared from the clipboard; clipboard history tools may already \
             hold the value"
        );
    } else {
        eprintln!(
            "envcloak: warning: the clipboard changed before it could be cleared; clipboard \
             history tools may already hold the value"
        );
    }
    parsed
}

fn add(a: AddArgs) -> Result<ExitCode, Failure> {
    validate_provider(a.provider.as_deref())?;
    refuse_if_traced()?;
    #[cfg(not(target_os = "macos"))]
    if a.from_clipboard {
        return Err(Failure::new(
            "app_required",
            "--from-clipboard is only available on macOS; pipe the value in with --stdin or type \
             it at the prompt",
        ));
    }
    // The vault is unlocked before the value is asked for.
    require_unlocked(&mut connect()?)?;
    let value = if a.from_clipboard {
        read_clipboard_value()?
    } else if a.stdin {
        read_stdin_value()?
    } else {
        Terminal::open()
            .map_err(|_| {
                Failure::new(
                    "no_terminal",
                    "there is no terminal to type the value on; pipe it in with --stdin",
                )
            })?
            .read_secret("Value for the new item (typing is hidden): ")
            .map_err(|e| match e {
                InputError::Empty => Failure::new("no_input", "no value was entered"),
                e => e.into(),
            })?
    };
    let params = AddParams {
        slug: a.slug,
        provider: a.provider,
        field: a.field,
        account: a.account,
        env_hint: a.env,
        allow_short: a.allow_short,
        value: WireSecret::new(value),
        claims: claims(),
    };
    let added = connect()?.items_add(&params)?;
    drop(params);
    print(&added, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_names_and_there_is_no_value_option() {
        assert_eq!(parse(&[]).unwrap(), AddArgs::default());
        assert_eq!(
            parse(&[
                "openai",
                "--slug",
                "openai/work",
                "--account",
                "you@work.com",
                "--env",
                "OPENAI_API_KEY",
                "--field",
                "api_key",
                "--allow-short",
                "--stdin",
                "--json",
            ])
            .unwrap(),
            AddArgs {
                provider: Some("openai".into()),
                slug: Some("openai/work".into()),
                field: Some("api_key".into()),
                account: Some("you@work.com".into()),
                env: Some("OPENAI_API_KEY".into()),
                note: None,
                allow_short: true,
                stdin: true,
                from_clipboard: false,
                ask: false,
                wait: None,
                json: true,
            }
        );
        assert_eq!(
            parse(&[
                "openai",
                "--ask",
                "--account",
                "you@work.com",
                "--wait",
                "30s",
                "--json"
            ])
            .unwrap(),
            AddArgs {
                provider: Some("openai".into()),
                account: Some("you@work.com".into()),
                ask: true,
                wait: Some(Duration::from_secs(30)),
                json: true,
                ..AddArgs::default()
            }
        );
        assert_eq!(
            parse(&["openai", "--from-clipboard"]).unwrap(),
            AddArgs {
                provider: Some("openai".into()),
                from_clipboard: true,
                ..AddArgs::default()
            }
        );
        for bad in [
            &["--value", "x"][..],
            &["--value"],
            &["openai", "a-second-positional"],
            &["--slug"],
            &["--slug", "a", "--slug", "b"],
            &["--stdin", "--stdin"],
            &["--from-clipboard", "--from-clipboard"],
            &["--stdin", "--from-clipboard"],
            &["--stdin", "--ask", "openai"],
            &["--from-clipboard", "--ask", "openai"],
            &["--ask"],
            &["openai", "--ask", "--slug", "openai/work"],
            &["openai", "--ask", "--field", "api_key"],
            &["openai", "--ask", "--allow-short"],
            &["openai", "--wait", "30s"],
            &["openai", "--ask", "--wait", "0s"],
            &["openai", "--ask", "--wait", "11m"],
            &["--bogus"],
            &["-v"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
