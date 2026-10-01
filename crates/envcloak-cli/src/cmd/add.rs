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

use envcloak_client::claims::claims;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use envcloak_client::render::{print, registry};
use envcloak_client::tty::{InputError, Terminal, read_stdin_value};
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::AddParams;

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
    allow_short: bool,
    stdin: bool,
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
        ]
        .into_iter()
        .filter_map(|n| n.as_deref())
        .collect()
    }
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
            "--allow-short" if !a.allow_short => {
                a.allow_short = true;
                continue;
            }
            "--stdin" if !a.stdin => {
                a.stdin = true;
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
    add(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn add(a: AddArgs) -> Result<ExitCode, Failure> {
    if let (Some(p), Some(r)) = (a.provider.as_deref(), registry()) {
        if r.get(p).is_none() {
            return Err(Failure::new(
                "invalid_item",
                "no provider has that name; leave it out, and it is detected from the value",
            ));
        }
    }
    // The vault is unlocked before the value is asked for.
    require_unlocked(&mut connect()?)?;
    refuse_if_traced()?;
    let value = if a.stdin {
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
                allow_short: true,
                stdin: true,
                json: true,
            }
        );
        for bad in [
            &["--value", "x"][..],
            &["--value"],
            &["openai", "a-second-positional"],
            &["--slug"],
            &["--slug", "a", "--slug", "b"],
            &["--stdin", "--stdin"],
            &["--bogus"],
            &["-v"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
