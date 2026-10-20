//! `envcloak login add <slug> [--test | --live] [--tier <tier>]
//! [--session-lifetime <dur>] [--adapter-key] [--username-fd N]
//! [--password-fd N] [--totp-fd N] [--adapter-key-fd N] [--json]`
//! (SPEC §6.8 "Login items", M2b-03).
//!
//! Enrolls a login item with typed credential fields (`username`, `password`,
//! optional `totp` from an `otpauth://totp/` URI, and optional `adapter_key`).
//! Credential material is read only from `/dev/tty` with echo off or from
//! inherited file descriptors named by `--*-fd`, never from `argv`.

use std::process::ExitCode;

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use envcloak_client::render::print;
use envcloak_client::tty::{InputError, Terminal, read_value_fd};
use envcloak_core::vault::{DEFAULT_LOGIN_SESSION_LIFETIME_SECS, MAX_LOGIN_SESSION_LIFETIME_SECS};
use envcloak_ipc::WireSecret;
use envcloak_ipc::proto::LoginAddParams;
use envcloak_ipc::view::{ClassificationView, LoginTierView};

use super::{fd_number, refuse_value_like, require_unlocked};

const USAGE_TEXT: &str =
    "envcloak login add <slug> [--test | --live] [--tier dev|each|never-agent] \
     [--session-lifetime <dur>] [--adapter-key] [--username-fd N] [--password-fd N] \
     [--totp-fd N] [--adapter-key-fd N] [--json]
       credentials are typed at hidden prompts on /dev/tty or read from --*-fd; never arguments";

#[derive(Debug, PartialEq, Eq)]
struct LoginAddArgs {
    slug: String,
    classification: ClassificationView,
    tier: LoginTierView,
    session_lifetime_secs: u64,
    adapter_key: bool,
    username_fd: Option<i32>,
    password_fd: Option<i32>,
    totp_fd: Option<i32>,
    adapter_key_fd: Option<i32>,
    json: bool,
}

fn parse_duration_secs(s: &str) -> Option<u64> {
    let (digits, factor) = if let Some(d) = s.strip_suffix('s') {
        (d, 1u64)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60u64)
    } else {
        (s.strip_suffix('h')?, 3600u64)
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(factor)?;
    (1..=MAX_LOGIN_SESSION_LIFETIME_SECS)
        .contains(&secs)
        .then_some(secs)
}

fn parse_tier(s: &str) -> Option<LoginTierView> {
    match s {
        "dev" => Some(LoginTierView::Dev),
        "each" => Some(LoginTierView::Each),
        "never-agent" => Some(LoginTierView::NeverAgent),
        _ => None,
    }
}

fn parse(args: &[&str]) -> Result<LoginAddArgs, &'static str> {
    let mut slug: Option<String> = None;
    let mut classification: Option<ClassificationView> = None;
    let mut tier: Option<LoginTierView> = None;
    let mut session_lifetime_secs: Option<u64> = None;
    let mut adapter_key = false;
    let mut username_fd: Option<i32> = None;
    let mut password_fd: Option<i32> = None;
    let mut totp_fd: Option<i32> = None;
    let mut adapter_key_fd: Option<i32> = None;
    let mut json = false;

    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--test" if classification.is_none() => {
                classification = Some(ClassificationView::Test);
            }
            "--live" if classification.is_none() => {
                classification = Some(ClassificationView::Live);
            }
            "--test" | "--live" => {
                return Err("choose at most one of --test and --live");
            }
            "--tier" if tier.is_none() => {
                let raw = *it
                    .next()
                    .ok_or("--tier needs one of dev, each or never-agent")?;
                tier =
                    Some(parse_tier(raw).ok_or("--tier must be one of dev, each or never-agent")?);
            }
            "--session-lifetime" if session_lifetime_secs.is_none() => {
                let raw = *it
                    .next()
                    .ok_or("--session-lifetime needs a duration from 1s to 24h")?;
                session_lifetime_secs = Some(parse_duration_secs(raw).ok_or(
                    "--session-lifetime needs a duration from 1s to 24h, such as 30m or 1h",
                )?);
            }
            "--adapter-key" if !adapter_key => {
                adapter_key = true;
            }
            "--username-fd" if username_fd.is_none() => {
                let raw = *it.next().ok_or("--username-fd needs a descriptor number")?;
                username_fd =
                    Some(fd_number(raw).ok_or("--username-fd needs a descriptor number")?);
            }
            "--password-fd" if password_fd.is_none() => {
                let raw = *it.next().ok_or("--password-fd needs a descriptor number")?;
                password_fd =
                    Some(fd_number(raw).ok_or("--password-fd needs a descriptor number")?);
            }
            "--totp-fd" if totp_fd.is_none() => {
                let raw = *it.next().ok_or("--totp-fd needs a descriptor number")?;
                totp_fd = Some(fd_number(raw).ok_or("--totp-fd needs a descriptor number")?);
            }
            "--adapter-key-fd" if adapter_key_fd.is_none() => {
                let raw = *it
                    .next()
                    .ok_or("--adapter-key-fd needs a descriptor number")?;
                adapter_key_fd =
                    Some(fd_number(raw).ok_or("--adapter-key-fd needs a descriptor number")?);
            }
            "--json" if !json => {
                json = true;
            }
            "--username" | "--password" | "--totp" | "--seed" | "--value" => {
                return Err("credentials are never taken on the command line");
            }
            flag if flag.starts_with('-') => {
                return Err("unknown or repeated option");
            }
            _ if slug.is_none() => {
                slug = Some(arg.to_owned());
            }
            _ => {
                return Err("login add takes one <slug>; credentials are never arguments");
            }
        }
    }

    let slug = slug.ok_or("login add needs a <slug>")?;
    let fds: Vec<i32> = [username_fd, password_fd, totp_fd, adapter_key_fd]
        .into_iter()
        .flatten()
        .collect();
    for (i, fd) in fds.iter().enumerate() {
        if fds[i + 1..].contains(fd) {
            return Err("each --*-fd option must name a distinct file descriptor");
        }
    }

    Ok(LoginAddArgs {
        slug,
        classification: classification.unwrap_or(ClassificationView::Test),
        tier: tier.unwrap_or(LoginTierView::Each),
        session_lifetime_secs: session_lifetime_secs.unwrap_or(DEFAULT_LOGIN_SESSION_LIFETIME_SECS),
        adapter_key: adapter_key || adapter_key_fd.is_some(),
        username_fd,
        password_fd,
        totp_fd,
        adapter_key_fd,
        json,
    })
}

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["--help"] | ["-h"] | ["add", "--help"] | ["add", "-h"] => {
            println!("usage: {USAGE_TEXT}");
            ExitCode::SUCCESS
        }
        ["add", rest @ ..] => {
            let a = match parse(rest) {
                Ok(a) => a,
                Err(why) => {
                    eprintln!("envcloak: {why}");
                    return usage(USAGE_TEXT);
                }
            };
            if let Err(f) = refuse_value_like(&[a.slug.as_str()]) {
                return f.report(USAGE);
            }
            login_add(a).unwrap_or_else(|f| f.report(FAILURE))
        }
        _ => usage(USAGE_TEXT),
    }
}

fn login_add(a: LoginAddArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    if a.classification != ClassificationView::Test && a.tier == LoginTierView::Dev {
        return Err(Failure::new(
            "invalid_item",
            "live login items cannot use the dev tier",
        ));
    }

    let mut client = connect()?;
    require_unlocked(&mut client)?;
    drop(client);

    let no_terminal = |what: &'static str| {
        move |_| {
            Failure::new(
                "no_terminal",
                format!("there is no terminal to type {what} on"),
            )
        }
    };
    let mut terminal: Option<Terminal> = None;

    let username = match a.username_fd {
        Some(fd) => read_value_fd(fd)?,
        None => {
            let t = match terminal.as_mut() {
                Some(t) => t,
                None => terminal.insert(
                    Terminal::open().map_err(no_terminal("the username; pass --username-fd"))?,
                ),
            };
            let v = t
                .read_secret("Username (typing is hidden): ")
                .map_err(|e| match e {
                    InputError::Empty => Failure::new("no_input", "no username was entered"),
                    other => other.into(),
                })?;
            if v.is_empty() {
                return Err(Failure::new("no_input", "no username was entered"));
            }
            v
        }
    };

    let password = match a.password_fd {
        Some(fd) => read_value_fd(fd)?,
        None => {
            let t = match terminal.as_mut() {
                Some(t) => t,
                None => terminal.insert(
                    Terminal::open().map_err(no_terminal("the password; pass --password-fd"))?,
                ),
            };
            let v = t
                .read_secret("Password (typing is hidden): ")
                .map_err(|e| match e {
                    InputError::Empty => Failure::new("no_input", "no password was entered"),
                    other => other.into(),
                })?;
            if v.is_empty() {
                return Err(Failure::new("no_input", "no password was entered"));
            }
            v
        }
    };

    let totp_uri = match a.totp_fd {
        Some(fd) => Some(read_value_fd(fd)?),
        None if a.username_fd.is_some() && a.password_fd.is_some() => None,
        None => {
            let t = match terminal.as_mut() {
                Some(t) => t,
                None => terminal
                    .insert(Terminal::open().map_err(no_terminal("the TOTP URI; pass --totp-fd"))?),
            };
            match t.read_secret("TOTP otpauth:// URI (optional, press Enter to skip): ") {
                Ok(uri) if uri.is_empty() => None,
                Ok(uri) => Some(uri),
                Err(InputError::Empty) => None,
                Err(other) => return Err(other.into()),
            }
        }
    };

    if let Some(ref uri) = totp_uri
        && envcloak_signin::otpauth::parse(uri).is_err()
    {
        return Err(Failure::new(
            "invalid_item",
            "the TOTP URI is not a valid otpauth://totp/ enrollment URI",
        ));
    }

    let adapter_key = match (a.adapter_key, a.adapter_key_fd) {
        (_, Some(fd)) => Some(read_value_fd(fd)?),
        (true, None) => {
            let t = match terminal.as_mut() {
                Some(t) => t,
                None => terminal.insert(
                    Terminal::open()
                        .map_err(no_terminal("the adapter key; pass --adapter-key-fd"))?,
                ),
            };
            let v = t
                .read_secret("Adapter key (typing is hidden): ")
                .map_err(|e| match e {
                    InputError::Empty => Failure::new("no_input", "no adapter key was entered"),
                    other => other.into(),
                })?;
            if v.is_empty() {
                return Err(Failure::new("no_input", "no adapter key was entered"));
            }
            Some(v)
        }
        (false, None) => None,
    };

    let params = LoginAddParams {
        slug: a.slug,
        classification: a.classification,
        tier: a.tier,
        session_lifetime_secs: a.session_lifetime_secs,
        username: WireSecret::new(username),
        password: WireSecret::new(password),
        totp: totp_uri.map(WireSecret::new),
        adapter_key: adapter_key.map(WireSecret::new),
        claims: claims_now,
    };
    let added = connect()?.login_add(&params)?;
    print(&added, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_add_parses_options_and_refuses_credential_arguments() {
        let a = parse(&["acme/editor"]).unwrap();
        assert_eq!(
            a,
            LoginAddArgs {
                slug: "acme/editor".into(),
                classification: ClassificationView::Test,
                tier: LoginTierView::Each,
                session_lifetime_secs: DEFAULT_LOGIN_SESSION_LIFETIME_SECS,
                adapter_key: false,
                username_fd: None,
                password_fd: None,
                totp_fd: None,
                adapter_key_fd: None,
                json: false,
            }
        );

        let a = parse(&[
            "acme/editor",
            "--test",
            "--tier",
            "dev",
            "--session-lifetime",
            "2h",
            "--adapter-key",
            "--username-fd",
            "3",
            "--password-fd",
            "4",
            "--totp-fd",
            "5",
            "--adapter-key-fd",
            "6",
            "--json",
        ])
        .unwrap();
        assert_eq!(
            a,
            LoginAddArgs {
                slug: "acme/editor".into(),
                classification: ClassificationView::Test,
                tier: LoginTierView::Dev,
                session_lifetime_secs: 7200,
                adapter_key: true,
                username_fd: Some(3),
                password_fd: Some(4),
                totp_fd: Some(5),
                adapter_key_fd: Some(6),
                json: true,
            }
        );

        for bad in [
            &[][..],
            &["a", "b"],
            &["a", "--password", "secret"],
            &["a", "--username", "alice"],
            &["a", "--totp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"],
            &["a", "--value", "secret"],
            &["a", "--test", "--live"],
            &["a", "--tier", "bogus"],
            &["a", "--session-lifetime", "0s"],
            &["a", "--session-lifetime", "25h"],
            &["a", "--username-fd", "3", "--password-fd", "3"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
