//! `envcloak mcp-bridge`: client bridges for HTTP and stdio MCP servers and
//! the daemon-started HTTP relay (`--relay`) (SPEC §6.4, §6.6; M2 plan
//! D-04, D-05, D-06, D-18, D-33, D-36; task M2-18).
//!
//! Three forms:
//! 1. `envcloak mcp-bridge --manifest <path> --url <url>
//!    --header-ref <Header>=<slug>[#<field>]... [--wait [DURATION]]`
//!    (HTTP client mode): validates the URL (`https://`, or `http://` on
//!    loopback only) and header references, sends `run.request` with its
//!    pipe ends and lifeline over `SCM_RIGHTS`, never receives secret
//!    header values (D-36), and forwards MCP JSON-RPC traffic to and from
//!    the daemon-started relay.
//! 2. `envcloak mcp-bridge --stdio --launch <launch-id> [--wait [DURATION]]`
//!    (stdio client mode): hands its pipe ends and lifeline to `envcloakd`
//!    for the registered launch, never receives secret values, and pumps
//!    standard input and output to and from the daemon-started runner.
//! 3. `envcloak mcp-bridge --relay` (daemon-started relay): verifies that
//!    `envcloakd` is its parent (`not_started_by_daemon` otherwise), reads
//!    the released header values and registered origin from the control
//!    channel, enforces provider `allowed_hosts`, and executes MCP
//!    Streamable HTTP over `ureq` + `rustls` with platform certificate
//!    verification, zero redirects, and full response redaction.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use envcloak_client::fail::{RUN_FAILURE, USAGE, usage};
use envcloak_ipc::wait::MAX_WAIT;
use envcloak_mcp::bridge::{
    Bridge, BridgeUrl, HeaderRef, HttpBridgeConfig, StdioBridgeConfig, WaitBudget,
    default_wait_budget,
};
use envcloak_policy::managed::parse_launch_id;

const USAGE_TEXT: &str = "envcloak mcp-bridge --manifest /absolute/path/envcloak.toml --url URL \
     --header-ref HEADER=slug[#field]... [--wait [DURATION (1s to 10m)]]\n       \
     envcloak mcp-bridge --stdio --launch LAUNCH_ID [--wait [DURATION (1s to 10m)]]";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Http(HttpBridgeConfig),
    Stdio(StdioBridgeConfig),
    Relay,
}

/// `<n>s` or `<n>m`, from 1 second to [`MAX_WAIT`] (10 minutes).
fn parse_wait_duration(s: &str) -> Option<Duration> {
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

fn check_value_like_args(args: &[&str]) -> Result<(), ExitCode> {
    let mut names: Vec<&str> = Vec::new();
    let mut it = args.iter().copied();
    while let Some(arg) = it.next() {
        match arg {
            "--manifest" => {
                if let Some(v) = it.next() {
                    names.extend(v.split('/'));
                }
            }
            "--url" => {
                if let Some(v) = it.next() {
                    names.extend(v.split(['/', ':', '?', '&', '=']));
                }
            }
            "--header-ref" | "--header" => {
                if let Some(v) = it.next() {
                    names.extend(v.split(['=', '#']));
                }
            }
            "--launch" => {
                if let Some(v) = it.next() {
                    if parse_launch_id(v).is_none() {
                        names.push(v);
                    }
                }
            }
            "--wait" | "--stdio" | "--relay" | "--http" => {}
            other => {
                if !other.starts_with('-') && parse_wait_duration(other).is_none() {
                    names.push(other);
                }
            }
        }
    }
    super::refuse_value_like(&names).map_err(|f| f.report(USAGE))
}

fn parse(args: &[&str]) -> Result<Mode, &'static str> {
    if args.is_empty() {
        return Err("mcp-bridge needs --url and --header-ref, or --stdio --launch");
    }
    if args == ["--relay"] {
        return Ok(Mode::Relay);
    }
    if args.contains(&"--relay") {
        return Err("--relay takes nothing else: envcloak mcp-bridge --relay");
    }

    let mut stdio = false;
    let mut http_flag = false;
    let mut launch: Option<String> = None;
    let mut manifest: Option<PathBuf> = None;
    let mut url: Option<BridgeUrl> = None;
    let mut headers: Vec<HeaderRef> = Vec::new();
    let mut wait: Option<WaitBudget> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "--stdio" => {
                if stdio {
                    return Err("--stdio is given twice");
                }
                stdio = true;
                i += 1;
            }
            "--http" => {
                if http_flag {
                    return Err("--http is given twice");
                }
                http_flag = true;
                i += 1;
            }
            "--launch" => {
                if launch.is_some() {
                    return Err("--launch is given twice");
                }
                let Some(&id) = args.get(i + 1) else {
                    return Err("--launch needs a 26-character launch id");
                };
                if parse_launch_id(id).is_none() {
                    return Err("--launch needs a 26-character Crockford base32 launch id");
                }
                launch = Some(id.to_owned());
                i += 2;
            }
            "--manifest" => {
                if manifest.is_some() {
                    return Err("--manifest is given twice");
                }
                let Some(&p) = args.get(i + 1) else {
                    return Err("--manifest needs the absolute path of an envcloak.toml");
                };
                if !Path::new(p).is_absolute() {
                    return Err("--manifest needs the absolute path of an envcloak.toml");
                }
                manifest = Some(PathBuf::from(p));
                i += 2;
            }
            "--url" => {
                if url.is_some() {
                    return Err("--url is given twice");
                }
                let Some(&u) = args.get(i + 1) else {
                    return Err("--url needs an https:// URL (or http:// on loopback)");
                };
                url = Some(
                    BridgeUrl::parse(u).map_err(|_| {
                        "--url needs an https:// URL (or http:// on loopback without userinfo or fragment)"
                    })?,
                );
                i += 2;
            }
            "--header-ref" | "--header" => {
                let Some(&r) = args.get(i + 1) else {
                    return Err("--header-ref needs <Header>=<slug>[#<field>]");
                };
                if headers.len() >= envcloak_mcp::bridge::http::MAX_HEADERS {
                    return Err("at most 32 --header-ref options may be given");
                }
                headers.push(
                    HeaderRef::parse(r).map_err(|_| {
                        "--header-ref needs <Header>=<slug>[#<field>] with a valid header name and slug"
                    })?,
                );
                i += 2;
            }
            "--wait" => {
                if wait.is_some() {
                    return Err("--wait is given twice");
                }
                match args.get(i + 1).copied() {
                    Some(next) if !next.starts_with('-') => {
                        let d = parse_wait_duration(next)
                            .ok_or("--wait needs a duration from 1s to 10m, such as 30s or 5m")?;
                        wait = Some(WaitBudget::explicit(d));
                        i += 2;
                    }
                    _ => {
                        wait = Some(default_wait_budget());
                        i += 1;
                    }
                }
            }
            _ => return Err("unknown option; see envcloak mcp-bridge --help"),
        }
    }

    if stdio {
        if http_flag || manifest.is_some() || url.is_some() || !headers.is_empty() {
            return Err("--stdio takes only --launch <id> (and optional --wait)");
        }
        let Some(launch_id) = launch else {
            return Err("--stdio needs --launch <id>");
        };
        return Ok(Mode::Stdio(StdioBridgeConfig { launch_id, wait }));
    }

    if launch.is_some() {
        return Err("--launch requires --stdio: envcloak mcp-bridge --stdio --launch <id>");
    }
    let Some(manifest) = manifest else {
        return Err("HTTP mode needs --manifest /absolute/path/envcloak.toml");
    };
    let Some(url) = url else {
        return Err("HTTP mode needs --url <https://...>");
    };
    if headers.is_empty() {
        return Err("HTTP mode needs at least one --header-ref <Header>=<slug>[#<field>]");
    }
    Ok(Mode::Http(HttpBridgeConfig {
        manifest,
        url,
        headers,
        wait,
    }))
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    if let Err(code) = check_value_like_args(args) {
        return code;
    }
    let mode = match parse(args) {
        Ok(m) => m,
        Err(why) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    let result = match mode {
        Mode::Http(cfg) => Bridge::run_http(&cfg),
        Mode::Stdio(cfg) => Bridge::run_stdio(&cfg),
        Mode::Relay => Bridge::run_relay(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) if f.message().is_empty() => ExitCode::from(RUN_FAILURE),
        Err(f) => f.report(RUN_FAILURE),
    }
}
