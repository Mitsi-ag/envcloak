//! `ec-launch-fixture`: the managed stdio server of the registered-launch
//! tests (M2 plan task M2-27). It reports what it is and what it got,
//! never a value: digests and names only.
//!
//! Usage: `ec-launch-fixture [--marker <path>] [--linger <secs>] [--var <NAME>]...`
//!
//! Its first act is to write `ran` to the marker file, so a test can tell
//! whether any of it ran (a suspended start that was refused never does).
//! Then, for each line on standard input:
//!
//! - `report`: one JSON line on standard output: its pid and parent pid;
//!   its own executable's SHA-256 (Linux, read through `/proc/self/exe`,
//!   which names the image the kernel runs, a sealed copy included) and
//!   code directory hash (macOS, the kernel's); the SHA-256 of its working
//!   directory's path; the names of its environment variables, sorted; and
//!   for each `--var`, the SHA-256 of its value, or `null` when it is not
//!   set;
//! - `spawn <argv as a JSON array>`: runs that command (standard input
//!   from `/dev/null`) as a child, and reports its exit code and the start
//!   of its standard error as one JSON line: what a command a managed
//!   server starts is told;
//! - anything else: ignored.
//!
//! At the end of its input it exits 0, or with `--linger`, that many seconds
//! later: a server that does not end with its input, so a test sees whether
//! the runner stops it. Test support only.

use std::io::{BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;

use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SHA-256 of the image this process runs (Linux).
fn exe_sha256() -> Option<String> {
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return None;
    }
    let mut f = std::fs::File::open("/proc/self/exe").ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex(&h.finalize()))
}

/// The kernel's code directory hash of this process (macOS).
fn cdhash() -> Option<String> {
    let me = i32::try_from(std::process::id()).ok()?;
    envcloak_sys::proc_info(me)
        .ok()?
        .exe?
        .signature?
        .cdhash
        .map(|h| hex(&h))
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mut marker = None;
    let mut linger = 0u64;
    let mut vars: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--marker") => marker = args.next(),
            Some("--linger") => {
                linger = args
                    .next()
                    .and_then(|v| v.to_str().and_then(|v| v.parse().ok()))
                    .unwrap_or(0);
            }
            Some("--var") => {
                if let Some(v) = args.next().and_then(|v| v.into_string().ok()) {
                    vars.push(v);
                }
            }
            _ => {}
        }
    }
    if let Some(m) = &marker {
        let _ = std::fs::write(m, b"ran\n");
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if let Some(argv) = line.trim().strip_prefix("spawn ") {
            let argv: Vec<String> = serde_json::from_str(argv).unwrap_or_default();
            let ran = argv.split_first().map(|(program, args)| {
                std::process::Command::new(program)
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .output()
            });
            let answer = match ran {
                Some(Ok(o)) => serde_json::json!({
                    "code": o.status.code(),
                    "stderr": String::from_utf8_lossy(&o.stderr).chars().take(400).collect::<String>(),
                }),
                _ => serde_json::json!({"code": null, "stderr": "not started"}),
            };
            if writeln!(out, "{answer}")
                .and_then(|()| out.flush())
                .is_err()
            {
                break;
            }
            continue;
        }
        if line.trim() != "report" {
            continue;
        }
        let mut names: Vec<String> = std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        names.sort();
        let cwd = std::env::current_dir()
            .map(|d| hex(&Sha256::digest(d.as_os_str().as_bytes())))
            .unwrap_or_default();
        let digests: serde_json::Map<String, serde_json::Value> = vars
            .iter()
            .map(|v| {
                let d = std::env::var_os(v)
                    .map(|x| serde_json::Value::from(hex(&Sha256::digest(x.as_bytes()))))
                    .unwrap_or(serde_json::Value::Null);
                (v.clone(), d)
            })
            .collect();
        let report = serde_json::json!({
            "pid": std::process::id(),
            "ppid": std::os::unix::process::parent_id(),
            "exe_sha256": exe_sha256(),
            "cdhash": cdhash(),
            "cwd_sha256": cwd,
            "env": names,
            "vars": digests,
        });
        if writeln!(out, "{report}")
            .and_then(|()| out.flush())
            .is_err()
        {
            break;
        }
    }
    std::thread::sleep(std::time::Duration::from_secs(linger));
}
