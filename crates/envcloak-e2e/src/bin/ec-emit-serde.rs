//! Gate 8's serde_json serializer for the fixture story (the emitters'
//! emit.py runs it): for each variable name given, the value in this
//! process's environment as `serde_json::to_string` writes a string, then
//! NUL, then the SHA-256 of the value in hex, then NUL. Nothing else is
//! written, and no error holds a value.

use std::fmt::Write as _;
use std::io::Write;
use std::process::ExitCode;

use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mut out = std::io::stdout().lock();
    for name in std::env::args_os().skip(1) {
        let Some(value) = std::env::var_os(&name).and_then(|v| v.into_string().ok()) else {
            eprintln!("ec-emit-serde: a variable is not set, or not UTF-8");
            return ExitCode::FAILURE;
        };
        let Ok(json) = serde_json::to_string(&value) else {
            return ExitCode::FAILURE;
        };
        let digest = Sha256::digest(value.as_bytes())
            .iter()
            .fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
        let written = out
            .write_all(json.as_bytes())
            .and_then(|()| out.write_all(b"\0"))
            .and_then(|()| out.write_all(digest.as_bytes()))
            .and_then(|()| out.write_all(b"\0"));
        if written.is_err() {
            return ExitCode::FAILURE;
        }
    }
    if out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
