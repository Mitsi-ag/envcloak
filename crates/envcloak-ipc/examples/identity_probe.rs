//! Native M3 peer-check fixture. Sends a metadata request only after connect.
use envcloak_ipc::{Client, DaemonIdentity, RunPaths};

fn main() {
    let Some(dir) = std::env::args_os().nth(1) else {
        std::process::exit(2);
    };
    let Ok(paths) = RunPaths::under(dir) else {
        std::process::exit(2);
    };
    match Client::connect(&paths) {
        Ok(mut client) => {
            println!(
                "{}",
                match client.identity() {
                    DaemonIdentity::Verified => "verified",
                    DaemonIdentity::Unverified => "unverified",
                }
            );
            // A fake server records this frame and closes without answering.
            if client.status().is_err() {
                std::process::exit(124);
            }
        }
        Err(error) => {
            println!("{error:?}");
            std::process::exit(125);
        }
    }
}
