//! The network the agent hosts run with, checked (review of M2-04:
//! on macOS nothing kept a host from connecting anywhere directly, past
//! the proxy the scripted model records). CI's agent jobs run the hosts
//! with loopback only: on Linux in a network namespace with nothing but
//! `lo` (`unshare --net`), on macOS with a group of their own whose every
//! TCP and UDP packet to anywhere but `lo0` a `pf` rule refuses. Each job
//! says which it set up in [`NETWORK_VAR`], and first, outside it, that
//! the network is open, so a refusal inside is the isolation's and not a
//! network that is down.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `loopback-only` or `open`: what CI set up for the tests' network.
/// Unset (a developer's machine), the check is skipped with a line on
/// standard error.
pub const NETWORK_VAR: &str = "ENVCLOAK_TEST_NETWORK";

/// An address outside the machine that answers on any open network
/// (Cloudflare's resolver, on HTTPS).
const OUTSIDE: &str = "1.1.1.1:443";

/// What a program started from the tests gets for each address it is
/// given: `OPEN` or `NO <errno name>`, one line each.
const PROBE: &str = "import errno, socket, sys
for a in sys.argv[1:]:
    host, port = a.rsplit(':', 1)
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((host, int(port)))
        print('OPEN')
    except socket.timeout:
        print('NO timeout')
    except OSError as e:
        print('NO', errno.errorcode.get(e.errno, e.errno))
    finally:
        s.close()
";

/// Whether this process can connect to `addr`: `Ok(())`, or the kind of
/// error it got.
fn connects(addr: SocketAddr) -> Result<(), ErrorKind> {
    TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map(drop)
        .map_err(|e| e.kind())
}

/// Checks that the tests' network is what [`NETWORK_VAR`] says, from this
/// process and from a program it starts (as a host is): with
/// `loopback-only`, a direct connection outside the machine fails and one
/// to a loopback listener succeeds; with `open`, the connection outside
/// succeeds too.
///
/// # Panics
/// When it is not, or the variable names neither.
pub fn check_network() {
    let Some(want) = std::env::var_os(NETWORK_VAR) else {
        eprintln!("the network check is skipped: {NETWORK_VAR} is not set (CI sets it)");
        return;
    };
    let outside: SocketAddr = OUTSIDE.parse().unwrap_or_else(|e| panic!("{e}"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let local = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let direct = connects(outside);
    let out = Command::new(crate::python3())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-c", PROBE, OUTSIDE, &local.to_string()])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("start python3: {e}"));
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = said.lines().collect();
    let (child_outside, child_local) = match lines.as_slice() {
        [a, b] => (*a, *b),
        _ => panic!(
            "the probe printed {said:?} ({})",
            String::from_utf8_lossy(&out.stderr)
        ),
    };
    assert_eq!(
        connects(local),
        Ok(()),
        "this process cannot reach loopback"
    );
    assert_eq!(
        child_local, "OPEN",
        "a program it starts cannot reach loopback"
    );
    match want.to_str() {
        Some("loopback-only") => {
            assert!(
                direct.is_err(),
                "this process connected to {OUTSIDE} with loopback only"
            );
            assert!(
                child_outside.starts_with("NO "),
                "a program it starts connected to {OUTSIDE} with loopback only: {child_outside}"
            );
            println!(
                "measurement: direct connection to {OUTSIDE} with loopback only: this process \
                 {direct:?}, a program it starts {child_outside}"
            );
        }
        Some("open") => {
            assert_eq!(direct, Ok(()), "this process cannot reach {OUTSIDE}");
            assert_eq!(
                child_outside, "OPEN",
                "a program it starts cannot reach {OUTSIDE}"
            );
        }
        _ => panic!("{NETWORK_VAR} is neither loopback-only nor open"),
    }
}
