//! The network the agent hosts run with, checked (review of M2-04:
//! on macOS nothing kept a host from connecting anywhere directly, past
//! the proxy the scripted model records). CI's agent jobs run the hosts
//! with loopback only: on Linux in a network namespace with nothing but
//! `lo` (`unshare --net`), on macOS with a group of their own whose every
//! TCP and UDP packet to anywhere but `lo0` a `pf` rule refuses, and to
//! which an access control entry denies the system resolver's socket
//! (`/var/run/mDNSResponder`), so a lookup through `getaddrinfo` fails
//! and no query leaves for it (Codex review, medium: lookups went through
//! the resolver, outside the group, and a value in a name could reach
//! external DNS unrecorded). Each job says which it set up in
//! [`NETWORK_VAR`], and first, outside it, that the network is open, so a
//! refusal inside is the isolation's and not a network that is down.
//!
//! What that does not refuse (verifier review of M2-04): on macOS the
//! resolver also answers over its XPC service (`com.apple.dnssd.service`),
//! which Network.framework, URLSession, CFNetwork's streams and host
//! lookups and `dnssd_getaddrinfo` use, and which no file access control
//! can deny; on Linux, systemd-resolved's varlink and D-Bus endpoints are
//! filesystem sockets a network namespace does not cut off (not
//! measured). So a program that resolves through those could still send a
//! name, and a value in it, to external DNS unrecorded.
//! [`open_resolver_imports`] guards the pinned hosts on macOS, by their
//! static imports only: a host's test fails if any executable or library
//! of its pinned tree imports one of [`OPEN_RESOLVERS`]. None does today:
//! Claude Code's native binary imports `getaddrinfo` and dns_sd's
//! `DNSServiceGetAddrInfo`, which `dns_sd.h` documents as working over a
//! Unix domain socket to the resolver (`DNSServiceRefSockFD`), the socket
//! the access control entry denies; Codex
//! imports `getaddrinfo` and CFNetwork's proxy auto-configuration calls,
//! which fetch a PAC URL only when the system names one, and none is set
//! on the runners. What imports cannot show is not covered (verifier
//! review of M2-RES1): a framework a program loads at run time
//! (`dlopen`, as Bun's and Node's foreign function interfaces can), and
//! Foundation calls that load a URL without naming URLSession.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `loopback-only` or `open`: what CI set up for the tests' network.
/// Unset (a developer's machine), the check is skipped with a line on
/// standard error.
pub const NETWORK_VAR: &str = "ENVCLOAK_TEST_NETWORK";

/// An address outside the machine that answers on any open network
/// (Cloudflare's resolver, on HTTPS).
const OUTSIDE: &str = "1.1.1.1:443";

/// A name any open network resolves (the CI service's own), looked up
/// as a host looks one up (`getaddrinfo`).
const NAME: &str = "github.com";

/// What a program started from the tests gets for each argument: for
/// `connect:<host>:<port>`, `OPEN` or `NO <errno name>`; for
/// `lookup:<name>`, `RESOLVED` or `NO <error>`; one line each.
const PROBE: &str = "import errno, socket, sys
for a in sys.argv[1:]:
    kind, target = a.split(':', 1)
    if kind == 'lookup':
        try:
            socket.getaddrinfo(target, 443, proto=socket.IPPROTO_TCP)
            print('RESOLVED')
        except OSError as e:
            print('NO', type(e).__name__, e.errno)
        continue
    host, port = target.rsplit(':', 1)
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

/// Whether this process can look `name` up (`getaddrinfo`): `Ok(())`
/// when it gets an address, or why not.
fn resolves(name: &str) -> Result<(), String> {
    match (name, 443).to_socket_addrs().map(|mut a| a.next()) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err("no address".to_owned()),
        Err(e) => Err(format!("{:?}", e.kind())),
    }
}

/// The macOS resolver entry points the tests' isolation does not refuse
/// (see the module documentation), as a program imports them: imported
/// symbols starting so. Network.framework's connections and resolver
/// configuration; libdnssd's XPC lookup; CFNetwork's host lookup, its
/// socket streams to a named host and its HTTP streams; and URLSession and
/// NSURLConnection, whose Objective-C classes a program imports by their
/// class symbols (verifier review of M2-RES1).
pub const OPEN_RESOLVERS: [&str; 10] = [
    "_nw_connection_",
    "_nw_resolver",
    "_dnssd_getaddrinfo",
    "_CFHostStartInfoResolution",
    "_CFStreamCreatePairWithSocketToHost",
    "_CFStreamCreatePairWithSocketToCFHost",
    "_CFReadStreamCreateForHTTPRequest",
    "_CFReadStreamCreateForStreamedHTTPRequest",
    "_OBJC_CLASS_$_NSURLSession",
    "_OBJC_CLASS_$_NSURLConnection",
];

/// Every import of [`OPEN_RESOLVERS`] by a Mach-O file at or under `path`
/// (not following symlinks), as (file, symbol), as `nm -u` lists the
/// file's imports. Files that are not Mach-O are skipped. Only static
/// imports are seen: a framework loaded at run time is not.
///
/// # Errors
/// When a directory cannot be read, or `nm` fails on a Mach-O file: a
/// file whose imports cannot be read is never taken as clean.
pub fn open_resolver_imports(path: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    use std::io::Read as _;
    let mut found = Vec::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let meta = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(&p).map_err(|e| format!("{}: {e}", p.display()))? {
                stack.push(entry.map_err(|e| format!("{}: {e}", p.display()))?.path());
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let mut magic = [0u8; 4];
        let is_macho = std::fs::File::open(&p)
            .and_then(|mut f| f.read_exact(&mut magic))
            .is_ok()
            && matches!(
                magic,
                [0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf] | [0xca, 0xfe, 0xba, 0xbe]
            );
        if !is_macho {
            continue;
        }
        let out = Command::new("/usr/bin/nm")
            .arg("-u")
            .arg(&p)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("nm {}: {e}", p.display()))?;
        if !out.status.success() {
            return Err(format!("nm could not read the imports of {}", p.display()));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut syms: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| OPEN_RESOLVERS.iter().any(|r| l.starts_with(r)))
            .collect();
        syms.sort_unstable();
        syms.dedup();
        found.extend(
            syms.into_iter()
                .map(|sym| (p.display().to_string(), sym.to_owned())),
        );
    }
    Ok(found)
}

/// Checks that the tests' network is what [`NETWORK_VAR`] says, from this
/// process and from a program it starts (as a host is): with
/// `loopback-only`, a name lookup fails, a direct connection outside the
/// machine fails, and one to a loopback listener succeeds; with `open`,
/// the lookup and the connection outside succeed too (the positive
/// control that the checks inside can see a network).
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
    let lookup = resolves(NAME);
    let direct = connects(outside);
    let out = Command::new(crate::python3())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "-c",
            PROBE,
            &format!("lookup:{NAME}"),
            &format!("connect:{OUTSIDE}"),
            &format!("connect:{local}"),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("start python3: {e}"));
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = said.lines().collect();
    let (child_lookup, child_outside, child_local) = match lines.as_slice() {
        [a, b, c] => (*a, *b, *c),
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
                lookup.is_err(),
                "this process looked {NAME} up with loopback only"
            );
            assert!(
                child_lookup.starts_with("NO "),
                "a program it starts looked {NAME} up with loopback only: {child_lookup}"
            );
            assert!(
                direct.is_err(),
                "this process connected to {OUTSIDE} with loopback only"
            );
            assert!(
                child_outside.starts_with("NO "),
                "a program it starts connected to {OUTSIDE} with loopback only: {child_outside}"
            );
            println!(
                "measurement: with loopback only, a lookup of {NAME}: this process {lookup:?}, a \
                 program it starts {child_lookup}; a direct connection to {OUTSIDE}: this \
                 process {direct:?}, a program it starts {child_outside}"
            );
        }
        Some("open") => {
            assert_eq!(lookup, Ok(()), "this process cannot look {NAME} up");
            assert_eq!(
                child_lookup, "RESOLVED",
                "a program it starts cannot look {NAME} up"
            );
            assert_eq!(direct, Ok(()), "this process cannot reach {OUTSIDE}");
            assert_eq!(
                child_outside, "OPEN",
                "a program it starts cannot reach {OUTSIDE}"
            );
        }
        _ => panic!("{NETWORK_VAR} is neither loopback-only nor open"),
    }
}
