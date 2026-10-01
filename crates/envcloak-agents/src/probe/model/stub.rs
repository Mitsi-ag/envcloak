//! The client side of `envcloak-probe-model`: starts the program, hands it
//! the script, and reads its reports (see the module documentation of
//! [`super`] for the lines exchanged).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{Report, Token};

/// The longest line the client reads from the program: a report of 16
/// MiB of bodies, base64, with room for the rest.
const MAX_LINE: u64 = 64 * 1024 * 1024;

/// A running `envcloak-probe-model`, its own child. Dropping it ends the
/// run (its input closes) and waits for the program, killing it after a
/// few seconds if it has not exited; a child is only ever signalled while
/// unreaped.
#[derive(Debug)]
pub struct ModelStub {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    addr: SocketAddr,
    token: Token,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    addr: SocketAddr,
    token: String,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("envcloak-probe-model: {what}"),
    )
}

impl ModelStub {
    /// Starts `exe` (an `envcloak-probe-model`) with a cleared environment
    /// and `script` (JSON, see [`super::Script`]), and waits for it to
    /// listen.
    ///
    /// # Errors
    /// When the program cannot start, refuses the script or does not say
    /// where it listens.
    pub fn start(exe: &Path, script: &[u8], time_limit: Duration) -> io::Result<ModelStub> {
        // One line: the script re-serialized without its newlines.
        let value: serde_json::Value =
            serde_json::from_slice(script).map_err(|_| invalid("the script is not JSON"))?;
        let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *line, &value).map_err(io::Error::other)?;
        line.push(b'\n');
        drop(value);
        let mut child = Command::new(exe)
            .arg("--time-limit")
            .arg(time_limit.as_secs().max(1).to_string())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("no pipes"));
        };
        let mut stdout = BufReader::new(stdout);
        let started = stdin.write_all(&line).and_then(|()| stdin.flush());
        let ready = started.and_then(|()| read_line(&mut stdout));
        let ready = match ready.and_then(|l| {
            serde_json::from_slice::<Ready>(&l).map_err(|_| invalid("no address line"))
        }) {
            Ok(r) => r,
            Err(e) => {
                drop(stdin);
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        Ok(ModelStub {
            child,
            stdin: Some(stdin),
            stdout,
            addr: ready.addr,
            token: Token::from_text(Zeroizing::new(ready.token)),
        })
    }

    /// Where it listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The run's token, which a host must present as its API key.
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// `http://127.0.0.1:<port>`, the base URL for Anthropic Messages
    /// clients (they add `/v1/messages`).
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request recorded so far.
    ///
    /// # Errors
    /// When the program has gone or answers with something else.
    pub fn requests(&mut self) -> io::Result<Report> {
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(invalid("the run has ended"));
        };
        stdin.write_all(b"requests\n")?;
        stdin.flush()?;
        let line = read_line(&mut self.stdout)?;
        serde_json::from_slice(&line).map_err(|_| invalid("an unreadable report"))
    }

    /// Releases the barrier `name` (see [`super::Step::after`]).
    ///
    /// # Errors
    /// When the name is not a barrier's, or the program has gone.
    pub fn release(&mut self, name: &str) -> io::Result<()> {
        if !super::script::barrier_name(name) {
            return Err(invalid("not a barrier name"));
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(invalid("the run has ended"));
        };
        stdin.write_all(format!("release {name}\n").as_bytes())?;
        stdin.flush()
    }

    /// Ends the run and returns its last report.
    ///
    /// # Errors
    /// When the program has gone or answers with something else.
    pub fn finish(mut self) -> io::Result<Report> {
        if let Some(mut stdin) = self.stdin.take() {
            let _ = stdin.write_all(b"stop\n").and_then(|()| stdin.flush());
        }
        loop {
            let line = read_line(&mut self.stdout)?;
            let report: Report =
                serde_json::from_slice(&line).map_err(|_| invalid("an unreadable report"))?;
            if report.last {
                return Ok(report);
            }
        }
    }
}

impl Drop for ModelStub {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One line, without its newline, in a wiping buffer.
fn read_line(r: &mut BufReader<ChildStdout>) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    let n = r.by_ref().take(MAX_LINE).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Err(invalid("the program ended"));
    }
    if line.last() != Some(&b'\n') {
        return Err(invalid("a line too long or cut short"));
    }
    line.pop();
    Ok(line)
}
