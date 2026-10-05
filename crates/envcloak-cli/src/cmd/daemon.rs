//! `envcloak daemon install [--daemon PATH] [--no-start]` and `envcloak
//! daemon uninstall` (SPEC §4.1, §12 "Builds without EnvCloak's
//! profile").
//!
//! `install` writes a per-user service definition that starts
//! `envcloakd --foreground` by absolute path, and loads it:
//! - macOS: a LaunchAgent, `~/Library/LaunchAgents/<label>.plist`, loaded
//!   with `launchctl bootstrap gui/<uid>` (or `user/<uid>` without a GUI
//!   session);
//! - Linux: a systemd user unit, `<label>.service` in the directory the
//!   user manager reads (`~/.config/systemd/user` for the manager's own
//!   `HOME` or `XDG_CONFIG_HOME`), enabled and started with
//!   `systemctl --user`.
//!
//! The daemon is the `envcloakd` next to this `envcloak`, or the absolute
//! path given with `--daemon`; never one found on `PATH`. The definition
//! pins `HOME` and, on Linux, the `XDG_*` base directories this shell has,
//! so the daemon uses the same vault and socket as the CLI. launchctl and
//! systemctl are run by absolute path. The templates are the files in
//! `packaging/`, compiled in; a test checks they match.
//!
//! `--no-start` writes the definition and says how to load it. The hidden
//! `--label` names the service differently (tests run their own).

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};
use std::time::{Duration, Instant};

use envcloak_client::connect::run_paths;
use envcloak_client::fail::{FAILURE, Failure, usage};
use envcloak_ipc::Client;

const USAGE: &str = "envcloak daemon install [--daemon /absolute/path/to/envcloakd] [--no-start]\n       envcloak daemon uninstall";

/// The service's name: the launchd label, and the systemd unit's stem.
pub const LABEL: &str = "ai.envcloak.envcloakd";

/// `packaging/launchd/ai.envcloak.envcloakd.plist`.
pub const LAUNCHD_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>@LABEL@</string>
  <key>ProgramArguments</key>
  <array>
    <string>@ENVCLOAKD@</string>
    <string>--foreground</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
@ENVIRONMENT@  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>SoftResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>HardResourceLimits</key>
  <dict>
    <key>Core</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>@LOG@</string>
  <key>StandardErrorPath</key>
  <string>@LOG@</string>
</dict>
</plist>
"#;

/// `packaging/systemd/envcloakd.service`. `KillMode=process` (M2 task
/// M2-27): stopping or restarting the daemon stops the daemon only, so the
/// runners and relays it started for managed servers, each leading a
/// session of its own, keep serving their clients; `install` writes the
/// whole unit, so it rewrites an older one.
pub const SYSTEMD_TEMPLATE: &str = "[Unit]
Description=EnvCloak vault daemon
Documentation=https://github.com/Mitsi-ag/envcloak

[Service]
Type=simple
ExecStart=@ENVCLOAKD@ --foreground
@ENVIRONMENT@Restart=on-failure
RestartSec=2
KillMode=process
UMask=0077
LimitCORE=0
NoNewPrivileges=true

[Install]
WantedBy=default.target
";

/// How long `install` waits for the daemon to answer.
const START_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq)]
struct InstallArgs {
    daemon: Option<String>,
    start: bool,
    label: String,
}

pub fn run(args: &[&str]) -> ExitCode {
    let result = match args {
        ["install", rest @ ..] => match parse_install(rest) {
            Some(a) => install(&a),
            None => return usage(USAGE),
        },
        ["uninstall"] => uninstall(LABEL),
        ["uninstall", "--label", label] if valid_label(label) => uninstall(label),
        _ => return usage(USAGE),
    };
    result.unwrap_or_else(|f| f.report(FAILURE))
}

fn parse_install(args: &[&str]) -> Option<InstallArgs> {
    let mut a = InstallArgs {
        daemon: None,
        start: true,
        label: LABEL.to_owned(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--daemon" if a.daemon.is_none() => a.daemon = Some((*it.next()?).to_owned()),
            "--no-start" if a.start => a.start = false,
            "--label" => {
                let l = it.next()?;
                if !valid_label(l) {
                    return None;
                }
                (*l).clone_into(&mut a.label);
            }
            _ => return None,
        }
    }
    Some(a)
}

/// A label under `ai.envcloak.`, in lowercase letters, digits, `.` and `-`.
fn valid_label(l: &str) -> bool {
    l.strip_prefix("ai.envcloak.").is_some_and(|rest| {
        !rest.is_empty()
            && l.len() <= 64
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    })
}

fn failure(token: &'static str, message: impl Into<std::borrow::Cow<'static, str>>) -> Failure {
    Failure::new(token, message)
}

/// The `envcloakd` to install: `--daemon`'s absolute path, or the one next
/// to this executable. Never one on `PATH`.
fn daemon_path(explicit: Option<&str>) -> Result<PathBuf, Failure> {
    let path = match explicit {
        Some(p) => {
            let p = PathBuf::from(p);
            if !p.is_absolute() {
                return Err(failure(
                    "daemon_path",
                    "--daemon needs the absolute path to envcloakd",
                ));
            }
            p
        }
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|d| d.join("envcloakd")))
            .ok_or_else(|| failure("daemon_path", "cannot tell where envcloak is installed"))?,
    };
    let m = std::fs::metadata(&path).map_err(|_| {
        failure(
            "daemon_not_found",
            "there is no envcloakd next to envcloak; name it with --daemon <absolute path>",
        )
    })?;
    if !m.is_file() || m.permissions().mode() & 0o111 == 0 {
        return Err(failure(
            "daemon_not_found",
            "the envcloakd path is not an executable file",
        ));
    }
    Ok(path)
}

/// A path as text a service definition can hold: UTF-8 without control
/// characters.
fn text(p: &Path) -> Result<&str, Failure> {
    p.to_str()
        .filter(|s| !s.chars().any(char::is_control))
        .ok_or_else(|| {
            failure(
                "path_unsupported",
                "a path holds a control character or is not UTF-8, so it cannot go in a service \
                 definition",
            )
        })
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The variables pinned in the service definition.
fn environment() -> Result<Vec<(&'static str, PathBuf)>, Failure> {
    let home = absolute_env("HOME")
        .ok_or_else(|| failure("no_home", "HOME is not set to an absolute path"))?;
    let mut env = vec![("HOME", home)];
    if !cfg!(target_os = "macos") {
        for name in [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
        ] {
            if let Some(v) = absolute_env(name) {
                env.push((name, v));
            }
        }
    }
    Ok(env)
}

fn home() -> Result<PathBuf, Failure> {
    absolute_env("HOME").ok_or_else(|| failure("no_home", "HOME is not set to an absolute path"))
}

/// Fills `@NAME@` placeholders in one pass: a value is never scanned for
/// placeholders itself.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find('@') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let hit = after.find('@').and_then(|end| {
            let name = &after[..end];
            values
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v, end))
        });
        match hit {
            Some((value, end)) => {
                out.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                out.push('@');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A systemd double-quoted string: backslashes and quotes escaped, `%`
/// doubled (specifiers), and `$` doubled when `dollar` (variable
/// expansion in `ExecStart=`).
fn systemd_quoted(s: &str, dollar: bool) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' if dollar => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The launchd plist.
fn render_launchd(label: &str, daemon: &str, env: &[(&str, &str)], log: &str) -> String {
    let environment: String = env
        .iter()
        .map(|(k, v)| format!("    <key>{k}</key>\n    <string>{}</string>\n", xml(v)))
        .collect();
    fill(
        LAUNCHD_TEMPLATE,
        &[
            ("LABEL", label),
            ("ENVCLOAKD", &xml(daemon)),
            ("ENVIRONMENT", &environment),
            ("LOG", &xml(log)),
        ],
    )
}

/// The systemd unit.
fn render_systemd(daemon: &str, env: &[(&str, &str)]) -> String {
    let environment: String = env
        .iter()
        .map(|(k, v)| {
            format!(
                "Environment={}\n",
                systemd_quoted(&format!("{k}={v}"), false)
            )
        })
        .collect();
    fill(
        SYSTEMD_TEMPLATE,
        &[
            ("ENVCLOAKD", &systemd_quoted(daemon, true)),
            ("ENVIRONMENT", &environment),
        ],
    )
}

/// Writes `contents` to `path` through a temporary file and a rename, mode
/// 0644 (service managers refuse definitions others can write).
fn write_atomically(path: &Path, contents: &str) -> Result<(), Failure> {
    let err = |_| {
        failure(
            "write_failed",
            "the service definition could not be written",
        )
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(err)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| {
            f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(err)
}

fn run_tool(program: &str, args: &[&OsStr]) -> Result<Output, Failure> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|_| failure("service_manager", "the service manager could not be run"))
}

fn succeeded(o: &Output) -> bool {
    o.status.success()
}

/// Waits for the installed daemon to answer, and returns its pid.
fn wait_for_daemon() -> Result<u32, Failure> {
    let paths = run_paths()?;
    let end = Instant::now() + START_TIMEOUT;
    loop {
        match Client::connect(&paths).and_then(|mut c| c.status()) {
            Ok(s) => return Ok(s.daemon.pid),
            Err(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => {
                let f = Failure::from(e);
                return Err(failure(
                    "daemon_not_started",
                    format!(
                        "the service was loaded, but the daemon did not answer: {}",
                        f.message()
                    ),
                ));
            }
        }
    }
}

fn install(a: &InstallArgs) -> Result<ExitCode, Failure> {
    let daemon = daemon_path(a.daemon.as_deref())?;
    let daemon_text = text(&daemon)?.to_owned();
    let env = environment()?;
    let mut env_text = Vec::new();
    for (k, v) in &env {
        env_text.push((*k, text(v)?.to_owned()));
    }
    let env_refs: Vec<(&str, &str)> = env_text.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // The socket path must fit before anything is installed.
    run_paths()?;
    let home = home()?;
    if cfg!(target_os = "macos") {
        let plist = home
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", a.label));
        let logs = home.join("Library/Logs/EnvCloak");
        std::fs::create_dir_all(&logs)
            .and_then(|()| std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)))
            .map_err(|_| failure("write_failed", "the log directory could not be created"))?;
        let log = logs.join("envcloakd.log");
        let rendered = render_launchd(&a.label, &daemon_text, &env_refs, text(&log)?);
        write_atomically(&plist, &rendered)?;
        println!("Wrote {}", plist.display());
        if !a.start {
            println!(
                "Load it with: launchctl bootstrap gui/{} {}",
                envcloak_sys::effective_uid(),
                plist.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
        launchd_load(&a.label, &plist)?;
        let pid = wait_for_daemon()?;
        println!("envcloakd is running under launchd (pid {pid}).");
    } else {
        let name = format!("{}.service", a.label);
        let rendered = render_systemd(&daemon_text, &env_refs);
        if !a.start {
            let unit = absolute_env("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("systemd/user")
                .join(&name);
            write_atomically(&unit, &rendered)?;
            println!("Wrote {}", unit.display());
            println!("Start it with: systemctl --user enable --now {name}");
            return Ok(ExitCode::SUCCESS);
        }
        let manager = Manager::find()?;
        let unit = manager.unit_dir().join(&name);
        write_atomically(&unit, &rendered)?;
        println!("Wrote {}", unit.display());
        manager.load(&name)?;
        let pid = wait_for_daemon()?;
        println!("envcloakd is running under systemd (pid {pid}).");
    }
    Ok(ExitCode::SUCCESS)
}

const LAUNCHCTL: &str = "/bin/launchctl";

fn launchd_load(label: &str, plist: &Path) -> Result<(), Failure> {
    let uid = envcloak_sys::effective_uid();
    // A GUI login session first; `user/<uid>` over SSH, where there is none.
    for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
        let target = format!("{domain}/{label}");
        let _ = run_tool(LAUNCHCTL, &["bootout".as_ref(), target.as_ref()]);
        // bootout finishes asynchronously; a bootstrap right after it can
        // fail until it has.
        for _ in 0..20 {
            let out = run_tool(
                LAUNCHCTL,
                &["bootstrap".as_ref(), domain.as_ref(), plist.as_os_str()],
            )?;
            if succeeded(&out) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Err(failure(
        "service_manager",
        "launchctl could not load the LaunchAgent",
    ))
}

fn systemctl() -> Result<&'static str, Failure> {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or_else(|| failure("service_manager", "systemctl was not found"))
}

/// The systemd user manager. It looks for units under its own
/// `XDG_CONFIG_HOME` (or `HOME/.config`), which can differ from this
/// shell's; `systemctl --user` edits unit files where its own environment
/// says. So the unit goes where the manager looks, and systemctl runs with
/// the manager's `HOME` and `XDG_CONFIG_HOME`.
#[derive(Debug)]
struct Manager {
    systemctl: &'static str,
    home: PathBuf,
    config: Option<PathBuf>,
}

impl Manager {
    fn unreachable() -> Failure {
        failure(
            "service_manager",
            "systemctl --user could not reach your user service manager",
        )
    }

    /// Asks the manager for its environment.
    fn find() -> Result<Manager, Failure> {
        let systemctl = systemctl()?;
        let out = run_tool(systemctl, &["--user".as_ref(), "show-environment".as_ref()])?;
        if !succeeded(&out) {
            return Err(Self::unreachable());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        // `KEY=value`; a value systemd had to quote (`$'...'`) is not used.
        let var = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
                .filter(|v| !v.starts_with("$'"))
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let home = var("HOME").ok_or_else(Self::unreachable)?;
        Ok(Manager {
            systemctl,
            home,
            config: var("XDG_CONFIG_HOME"),
        })
    }

    fn unit_dir(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
            .join("systemd/user")
    }

    /// `systemctl --user <args>`, seeing the unit files the manager sees.
    fn run(&self, args: &[&str]) -> Result<Output, Failure> {
        let mut cmd = Command::new(self.systemctl);
        cmd.arg("--user").args(args).env("HOME", &self.home);
        match &self.config {
            Some(c) => cmd.env("XDG_CONFIG_HOME", c),
            None => cmd.env_remove("XDG_CONFIG_HOME"),
        };
        cmd.output()
            .map_err(|_| failure("service_manager", "the service manager could not be run"))
    }

    /// Reloads, enables and (re)starts the unit `name`.
    fn load(&self, name: &str) -> Result<(), Failure> {
        let fail = |what: &'static str| failure("service_manager", what);
        if !succeeded(&self.run(&["daemon-reload"])?) {
            return Err(Self::unreachable());
        }
        if !succeeded(&self.run(&["enable", name])?) {
            return Err(fail("systemctl --user could not enable the unit"));
        }
        if !succeeded(&self.run(&["restart", name])?) {
            return Err(fail("systemctl --user could not start the unit"));
        }
        Ok(())
    }
}

fn uninstall(label: &str) -> Result<ExitCode, Failure> {
    let home = home()?;
    if cfg!(target_os = "macos") {
        let uid = envcloak_sys::effective_uid();
        for domain in ["gui", "user"] {
            let target = format!("{domain}/{uid}/{label}");
            let _ = run_tool(LAUNCHCTL, &["bootout".as_ref(), target.as_ref()]);
        }
        let plist = home
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        remove(&plist)?;
    } else {
        let name = format!("{label}.service");
        match Manager::find() {
            Ok(m) => {
                let _ = m.run(&["disable", "--now", &name]);
                remove(&m.unit_dir().join(&name))?;
                let _ = m.run(&["daemon-reload"]);
            }
            // No manager to stop it: remove what `--no-start` wrote.
            Err(_) => remove(
                &absolute_env("XDG_CONFIG_HOME")
                    .unwrap_or_else(|| home.join(".config"))
                    .join("systemd/user")
                    .join(&name),
            )?,
        }
    }
    println!("Uninstalled the envcloakd service. The vault is unchanged.");
    Ok(ExitCode::SUCCESS)
}

fn remove(p: &Path) -> Result<(), Failure> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(failure(
            "write_failed",
            "the service definition could not be removed",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_filled_in_one_pass() {
        let out = fill("a @X@ b @Y@ c @Z@ d@", &[("X", "@Y@"), ("Y", "y")]);
        assert_eq!(out, "a @Y@ b y c @Z@ d@");
    }

    #[test]
    fn values_are_escaped_for_each_format() {
        assert_eq!(xml("a&b<c>\"'"), "a&amp;b&lt;c&gt;&quot;&apos;");
        assert_eq!(
            systemd_quoted("/p a/t\"h\\%$", true),
            "\"/p a/t\\\"h\\\\%%$$\""
        );
        assert_eq!(systemd_quoted("K=100%$", false), "\"K=100%%$\"");
        let plist = render_launchd(
            LABEL,
            "/Apps & Tools/envcloakd",
            &[("HOME", "/Users/<x>")],
            "/l",
        );
        assert!(plist.contains("<string>/Apps &amp; Tools/envcloakd</string>"));
        assert!(plist.contains("<key>HOME</key>\n    <string>/Users/&lt;x&gt;</string>\n"));
        let unit = render_systemd("/opt/env cloak/envcloakd", &[("HOME", "/home/u")]);
        assert!(unit.contains("ExecStart=\"/opt/env cloak/envcloakd\" --foreground\n"));
        assert!(unit.contains("Environment=\"HOME=/home/u\"\nRestart=on-failure"));
    }

    #[test]
    fn labels_are_restricted() {
        assert!(valid_label(LABEL));
        assert!(valid_label("ai.envcloak.test-1"));
        for bad in [
            "",
            "ai.envcloak.",
            "com.example.x",
            "ai.envcloak.X",
            "ai.envcloak.a/b",
        ] {
            assert!(!valid_label(bad), "{bad}");
        }
    }

    #[test]
    fn install_options_parse() {
        assert_eq!(
            parse_install(&["--daemon", "/x/envcloakd", "--no-start"]),
            Some(InstallArgs {
                daemon: Some("/x/envcloakd".into()),
                start: false,
                label: LABEL.into(),
            })
        );
        assert!(parse_install(&["--daemon"]).is_none());
        assert!(parse_install(&["--label", "evil"]).is_none());
        assert!(parse_install(&["--no-start", "--no-start"]).is_none());
    }
}
