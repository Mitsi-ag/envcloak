//! `ec-model` (M2 plan task M2-04): the command it wraps runs in an
//! isolated home with a cleared environment, so no credential or
//! configuration of whoever runs it reaches the command (Codex review,
//! high); and its diagnostics name no request target a host controls
//! (Codex review, medium: a request to `/<value>` put the value on
//! standard error).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use envcloak_testkit::{
    Canary, TestHome, by_label, canaries, find, fresh_seed, labels, testkit_bin,
};

/// `ec-model` with `script` and `--record <record>`, running `command`
/// under `/bin/sh -c`, with `parent` as the variables of its own
/// environment (nothing else of this process's).
fn ec_model(record: &Path, parent: &[(&str, &str)], command: &str) -> Output {
    let script = record.with_extension("script.json");
    std::fs::write(&script, r#"{"steps": [{"say": "done"}]}"#).unwrap();
    let mut cmd = Command::new(testkit_bin("ec-model"));
    cmd.env_clear()
        .envs(parent.iter().copied())
        .arg("--script")
        .arg(&script)
        .arg("--record")
        .arg(record)
        .args(["--", "/bin/sh", "-c", command])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    envcloak_testkit::agents::finish_within(cmd, std::time::Duration::from_secs(120))
}

/// A command that prints `c` on a line of its own, named in two pieces,
/// so whole it can only be what the command printed.
fn print_split(c: &Canary) -> String {
    let (a, b) = c.as_str().split_at(c.as_str().len() / 2);
    format!("printf '%s%s\\n' '{a}' '{b}'")
}

/// The variables the command may see: the test home's, the two
/// `ec-model` adds for hosts, the model's, the diagnostic ones, and what a
/// shell sets itself.
const ALLOWED: [&str; 21] = [
    "PATH",
    "LANG",
    "TERM",
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "CODEX_HOME",
    "CLAUDE_CODE_TMPDIR",
    "EC_MODEL_BASE_URL",
    "EC_MODEL_TOKEN",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "__CF_USER_TEXT_ENCODING",
];

/// Credentials and configurations planted in the environment `ec-model`
/// runs with (variables, and a home whose host configs hold keys) never
/// reach the command: it sees a home of its own under `/tmp/ec`, only the
/// variables [`ALLOWED`] names, starts in that home, and reads none of
/// the planted files. A control the command prints is found in its
/// output, so the clean result is the detector's and not a blind one.
#[test]
fn the_command_runs_in_a_home_of_its_own_with_nothing_of_the_callers_environment() {
    let cs = canaries(fresh_seed());
    let key = |l: &str| by_label(&cs, l).as_str().to_owned();
    // The caller's home, with the hosts' credential and config files.
    let parent = TestHome::new();
    let home = parent.home();
    for (file, body) in [
        (
            ".codex/auth.json",
            format!(
                "{{\"OPENAI_API_KEY\": \"{}\"}}",
                key(labels::OPENAI_API_KEY)
            ),
        ),
        (
            ".claude/.credentials.json",
            format!(
                "{{\"claudeAiOauth\": {{\"accessToken\": \"{}\"}}}}",
                key(labels::STRIPE_SECRET_KEY)
            ),
        ),
        (
            ".config/gh/hosts.yml",
            format!(
                "github.com:\n  oauth_token: {}\n",
                key(labels::GITHUB_TOKEN)
            ),
        ),
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
    }
    let (home_s, codex, claude, config) = (
        home.to_str().unwrap().to_owned(),
        home.join(".codex").to_str().unwrap().to_owned(),
        home.join(".claude").to_str().unwrap().to_owned(),
        home.join(".config").to_str().unwrap().to_owned(),
    );
    let (openai, github, db) = (
        key(labels::OPENAI_API_KEY),
        key(labels::GITHUB_TOKEN),
        key(labels::DATABASE_URL),
    );
    let planted = [
        ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        ("HOME", home_s.as_str()),
        ("CODEX_HOME", codex.as_str()),
        ("CLAUDE_CONFIG_DIR", claude.as_str()),
        ("XDG_CONFIG_HOME", config.as_str()),
        ("ANTHROPIC_API_KEY", openai.as_str()),
        ("OPENAI_API_KEY", openai.as_str()),
        ("GITHUB_TOKEN", github.as_str()),
        ("DATABASE_URL", db.as_str()),
        ("ANTHROPIC_BASE_URL", "https://elsewhere.invalid"),
    ];
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let command = format!(
        "env; echo \"CWD=$(pwd -P)\"; for f in \"$HOME/.codex/auth.json\" \
         \"$HOME/.claude/.credentials.json\" \"$HOME/.config/gh/hosts.yml\" \
         \"$CODEX_HOME/auth.json\" \"${{CLAUDE_CONFIG_DIR:-$HOME/.claude}}/.credentials.json\"; \
         do cat \"$f\" 2>/dev/null; done; {}",
        print_split(&control)
    );
    let files = TestHome::new();
    let record = files.root().join("record.json");
    let out = ec_model(&record, &planted, &command);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The control: found, so the detector looks where it should.
    let all: Vec<Canary> = cs.iter().cloned().chain([control.clone()]).collect();
    let hits = find(&out.stdout, &all);
    assert!(
        hits.iter().any(|f| f.label == "POSITIVE_CONTROL"),
        "the control the command printed was not found"
    );
    let leaked: Vec<String> = hits
        .iter()
        .filter(|f| f.label != "POSITIVE_CONTROL")
        .map(|f| format!("{} as {}", f.label, f.encoding))
        .collect();
    assert!(
        leaked.is_empty(),
        "the caller's credentials reached the command: {leaked:?}"
    );
    assert!(
        find(&out.stderr, &all).is_empty(),
        "ec-model's diagnostics hold a value"
    );
    // Only the allowed variables, and a home of its own.
    let vars: Vec<(&str, &str)> = stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .collect();
    for (name, _) in &vars {
        assert!(
            ALLOWED.contains(name) || *name == "CWD",
            "the command got {name} from the caller"
        );
    }
    let var = |n: &str| {
        vars.iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| PathBuf::from(v))
            .unwrap_or_else(|| panic!("no {n} in {stdout}"))
    };
    let its_home = var("HOME");
    assert!(
        its_home.starts_with("/tmp") && its_home != home,
        "the command's HOME is {}",
        its_home.display()
    );
    assert!(
        its_home
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n.to_string_lossy().starts_with("ec")),
        "the command's HOME is not a test home: {}",
        its_home.display()
    );
    assert_eq!(var("CODEX_HOME"), its_home.join(".codex"));
    assert!(
        var("CLAUDE_CODE_TMPDIR").starts_with(its_home.parent().unwrap()),
        "CLAUDE_CODE_TMPDIR is outside the command's home"
    );
    let real = std::fs::canonicalize(home.parent().unwrap()).unwrap();
    let cwd = var("CWD");
    assert!(
        cwd.ends_with("home") && !cwd.starts_with(&real),
        "the command started in {}",
        cwd.display()
    );
    // Removed after the run, without --keep-home.
    assert!(
        std::fs::symlink_metadata(&its_home).is_err(),
        "the command's home was left behind"
    );
}

/// A request a host sends can put anything in its request line: a path,
/// a method, a tunnel's destination. `ec-model`'s diagnostics show an
/// endpoint the model serves and a destination the pinned hosts were
/// measured reaching for by name, and anything else only by its length,
/// so values placed in every part of a request line (here by `curl`),
/// a destination of letters only that reads as any host name included,
/// never reach its standard error. Its record, mode 0600, keeps them
/// whole: the positive control that the requests carried them.
#[test]
fn diagnostics_name_no_request_target_a_host_controls() {
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("curl is needed"));
    let hex = || format!("{:016x}{:016x}", fresh_seed(), fresh_seed());
    let path = Canary::new("PATH_VALUE", format!("ecpath{}", hex()));
    let host = Canary::new("HOST_VALUE", format!("echost{}", hex()));
    let letters = |n: usize| -> String {
        hex()
            .bytes()
            .chain(hex().bytes())
            .take(n)
            .map(|b| char::from(b'a' + (b % 26)))
            .collect()
    };
    // A method is 16 upper-case letters at most.
    let method = Canary::new(
        "METHOD_VALUE",
        format!("EC{}", letters(14).to_ascii_uppercase()),
    );
    // A secret that is a valid DNS label: letters only.
    let word = Canary::new("WORD_VALUE", format!("ec{}", letters(30)));
    let command = format!(
        "c={curl}; t=\"x-api-key: $EC_MODEL_TOKEN\"; \
         $c -s -o /dev/null --path-as-is -H \"$t\" \"$EC_MODEL_BASE_URL/{p}?{p}\"; \
         $c -s -o /dev/null -X {m} -H \"$t\" \"$EC_MODEL_BASE_URL/v1/messages\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://{h}.example/\"; \
         $c -s -o /dev/null -x \"$EC_MODEL_BASE_URL\" \"http://{h}.example/{p}\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://{w}.com/\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://api.anthropic.com/\"; true",
        p = path.as_str(),
        m = method.as_str(),
        h = host.as_str(),
        w = word.as_str(),
    );
    let files = TestHome::new();
    let record = files.root().join("record.json");
    let out = ec_model(&record, &[("PATH", "/usr/bin:/bin")], &command);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let cs = [path.clone(), host.clone(), method.clone(), word.clone()];
    // The requests carried every value: the record has each.
    let kept = std::fs::read(&record).unwrap();
    for c in &cs {
        assert!(
            find(&kept, &cs).iter().any(|f| f.label == c.label),
            "no request carried {}",
            c.label
        );
    }
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The diagnostics hold none, and still say what was asked.
    let hits: Vec<String> = find(&out.stderr, &cs)
        .iter()
        .map(|f| format!("{} as {}", f.label, f.encoding))
        .collect();
    assert!(hits.is_empty(), "ec-model printed {hits:?}");
    assert!(
        stderr.contains("GET <") && stderr.contains("<method of "),
        "{stderr}"
    );
    assert!(
        stderr.contains("api.anthropic.com:443"),
        "a listed destination is not named: {stderr}"
    );
    // Not clean: the paths are not served. The run says so.
    assert_eq!(out.status.code(), Some(3), "{stderr}");
}
