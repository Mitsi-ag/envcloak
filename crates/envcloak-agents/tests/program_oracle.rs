//! The hook's reading of readers' programs against the tools themselves
//! (M2 plan M2-08, lesson L-02; Codex review, round 6: sed's and awk's
//! inline programs were taken as patterns, so a literal env-file read in
//! a sed `r` command or an awk `getline < FILE`, and awk's `ENVIRON`, were
//! let through).
//!
//! Random programs are run by every sed, awk, jq and yq installed here
//! (macOS's sed and awk, GNU sed, gawk and mawk on Linux), as an argv with
//! no shell, in a fixture directory whose env files hold a canary made at
//! run time, with a canary in the environment too. A program reaches the
//! secret when a canary is in what the tool printed. Every argv that
//! reaches it with any tool must not be let through, neither by
//! `check_argv` (the MCP server's `run_with_secrets` check) nor by
//! `check_script` given the same argv quoted for a shell (the hook's
//! check): a denial or a question, never `None`. Programs that reach
//! nothing are not judged.
//!
//! The families: sed scripts with an `r` or `R` among other commands (in
//! braces, after addresses, as one `-e` per line or one argument, under
//! `-n` and `-E`), and sed's `e` where GNU sed runs it; awk programs with
//! `getline < FILE`, a pipe, `system`, `ARGV` and the whole `ENVIRON`,
//! given as an argument, with `-f` and with gawk's `-e`; jq's `env`,
//! `$ENV` and raw input under `--seq`, and yq's `load`; grep given its
//! patterns with `-f`.
//!
//! Positive controls: `sed '1r .env' a.txt`, the awk `getline` read and
//! `jq -n env` reach the canary wherever the tool is here; `sed -n p
//! a.txt` and `awk 1 a.txt` reach nothing and are allowed. Each family must
//! reach the canary at least 5 times. `ENVCLOAK_TEST_REQUIRE_TOOLS` (CI:
//! `sed,awk,jq`) makes a missing tool a failure; `ENVCLOAK_ORACLE_SEED`
//! and `ENVCLOAK_ORACLE_CASES` change the run.
//!
//! Mutations checked: the reader's program not read (`Analyzer::program`
//! returning at once): sed's `r` and awk's `getline` spellings that reach
//! the canary are allowed, and this fails. `Reader::source_opts` read as
//! file options only (no operand is the pattern then): `grep -v -f
//! /dev/null .env` is allowed, and this fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use envcloak_agents::hook::shell::{check_argv, check_script};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn chance(&mut self, num: usize, den: usize) -> bool {
        self.below(den) < num
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

fn canary(rng: &mut Rng, tag: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let tail: String = (0..32)
        .map(|_| char::from(ALPHABET[rng.below(ALPHABET.len())]))
        .collect();
    format!("ec{tag}{tail}")
}

/// The first of `candidates` that is installed, each tool once by its
/// resolved path.
fn installed(candidates: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for c in candidates {
        let p = Path::new(c);
        let Ok(real) = std::fs::canonicalize(p) else {
            continue;
        };
        if seen.contains(&real) {
            continue;
        }
        seen.push(real);
        out.push(p.to_path_buf());
    }
    out
}

/// What `argv` prints (standard output and error), run with no shell in
/// `dir` with only `env` in its environment, within 10 seconds.
fn run(argv: &[String], dir: &Path, env: &[(&str, &str)]) -> Vec<u8> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut out = Vec::new();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut e = Vec::new();
        let _ = stderr.read_to_end(&mut e);
        e
    });
    let _ = stdout.read_to_end(&mut out);
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    out.extend(reader.join().unwrap());
    out
}

fn holds(out: &[u8], needle: &str) -> bool {
    out.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// `argv` as a shell command line, each word single-quoted.
fn quoted(argv: &[String]) -> String {
    argv.iter()
        .map(|w| format!("'{}'", w.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

struct Case {
    argv: Vec<String>,
    family: &'static str,
}

fn s(x: &str) -> String {
    x.to_owned()
}

/// An env file's path as a program names it.
fn env_path(rng: &mut Rng, root: &Path) -> String {
    let rel = if rng.chance(1, 3) { "sub/.env" } else { ".env" };
    match rng.below(4) {
        0 => format!("./{rel}"),
        1 => format!("{}/{rel}", root.display()),
        _ => rel.to_owned(),
    }
}

/// A sed address, or none.
fn sed_address(rng: &mut Rng) -> &'static str {
    rng.pick(&["", "", "1", "$", "/plain/", "1,2", "/x/,/y/", "\\%p%", "$!"])
}

fn sed_cases(rng: &mut Rng, seds: &[PathBuf], root: &Path, n: usize) -> Vec<Case> {
    let benign = [
        "p", "1d", "s/a/b/", "s|p|q|g", "y/ab/ba/", "=", "$!N", "/x/d", "s/[/]/x/", "h;G",
    ];
    let mut out = Vec::new();
    for _ in 0..n {
        let sed = &seds[rng.below(seds.len())];
        let path = env_path(rng, root);
        let read = if rng.chance(1, 4) { "R" } else { "r" };
        let addr = sed_address(rng);
        let mut lines: Vec<String> = Vec::new();
        for _ in 0..rng.below(3) {
            lines.push(rng.pick(&benign).to_owned());
        }
        let cmd = format!("{addr}{read} {path}");
        let cmd = if rng.chance(1, 4) {
            format!("{{\n{cmd}\n}}")
        } else {
            cmd
        };
        let at = rng.below(lines.len() + 1);
        lines.insert(at, cmd);
        let mut argv = vec![sed.display().to_string()];
        if rng.chance(1, 3) {
            argv.push(s("-n"));
        }
        if rng.chance(1, 4) {
            argv.push(s("-E"));
        }
        match rng.below(3) {
            0 => {
                for l in &lines {
                    argv.push(s("-e"));
                    argv.push(l.clone());
                }
            }
            1 => {
                argv.push(s("-e"));
                argv.push(lines.join("\n"));
            }
            _ => argv.push(lines.join("\n")),
        }
        argv.push(s("a.txt"));
        out.push(Case {
            argv,
            family: "sed",
        });
    }
    // sed's `e`, which GNU sed runs and macOS's refuses.
    for sed in seds {
        for script in [
            "1e cat .env",
            "s/.*/cat .env/e",
            "1e printenv",
            "s/plain/printenv/e",
        ] {
            out.push(Case {
                argv: vec![sed.display().to_string(), s(script), s("a.txt")],
                family: "sed-e",
            });
        }
    }
    out
}

fn awk_cases(rng: &mut Rng, awks: &[PathBuf], root: &Path, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let awk = &awks[rng.below(awks.len())];
        let path = env_path(rng, root);
        let program = match rng.below(8) {
            0 => format!("BEGIN {{ while ((getline l < \"{path}\") > 0) print l }}"),
            1 => format!("BEGIN {{ getline line < \"{path}\"; print line }}"),
            2 => format!("BEGIN {{ \"cat {path}\" | getline x; print x }}"),
            3 => format!("BEGIN {{ system(\"cat {path}\") }}"),
            4 => "BEGIN { for (k in ENVIRON) print k \"=\" ENVIRON[k] }".to_owned(),
            5 => format!("BEGIN {{ ARGV[1] = \"{path}\" }} {{ print }}"),
            6 => format!("BEGIN {{ f = \"{path}\"; while ((getline l < f) > 0) print l }}"),
            _ => "BEGIN { for (k in ENVIRON) if (k ~ /^ECX/) print ENVIRON[k] }".to_owned(),
        };
        let gawk = awk.file_name().is_some_and(|f| f == "gawk");
        let mut argv = vec![awk.display().to_string()];
        match rng.below(if gawk { 3 } else { 2 }) {
            0 => argv.push(program),
            1 => {
                let file = root.join(format!("prog{}.awk", rng.below(1000)));
                std::fs::write(&file, &program).unwrap();
                argv.push(s("-f"));
                argv.push(file.display().to_string());
            }
            _ => {
                argv.push(s("-e"));
                argv.push(program);
            }
        }
        argv.push(s("a.txt"));
        out.push(Case {
            argv,
            family: "awk",
        });
    }
    out
}

fn jq_cases(rng: &mut Rng, jqs: &[PathBuf], yqs: &[PathBuf], root: &Path) -> Vec<Case> {
    let mut out = Vec::new();
    for jq in jqs {
        let j = jq.display().to_string();
        for program in [
            "env",
            "$ENV",
            "$ENV | tostring",
            "env | to_entries[] | .value",
            "[env[]]",
            "{$ENV}",
        ] {
            out.push(Case {
                argv: vec![j.clone(), s("-n"), s(program)],
                family: "jq",
            });
        }
        for _ in 0..4 {
            let path = env_path(rng, root);
            out.push(Case {
                argv: vec![j.clone(), s("-R"), s("--seq"), s("."), path],
                family: "jq",
            });
        }
    }
    for yq in yqs {
        let y = yq.display().to_string();
        for _ in 0..3 {
            let path = env_path(rng, root);
            for f in ["load_str", "load"] {
                out.push(Case {
                    argv: vec![y.clone(), s("-n"), format!("{f}(\"{path}\")")],
                    family: "yq",
                });
            }
        }
    }
    out
}

fn grep_cases(rng: &mut Rng, root: &Path, n: usize) -> Vec<Case> {
    let mut out = Vec::new();
    for _ in 0..n {
        let path = env_path(rng, root);
        let mut argv = vec![s("/usr/bin/grep")];
        if rng.chance(1, 2) {
            argv.push(s("-h"));
        }
        argv.push(s("-v"));
        if rng.chance(1, 2) {
            argv.push(s("-f"));
            argv.push(s("/dev/null"));
        } else {
            argv.push(s("--file=/dev/null"));
        }
        argv.push(path);
        out.push(Case {
            argv,
            family: "grep",
        });
    }
    out
}

#[test]
fn every_program_that_reaches_a_secret_is_not_allowed() {
    let seds = installed(&["/usr/bin/sed", "/bin/sed", "/opt/homebrew/bin/gsed"]);
    let awks = installed(&[
        "/usr/bin/awk",
        "/usr/bin/gawk",
        "/usr/bin/mawk",
        "/usr/bin/original-awk",
        "/opt/homebrew/bin/gawk",
    ]);
    let jqs = installed(&["/usr/bin/jq", "/opt/homebrew/bin/jq", "/usr/local/bin/jq"]);
    let yqs = installed(&["/usr/bin/yq", "/opt/homebrew/bin/yq", "/usr/local/bin/yq"]);
    // Only mikefarah's yq has `load`; the Python wrapper of jq does not.
    let yqs: Vec<PathBuf> = yqs
        .into_iter()
        .filter(|y| {
            Command::new(y)
                .arg("--version")
                .output()
                .is_ok_and(|o| holds(&o.stdout, "mikefarah"))
        })
        .collect();
    if let Ok(want) = std::env::var("ENVCLOAK_TEST_REQUIRE_TOOLS") {
        for name in want.split(',').filter(|n| !n.is_empty()) {
            let have = match name {
                "sed" => !seds.is_empty(),
                "awk" => !awks.is_empty(),
                "jq" => !jqs.is_empty(),
                "yq" => !yqs.is_empty(),
                other => panic!("unknown tool {other}"),
            };
            assert!(have, "{name} is required here and not installed");
        }
    }
    assert!(!seds.is_empty() && !awks.is_empty(), "no sed or awk here");
    let seed = std::env::var("ENVCLOAK_ORACLE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5eed_08c1_0a4c_e66d_u64);
    let cases: usize = std::env::var("ENVCLOAK_ORACLE_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);
    let mut rng = Rng(seed | 1);
    let dir = tempfile::Builder::new()
        .prefix("ecpo")
        .tempdir_in("/tmp")
        .unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let (a, b, e) = (
        canary(&mut rng, "a"),
        canary(&mut rng, "b"),
        canary(&mut rng, "e"),
    );
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join(".env"), format!("K={a}\n")).unwrap();
    std::fs::write(root.join("sub/.env"), format!("K={b}\n")).unwrap();
    std::fs::write(root.join("a.txt"), "plain\nx\ny\n").unwrap();
    let env = [("ECX_PROBE", e.as_str())];
    let reached = |out: &[u8]| holds(out, &a) || holds(out, &b) || holds(out, &e);
    let judge = |argv: &[String]| (check_argv(argv), check_script(&quoted(argv)));
    let mut misses: Vec<String> = Vec::new();
    let flagged = |argv: &[String], misses: &mut Vec<String>| {
        let (a, b) = judge(argv);
        if a.is_none() || b.is_none() {
            misses.push(format!(
                "control {argv:?} (check_argv {a:?}, check_script {b:?})"
            ));
        }
    };

    // Positive and negative controls, with every tool here.
    for sed in &seds {
        let sed = sed.display().to_string();
        let reads = vec![sed.clone(), s("1r .env"), s("a.txt")];
        assert!(reached(&run(&reads, &root, &env)), "{sed}: control r");
        flagged(&reads, &mut misses);
        let plain = vec![sed.clone(), s("-n"), s("p"), s("a.txt")];
        let out = run(&plain, &root, &env);
        assert!(!reached(&out) && holds(&out, "plain"), "{sed}");
        assert_eq!(judge(&plain), (None, None), "{sed}");
    }
    for awk in &awks {
        let awk = awk.display().to_string();
        let reads = vec![
            awk.clone(),
            s("BEGIN { while ((getline l < \".env\") > 0) print l }"),
        ];
        assert!(reached(&run(&reads, &root, &env)), "{awk}: control getline");
        flagged(&reads, &mut misses);
        let plain = vec![awk.clone(), s("1"), s("a.txt")];
        let out = run(&plain, &root, &env);
        assert!(!reached(&out) && holds(&out, "plain"), "{awk}");
        assert_eq!(judge(&plain), (None, None), "{awk}");
    }
    for jq in &jqs {
        let dump = vec![jq.display().to_string(), s("-n"), s("env")];
        assert!(reached(&run(&dump, &root, &env)), "jq env");
        flagged(&dump, &mut misses);
    }

    let mut all = sed_cases(&mut rng, &seds, &root, cases);
    all.extend(awk_cases(&mut rng, &awks, &root, cases));
    all.extend(jq_cases(&mut rng, &jqs, &yqs, &root));
    all.extend(grep_cases(&mut rng, &root, cases / 10));
    let mut counts: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for case in &all {
        let out = run(&case.argv, &root, &env);
        let c = counts.entry(case.family).or_default();
        c.0 += 1;
        if !reached(&out) {
            continue;
        }
        c.1 += 1;
        let (argv, script) = judge(&case.argv);
        if argv.is_none() || script.is_none() {
            misses.push(format!(
                "{:?} (check_argv {argv:?}, check_script {script:?})",
                case.argv
            ));
        }
    }
    eprintln!(
        "measurement: sed {seds:?}, awk {awks:?}, jq {jqs:?}, yq {yqs:?}; (cases, reaching) by \
         family: {counts:?}"
    );
    for (family, (_, hits)) in &counts {
        // GNU sed alone runs `e`: macOS's refuses it, so that family may
        // reach nothing here.
        if *family == "sed-e" {
            continue;
        }
        assert!(
            *hits >= 5,
            "{family}: only {hits} programs reached the secret"
        );
    }
    assert!(
        misses.is_empty(),
        "{} program(s) reach a secret and are allowed:\n{}",
        misses.len(),
        misses.join("\n")
    );
}
