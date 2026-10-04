//! The command line of a test binary that has its own `main`
//! (`harness = false`), read the way libtest reads it, so `cargo test`
//! means the same for those binaries as for the others (review F-126):
//!
//! - name filters (substrings, or whole names with `--exact`), `--skip`
//!   (repeatable, `--skip=x` too), `--ignored` and `--include-ignored`;
//! - `--list` lists what would run and runs nothing; `--help` and `-h`
//!   print the options and run nothing;
//! - `--test-threads N`, `--color` and `--test` are read and checked
//!   (each binary keeps its own pace);
//! - `--nocapture`, `--show-output` and `--quiet` are accepted: these
//!   binaries never capture output;
//! - anything else (an unknown option, a missing or bad value, `--format`,
//!   `--logfile`, `-Z`, `--bench`) is refused before any case runs, with
//!   exit code 2. `--` makes every word after it a filter.
//!
//! [`run_cases`] runs the selected cases; [`Plan`] is the parsed line.
//! Adapted from an independent review's reference parser (cycle 363),
//! whose contract table [`tests`] keeps.

use std::io::Write;
use std::num::NonZeroUsize;
use std::time::Instant;

/// What the command line asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Run,
    List,
    Help,
}

/// Which cases `--ignored` and `--include-ignored` select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// The cases not marked ignored (listing shows them all).
    Default,
    /// The ignored ones only (`--ignored`).
    Only,
    /// Both (`--include-ignored`).
    Include,
}

/// `--color`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Auto,
    Always,
    Never,
}

/// Why a command line was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An option these binaries do not know or do not implement.
    Unknown,
    /// An option that takes a value came last.
    MissingValue,
    /// A value that is not one, or a value given to a flag.
    InvalidValue,
    /// `--ignored` with `--include-ignored`.
    ConflictingModes,
}

/// A parsed command line.
#[derive(Debug, Clone)]
pub struct Plan {
    pub action: Action,
    includes: Vec<String>,
    excludes: Vec<String>,
    exact: bool,
    ignored: Ignored,
    pub requested_threads: Option<NonZeroUsize>,
    pub color: Color,
}

impl Plan {
    /// Reads the words after the binary's name.
    ///
    /// # Errors
    /// See [`ParseError`]; nothing is run on an error.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, ParseError> {
        let mut p = Plan {
            action: Action::Run,
            includes: vec![],
            excludes: vec![],
            exact: false,
            ignored: Ignored::Default,
            requested_threads: None,
            color: Color::Auto,
        };
        let mut args = args.into_iter();
        let mut positional = false;
        while let Some(word) = args.next() {
            if positional {
                p.includes.push(word);
                continue;
            }
            if word == "--" {
                positional = true;
                continue;
            }
            let (key, inline) = word
                .split_once('=')
                .map_or((word.as_str(), None), |(k, v)| (k, Some(v)));
            match key {
                "--skip" | "--test-threads" | "--color" => {
                    let value = match inline {
                        Some(v) => v.to_owned(),
                        None => args.next().ok_or(ParseError::MissingValue)?,
                    };
                    match key {
                        "--skip" => {
                            if value.starts_with('-') {
                                return Err(ParseError::InvalidValue);
                            }
                            p.excludes.push(value);
                        }
                        "--test-threads" => {
                            p.requested_threads = Some(
                                value
                                    .parse::<NonZeroUsize>()
                                    .map_err(|_| ParseError::InvalidValue)?,
                            );
                        }
                        _ => {
                            p.color = match value.as_str() {
                                "auto" => Color::Auto,
                                "always" => Color::Always,
                                "never" => Color::Never,
                                _ => return Err(ParseError::InvalidValue),
                            };
                        }
                    }
                }
                "--exact" | "--list" | "--help" | "-h" | "--ignored" | "--include-ignored"
                | "--test" | "--nocapture" | "--show-output" | "--quiet" | "-q" => {
                    if inline.is_some() {
                        return Err(ParseError::InvalidValue);
                    }
                    match key {
                        "--exact" => p.exact = true,
                        "--list" => {
                            if p.action != Action::Help {
                                p.action = Action::List;
                            }
                        }
                        "--help" | "-h" => p.action = Action::Help,
                        "--ignored" => {
                            if p.ignored == Ignored::Include {
                                return Err(ParseError::ConflictingModes);
                            }
                            p.ignored = Ignored::Only;
                        }
                        "--include-ignored" => {
                            if p.ignored == Ignored::Only {
                                return Err(ParseError::ConflictingModes);
                            }
                            p.ignored = Ignored::Include;
                        }
                        // Accepted: these binaries run their own cases and
                        // never capture output.
                        _ => {}
                    }
                }
                _ if word.starts_with('-') => return Err(ParseError::Unknown),
                _ => p.includes.push(word),
            }
        }
        Ok(p)
    }

    /// Reads the words after the binary's name as the system gave them; a
    /// word that is not UTF-8 is refused ([`ParseError::InvalidValue`])
    /// rather than read in part.
    ///
    /// # Errors
    /// As [`Plan::parse`].
    pub fn parse_os(
        args: impl IntoIterator<Item = std::ffi::OsString>,
    ) -> Result<Self, ParseError> {
        let words = args
            .into_iter()
            .map(|a| a.into_string().map_err(|_| ParseError::InvalidValue))
            .collect::<Result<Vec<_>, _>>()?;
        Plan::parse(words)
    }

    /// Whether the case `name` (marked ignored or not) is selected: run in
    /// [`Action::Run`], listed in [`Action::List`].
    pub fn selects(&self, name: &str, ignored: bool) -> bool {
        let fits = |filter: &String| {
            if self.exact {
                name == filter
            } else {
                name.contains(filter.as_str())
            }
        };
        let named = (self.includes.is_empty() || self.includes.iter().any(fits))
            && !self.excludes.iter().any(fits);
        named
            && match self.ignored {
                Ignored::Default => self.action == Action::List || !ignored,
                Ignored::Only => ignored,
                Ignored::Include => true,
            }
    }
}

/// What `--help` prints.
pub const USAGE: &str = "Usage: <test binary> [OPTIONS] [FILTERS...]

Options read as libtest reads them:
    --exact               Filters match whole case names
    --skip FILTER         Skip the cases FILTER selects (repeatable)
    --ignored             Run the ignored cases only
    --include-ignored     Run the ignored cases too
    --list                List the selected cases; run nothing
    --test-threads N      Read and checked; the binary keeps its own pace
    --color auto|always|never
    --nocapture, --show-output, --quiet, --test
                          Accepted; output is never captured
    -h, --help            This text
Anything else is refused before a case runs.";

/// Reads this process's command line and runs, lists or describes
/// `cases` (none of them ignored), printing one line per case run and a
/// summary; exits 101 when a case failed and 2 for a command line it
/// refuses, before any case runs.
pub fn run_cases(name: &str, cases: &[(&str, fn())]) {
    let code = dispatch(
        name,
        Plan::parse_os(std::env::args_os().skip(1)),
        cases,
        &mut std::io::stdout().lock(),
    );
    if code != 0 {
        std::process::exit(code);
    }
}

/// [`run_cases`] on a parsed command line, writing to `out`; returns the
/// exit code.
fn dispatch(
    name: &str,
    parsed: Result<Plan, ParseError>,
    cases: &[(&str, fn())],
    out: &mut dyn Write,
) -> i32 {
    let plan = match parsed {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{name}: the command line was refused ({e:?})\n{USAGE}");
            return 2;
        }
    };
    let chosen: Vec<&(&str, fn())> = cases
        .iter()
        .filter(|(case, _)| plan.selects(case, false))
        .collect();
    match plan.action {
        Action::Help => {
            let _ = writeln!(out, "{USAGE}");
            return 0;
        }
        Action::List => {
            for (case, _) in &chosen {
                let _ = writeln!(out, "{case}: test");
            }
            let _ = writeln!(out, "\n{} tests, 0 benchmarks", chosen.len());
            return 0;
        }
        Action::Run => {}
    }
    let _ = writeln!(out, "\nrunning {} tests", chosen.len());
    let mut failed = Vec::new();
    for (case, f) in &chosen {
        let start = Instant::now();
        match std::panic::catch_unwind(*f) {
            Ok(()) => {
                let _ = writeln!(out, "test {case} ... ok ({:?})", start.elapsed());
            }
            Err(_) => {
                let _ = writeln!(out, "test {case} ... FAILED");
                failed.push(*case);
            }
        }
    }
    let _ = writeln!(
        out,
        "{name}: {} case(s) run, {} failed{}",
        chosen.len(),
        failed.len(),
        if failed.is_empty() {
            String::new()
        } else {
            format!(": {failed:?}")
        }
    );
    if failed.is_empty() { 0 } else { 101 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The review's contract table: four cases (`alpha`, `beta`, `gamma`
    /// and `delta`, the last marked ignored); for each command line, which
    /// run, which are listed, whether help is shown, or that it is refused.
    /// The rows marked as checked against standard libtest by the review
    /// match what `cargo test`'s own harness does with the same words.
    #[test]
    fn the_command_line_selects_as_libtest_does() {
        const CASES: [(&str, bool); 4] = [
            ("alpha", false),
            ("beta", false),
            ("gamma", false),
            ("delta", true),
        ];
        // (args, ran, listed, help); refused when `None`.
        type Row = (
            &'static [&'static str],
            Option<(&'static [usize], &'static [usize], bool)>,
        );
        let rows: &[Row] = &[
            (&[], Some((&[0, 1, 2], &[], false))),
            (&["--test"], Some((&[0, 1, 2], &[], false))),
            (&["--test-threads", "6"], Some((&[0, 1, 2], &[], false))),
            (&["--test-threads=6"], Some((&[0, 1, 2], &[], false))),
            (&["--color", "never"], Some((&[0, 1, 2], &[], false))),
            (&["--color=auto"], Some((&[0, 1, 2], &[], false))),
            (&["alpha"], Some((&[0], &[], false))),
            (&["alpha", "beta"], Some((&[0, 1], &[], false))),
            (&["alpha", "--exact"], Some((&[0], &[], false))),
            (&["alph", "--exact"], Some((&[], &[], false))),
            (&["--skip", "no-such-case"], Some((&[0, 1, 2], &[], false))),
            (&["--skip", "beta"], Some((&[0, 2], &[], false))),
            (&["--skip=beta"], Some((&[0, 2], &[], false))),
            (&["alpha", "--skip", "alpha"], Some((&[], &[], false))),
            (
                &["--skip", "beta", "--skip=gamma"],
                Some((&[0], &[], false)),
            ),
            (&["--skip", ""], Some((&[], &[], false))),
            (&["--exact", "--skip", "alpha"], Some((&[1, 2], &[], false))),
            (
                &["--exact", "--skip", "alph"],
                Some((&[0, 1, 2], &[], false)),
            ),
            (&[""], Some((&[0, 1, 2], &[], false))),
            (&["", "--exact"], Some((&[], &[], false))),
            (&["--ignored"], Some((&[3], &[], false))),
            (&["--include-ignored"], Some((&[0, 1, 2, 3], &[], false))),
            (&["--ignored", "delta"], Some((&[3], &[], false))),
            (&["--ignored", "alpha"], Some((&[], &[], false))),
            (&["--ignored", "--skip", "delta"], Some((&[], &[], false))),
            (
                &["--include-ignored", "--skip", "delta"],
                Some((&[0, 1, 2], &[], false)),
            ),
            (&["--list"], Some((&[], &[0, 1, 2, 3], false))),
            (&["--list", "alpha"], Some((&[], &[0], false))),
            (
                &["--list", "--skip", "beta"],
                Some((&[], &[0, 2, 3], false)),
            ),
            (&["--list", "--exact", "alph"], Some((&[], &[], false))),
            (&["--list", "--ignored"], Some((&[], &[3], false))),
            (
                &["--list", "--include-ignored"],
                Some((&[], &[0, 1, 2, 3], false)),
            ),
            (&["--help"], Some((&[], &[], true))),
            (&["-h"], Some((&[], &[], true))),
            (&["--", "--skip"], Some((&[], &[], false))),
            // Accepted: never captured anyway.
            (&["--nocapture"], Some((&[0, 1, 2], &[], false))),
            (&["--show-output", "-q"], Some((&[0, 1, 2], &[], false))),
            // Refused before anything runs.
            (&["--reviewer-unknown"], None),
            (&["--list", "--reviewer-unknown"], None),
            (&["--help", "--reviewer-unknown"], None),
            (&["--skip"], None),
            (&["--skip", "--list"], None),
            (&["--test-threads"], None),
            (&["--test-threads=0"], None),
            (&["--test-threads", "bad"], None),
            (&["--test-threads=-1"], None),
            (&["--color"], None),
            (&["--color=bad"], None),
            (&["--exact=yes"], None),
            (&["--list=no"], None),
            (&["--help=1"], None),
            (&["--ignored=yes"], None),
            (&["--ignored", "--include-ignored"], None),
            (&["--include-ignored", "--ignored"], None),
            (&["--format", "pretty"], None),
            (&["--logfile", "unused"], None),
            (&["-Z", "unstable-options"], None),
            (&["--bench"], None),
            (&["alpha", "--child"], None),
        ];
        for (args, expected) in rows {
            let parsed = Plan::parse(args.iter().map(|a| (*a).to_owned()));
            let Some((ran, listed, help)) = expected else {
                assert!(parsed.is_err(), "{args:?} was not refused: {parsed:?}");
                continue;
            };
            let plan = parsed.unwrap_or_else(|e| panic!("{args:?} refused: {e:?}"));
            let picked: Vec<usize> = CASES
                .iter()
                .enumerate()
                .filter(|(_, (n, ig))| plan.selects(n, *ig))
                .map(|(i, _)| i)
                .collect();
            let (got_ran, got_listed): (&[usize], &[usize]) = match plan.action {
                Action::Run => (&picked, &[]),
                Action::List => (&[], &picked),
                Action::Help => (&[], &[]),
            };
            assert_eq!(
                (got_ran, got_listed, plan.action == Action::Help),
                (*ran, *listed, *help),
                "{args:?}"
            );
        }
    }

    /// A word that is not UTF-8 is refused, not read in part.
    #[test]
    fn a_word_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_vec(vec![b'a', 0xff]);
        assert_eq!(Plan::parse_os([bad]).unwrap_err(), ParseError::InvalidValue);
        assert!(Plan::parse_os([std::ffi::OsString::from("alpha")]).is_ok());
    }

    static RAN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn counted() {
        RAN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn failing() {
        RAN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("a failing case");
    }

    /// `--list` and `--help` run no case, nor does a refused line (exit 2);
    /// a run runs what is selected, and a failed case makes the exit 101.
    /// The cases count their runs, so a list or help that ran them would
    /// show.
    #[test]
    fn listing_help_and_refusal_run_nothing() {
        use std::sync::atomic::Ordering::SeqCst;
        let cases: [(&str, fn()); 2] = [("alpha", counted), ("beta", failing)];
        let words = |w: &[&str]| w.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for (args, code, listed) in [
            (&["--list"][..], 0, Some(2)),
            (&["--list", "--skip", "beta"][..], 0, Some(1)),
            (&["--help"][..], 0, None),
            (&["--list", "--unknown"][..], 2, None),
            (&["--format", "json"][..], 2, None),
        ] {
            let before = RAN.load(SeqCst);
            let mut out = Vec::new();
            assert_eq!(
                dispatch("t", Plan::parse(words(args)), &cases, &mut out),
                code,
                "{args:?}"
            );
            assert_eq!(RAN.load(SeqCst), before, "{args:?} ran a case");
            let text = String::from_utf8(out).unwrap();
            if let Some(n) = listed {
                assert_eq!(text.matches(": test").count(), n, "{text}");
            }
        }
        let before = RAN.load(SeqCst);
        let mut out = Vec::new();
        assert_eq!(
            dispatch("t", Plan::parse(words(&["alpha"])), &cases, &mut out),
            0
        );
        assert_eq!(RAN.load(SeqCst), before + 1);
        let mut out = Vec::new();
        assert_eq!(
            dispatch(
                "t",
                Plan::parse(words(&["--test-threads", "6"])),
                &cases,
                &mut out
            ),
            101
        );
        assert_eq!(RAN.load(SeqCst), before + 3, "both cases ran");
    }
}
