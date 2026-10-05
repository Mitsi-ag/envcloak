//! `envcloak items reclassify <slug> test|live|unknown [--passphrase-fd N]
//! [--json]` (SPEC §10b "Live-key guard", "Writes that need a proof"):
//! sets a secret item's classification by hand, where the registry's
//! detection got it wrong or could not tell.
//!
//! - Towards `live` tightens: an agent or an unknown process then gets the
//!   item only where an approval ticks it (`--live NAME`). It needs no
//!   proof, so any caller may run it, an agent included; nothing is read
//!   from a terminal.
//! - Towards `test` or `unknown` loosens: an agent then gets the item
//!   without a tick (and, towards `test`, SPEC §10b's standing approvals
//!   may cover it once they ship). It is a proof, as `rotate` is: under a tracer it refuses at
//!   once, and so it does when its environment holds an agent's markers; a
//!   verified daemon names the item, and serves it only to a caller that
//!   may give a proof, so where none is taken nothing is asked for; the
//!   statement says what changes, and the vault passphrase is read from
//!   `/dev/tty` (or the descriptor `--passphrase-fd` names), never from
//!   argv or the environment. An item that has the classification already
//!   is reported as it is, and no passphrase is asked for.
//!
//! Either change ends the grants and pending requests that bind the item,
//! as a rotation that reclassifies does: the daemon says how many grants
//! ended.

use std::fmt::Write as _;
use std::process::ExitCode;

use envcloak_client::claims::{claims, refuse_if_claimed};
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use envcloak_client::render::{HIDDEN, looks_like_value, print_json, shown};
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_ipc::view::{ClassificationView, ReclassifiedView, TargetView};

use super::{fd_number, refuse_value_like};

const USAGE_TEXT: &str =
    "envcloak items reclassify <slug> test|live|unknown [--passphrase-fd N] [--json]
       towards test or unknown asks for the vault passphrase; towards live needs none";

/// The parsed command line of `items reclassify`.
#[derive(Debug, PartialEq, Eq)]
struct ReclassifyArgs {
    slug: String,
    to: ClassificationView,
    passphrase_fd: Option<i32>,
    json: bool,
}

fn classification(word: &str) -> Option<ClassificationView> {
    Some(match word {
        "test" => ClassificationView::Test,
        "live" => ClassificationView::Live,
        "unknown" => ClassificationView::Unknown,
        _ => return None,
    })
}

fn parse(args: &[&str]) -> Option<ReclassifyArgs> {
    let mut words = Vec::new();
    let mut passphrase_fd = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !json => json = true,
            "--passphrase-fd" if passphrase_fd.is_none() => {
                passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ if arg.starts_with('-') => return None,
            _ => words.push(arg),
        }
    }
    let [slug, to] = words.as_slice() else {
        return None;
    };
    let to = classification(to)?;
    // Towards live no passphrase is read: a descriptor for one is a
    // mistake, refused rather than left unread.
    if to == ClassificationView::Live && passphrase_fd.is_some() {
        return None;
    }
    Some(ReclassifyArgs {
        slug: (*slug).to_owned(),
        to,
        passphrase_fd,
        json,
    })
}

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["reclassify", rest @ ..] => {
            let Some(a) = parse(rest) else {
                return usage(USAGE_TEXT);
            };
            if let Err(f) = refuse_value_like(&[a.slug.as_str()]) {
                return f.report(USAGE);
            }
            reclassify(a).unwrap_or_else(|f| f.report(FAILURE))
        }
        _ => usage(USAGE_TEXT),
    }
}

fn reclassify(a: ReclassifyArgs) -> Result<ExitCode, Failure> {
    let done = match a.to {
        // Tightening: no proof, so no terminal and no statement.
        ClassificationView::Live => connect()?.items_reclassify_live(&a.slug, &claims())?,
        to => loosen(&a, to)?,
    };
    if a.json {
        let mut v = serde_json::to_value(&done).unwrap_or(serde_json::Value::Null);
        if looks_like_value(&done.slug) {
            v["slug"] = serde_json::Value::String(HIDDEN.to_owned());
        }
        print_json(&v);
    } else {
        print!("{}", human(&done));
    }
    Ok(ExitCode::SUCCESS)
}

/// Towards `test` or `unknown`: the proof. An item that has that
/// classification already is reported as it is, and nothing is asked for.
fn loosen(a: &ReclassifyArgs, to: ClassificationView) -> Result<ReclassifiedView, Failure> {
    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    // Served only where a proof is taken: nothing is asked for elsewhere.
    let target = connect()?.items_target(&a.slug, None, &claims_now)?;
    if target.item.classification == to {
        return Ok(ReclassifiedView {
            slug: target.item.slug.clone(),
            classification: to,
            reclassified_from: None,
            grants_ended: 0,
        });
    }
    let statement = statement(&target, to);
    let passphrase = match a.passphrase_fd {
        Some(fd) => {
            eprint!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open().map_err(|_| {
                Failure::new(
                    "no_terminal",
                    "there is no terminal to type the passphrase on; pass it on a descriptor \
                     with --passphrase-fd",
                )
            })?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to reclassify this: ")?
        }
    };
    Ok(connect()?.items_reclassify(&target, to, passphrase, &claims())?)
}

/// What a loosening reclassification changes, for the person who gives the
/// passphrase.
fn statement(t: &TargetView, to: ClassificationView) -> String {
    let i = &t.item;
    let mut o = format!(
        "Reclassify {} from {} to {}.\n",
        shown(&i.slug),
        i.classification.as_str(),
        to.as_str()
    );
    let _ = writeln!(
        o,
        "  An agent, or a process EnvCloak cannot place, then gets its value without a --live \
         tick on the approval."
    );
    let _ = writeln!(
        o,
        "  Grants that bind it end ({} now), and so do the requests waiting for an approval \
         that bind it.",
        t.grants
    );
    o
}

/// The result, for a person.
fn human(v: &ReclassifiedView) -> String {
    let mut o = String::new();
    match v.reclassified_from {
        Some(from) => {
            let _ = writeln!(
                o,
                "Reclassified {} from {} to {}: {} that bound it ended, so its runs need a new \
                 approval.",
                shown(&v.slug),
                from.as_str(),
                v.classification.as_str(),
                if v.grants_ended == 1 {
                    "1 grant".to_owned()
                } else {
                    format!("{} grants", v.grants_ended)
                }
            );
        }
        None => {
            let _ = writeln!(
                o,
                "{} is {} already; nothing changed.",
                shown(&v.slug),
                v.classification.as_str()
            );
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_is_a_slug_and_a_classification() {
        let a = parse(&["stripe/acme-live", "test", "--passphrase-fd", "3", "--json"]).unwrap();
        assert_eq!(
            a,
            ReclassifyArgs {
                slug: "stripe/acme-live".into(),
                to: ClassificationView::Test,
                passphrase_fd: Some(3),
                json: true,
            }
        );
        assert_eq!(parse(&["x", "live"]).unwrap().to, ClassificationView::Live);
        assert_eq!(
            parse(&["--json", "x", "unknown"]).unwrap().to,
            ClassificationView::Unknown
        );
        for bad in [
            &[][..],
            &["x"],
            &["x", "LIVE"],
            &["x", "prod"],
            &["x", "test", "y"],
            &["x", "live", "--passphrase-fd", "3"],
            &["x", "test", "--passphrase-fd"],
            &["x", "test", "--passphrase-fd", "x"],
            &["x", "test", "--json", "--json"],
            &["x", "test", "--value", "y"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
