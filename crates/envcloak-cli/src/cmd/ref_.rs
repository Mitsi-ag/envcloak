//! `envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]` (SPEC §7:
//! an agent that needs a key finds it with `envcloak ls` and references
//! it here): binds a variable to an item in the nearest `envcloak.toml`.
//! The manifest holds names only, so this reads and writes no value. A
//! slug does not say what its item is, and a reference to a login's field
//! is never written (SPEC §6.8 "Login fields are typed", gate b18), so the
//! daemon is asked what the reference names before anything is written:
//! a login's field is refused, `login_reference`, and so is every binding
//! the daemon could not check (no daemon, a locked vault, a failed or
//! malformed answer), with that failure's token. Nothing is written then.
//! Otherwise the answer says whether the reference resolves.
//!
//! The edit itself, which keeps everything else in the file as it was and
//! replaces it atomically, is [`envcloak_client::manifest_edit`]'s. A
//! binding written is a request for approval later, not an approval:
//! `envcloak run` still asks for the new binding.

use std::path::Path;
use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, usage};
use envcloak_client::manifest_edit::edit_manifest_ref;
use envcloak_client::render::print;
use envcloak_ipc::ClientError;
use envcloak_ipc::view::{RefEditView, RefStatus};
use envcloak_policy::{Binding, ProfileName, find_manifest};

use super::refuse_value_like;

const USAGE_TEXT: &str = "envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]";

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
struct RefArgs {
    binding: Binding,
    profile: Option<ProfileName>,
    json: bool,
}

fn parse(args: &[&str]) -> Result<RefArgs, &'static str> {
    let mut binding = None;
    let mut profile = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !json => json = true,
            "--profile" if profile.is_none() => {
                let p = *it.next().ok_or("--profile needs a name")?;
                profile = Some(ProfileName::new(p).map_err(|_| "invalid profile name")?);
            }
            _ if arg.starts_with('-') => return Err("unknown or repeated option"),
            _ if binding.is_some() => return Err("ref takes one NAME=<slug>[#field]"),
            _ => binding = Some(arg),
        }
    }
    let text = binding.ok_or("ref needs NAME=<slug>[#field]")?;
    Ok(RefArgs {
        binding: Binding::parse_arg(text).map_err(|_| "ref needs NAME=<slug>[#field]")?,
        profile,
        json,
    })
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    // A value pasted as an argument is refused as one, before anything
    // about its grammar is said.
    let pieces: Vec<&str> = args
        .iter()
        .flat_map(|a| a.split(['=', '#']))
        .filter(|p| !p.is_empty())
        .collect();
    if let Err(f) = refuse_value_like(&pieces) {
        return f.report(USAGE);
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    edit(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn edit(a: RefArgs) -> Result<ExitCode, Failure> {
    let manifest = match find_manifest(Path::new(".")) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(Failure::new(
                "manifest_invalid",
                "no envcloak.toml in this directory or above it; run `envcloak init` first",
            ));
        }
        Err(_) => {
            return Err(Failure::new(
                "manifest_invalid",
                "the working directory could not be read while looking for envcloak.toml",
            ));
        }
    };
    // What the reference names, from the daemon, before anything is
    // written: a login's field is never bound (SPEC §6.8), and a binding
    // the daemon did not check is not written either.
    let text = format!("{}={}", a.binding.env_name, a.binding.reference);
    let status = check(text)?;
    writable(status)?;
    let e = edit_manifest_ref(&manifest, &a.binding, a.profile.as_ref())?;
    let view = RefEditView {
        manifest: manifest.to_string_lossy().into_owned(),
        profile: a.profile.map(|p| p.as_str().to_owned()),
        env_name: a.binding.env_name.as_str().to_owned(),
        reference: a.binding.reference.to_string(),
        change: e.change,
        previous: e.previous.map(|r| r.to_string()),
        resolves: status,
    };
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

/// The tail of every failure to check: what was not done, and why it was
/// not done without the check.
const NOT_WRITTEN: &str = "nothing was written: `envcloak ref` asks the daemon what a \
     reference names before writing it, since a login's field is never bound to a variable";

/// The daemon's status for the one reference `text`. Every way of not
/// getting one fails, with nothing written: no daemon running, one that
/// is not verified, a locked or unavailable vault, a refused or malformed
/// answer, or an answer that is not one status for the one reference.
fn check(text: String) -> Result<RefStatus, Failure> {
    let unchecked = |f: Failure| f.with_tail(NOT_WRITTEN);
    let mut c = connect().map_err(unchecked)?;
    let answer = c
        .items_check(None, &[text])
        .map_err(|e| unchecked(e.into()))?;
    match answer.refs.as_slice() {
        [status] => Ok(*status),
        _ => Err(unchecked(ClientError::Protocol.into())),
    }
}

/// Whether a binding the daemon answered `status` for may be written. A
/// reference to a missing item or field, or to an item of another class,
/// is written with what the daemon said of it, as it always was (`run`
/// refuses it then); a login's field never is (SPEC §6.8), nor a reference
/// the daemon found shaped like a value (it would put the value in the
/// file), nor one it did not check. Every status is decided here: there is
/// no wildcard, so a new status fails to compile until it is.
fn writable(status: RefStatus) -> Result<(), Failure> {
    match status {
        RefStatus::Ok
        | RefStatus::UnknownItem
        | RefStatus::UnknownField
        | RefStatus::AmbiguousField
        | RefStatus::NoField
        | RefStatus::CardReference
        | RefStatus::IssuerCredentialReference
        | RefStatus::UnknownItemClass => Ok(()),
        RefStatus::LoginReference => Err(Failure::new(
            "login_reference",
            "that reference names a login's field, which is never bound to a variable (only a \
             sign-in opens it); nothing was written",
        )),
        RefStatus::LooksLikeValue => Err(Failure::new(
            "value_on_argv",
            "the binding is shaped like a key or token rather than a name, and values are never \
             taken on the command line or written to envcloak.toml; nothing was written; if it \
             was a key, rotate it, since your shell history may hold it now",
        )),
        RefStatus::InvalidReference | RefStatus::Unchecked => {
            Err(Failure::from(ClientError::Protocol).with_tail(NOT_WRITTEN))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(s: &str) -> Binding {
        Binding::parse_arg(s).unwrap()
    }

    /// Every status the daemon can answer is decided: written as before,
    /// or refused with nothing written. Mutations checked: a login's field
    /// written (the old `.ok()` path's effect), and a value-shaped or
    /// unchecked answer written; each fails here.
    #[test]
    fn only_a_checked_binding_that_is_not_a_login_field_is_written() {
        for ok in [
            RefStatus::Ok,
            RefStatus::UnknownItem,
            RefStatus::UnknownField,
            RefStatus::AmbiguousField,
            RefStatus::NoField,
            RefStatus::CardReference,
            RefStatus::IssuerCredentialReference,
            RefStatus::UnknownItemClass,
        ] {
            assert_eq!(writable(ok), Ok(()), "{ok:?}");
        }
        for (refused, token) in [
            (RefStatus::LoginReference, "login_reference"),
            (RefStatus::LooksLikeValue, "value_on_argv"),
            (RefStatus::InvalidReference, "protocol_error"),
            (RefStatus::Unchecked, "protocol_error"),
        ] {
            let f = writable(refused).unwrap_err();
            assert_eq!(f.token(), token, "{refused:?}");
            assert!(f.message().contains("nothing was written"), "{refused:?}");
        }
    }

    #[test]
    fn arguments_are_one_binding_and_names() {
        let a = parse(&["OPENAI_API_KEY=openai/acme-web", "--profile", "short"]).unwrap();
        assert_eq!(a.binding, binding("OPENAI_API_KEY=openai/acme-web"));
        assert_eq!(a.profile, Some(ProfileName::new("short").unwrap()));
        for bad in [
            &[][..],
            &["A=b", "C=d"],
            &["A"],
            &["A=b", "--profile"],
            &["A=b", "--profile", "Bad"],
            &["A=b", "--value", "x"],
            &["=b"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
