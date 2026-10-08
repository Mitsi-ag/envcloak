//! `envcloak ref NAME=<slug>[#field] [--profile NAME] [--manifest PATH]
//! [--json]` (SPEC §7: an agent that needs a key finds it with `envcloak
//! ls` and references it here): binds a variable to an item in the nearest
//! `envcloak.toml`, or in the one `--manifest` names (an absolute path, as
//! `envcloak run --manifest` takes it), which the approval statement's and
//! `envcloak run`'s advice to bind a test key in a live one's place names,
//! so that it edits that project from any directory (SPEC §10b "Live-key
//! guard").
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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, usage};
use envcloak_client::manifest_edit::{
    EditError, UndoRecord, record_ref, record_unset, restore_ref,
};
use envcloak_client::render::print;
use envcloak_ipc::ClientError;
use envcloak_ipc::view::{RefEditView, RefStatus, RefUnsetView};
use envcloak_policy::{Binding, EnvName, MANIFEST_NAME, ProfileName, find_manifest};

use super::refuse_value_like;

const USAGE_TEXT: &str = "envcloak ref (NAME=<slug>[#field] | --unset NAME) [--profile NAME] [--manifest /absolute/path/envcloak.toml] \
     [--json]";

/// What a `--manifest` must be.
const MANIFEST_PATH: &str = "--manifest needs the absolute path of an envcloak.toml";

/// The parsed command line.
#[derive(PartialEq, Eq)]
struct RefArgs {
    binding: Option<Binding>,
    unset: Option<EnvName>,
    profile: Option<ProfileName>,
    /// `--manifest`: an absolute path to a file named `envcloak.toml`.
    manifest: Option<PathBuf>,
    json: bool,
    undo_fd: Option<i32>,
    restore_fd: Option<i32>,
}

impl core::fmt::Debug for RefArgs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RefArgs { .. }")
    }
}

fn parse(args: &[&str]) -> Result<RefArgs, &'static str> {
    let mut binding = None;
    let mut unset = None;
    let mut profile = None;
    let mut manifest = None;
    let mut json = false;
    let mut undo_fd = None;
    let mut restore_fd = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--unset" if unset.is_none() => {
                unset = Some(
                    EnvName::new(it.next().ok_or("--unset needs a name")?)
                        .map_err(|_| "invalid variable name")?,
                );
            }
            "--json" if !json => json = true,
            "--undo-fd" if undo_fd.is_none() => undo_fd = Some(private_fd(it.next())?),
            "--restore-fd" if restore_fd.is_none() => restore_fd = Some(private_fd(it.next())?),
            "--profile" if profile.is_none() => {
                let p = *it.next().ok_or("--profile needs a name")?;
                profile = Some(ProfileName::new(p).map_err(|_| "invalid profile name")?);
            }
            "--manifest" if manifest.is_none() => {
                // The editor opens the file named `envcloak.toml` in this
                // path's directory, through that directory, never through
                // a symlink, and checks the rest; a path that is relative
                // or names another file is refused here, unechoed.
                let p = Path::new(*it.next().ok_or(MANIFEST_PATH)?);
                if !p.is_absolute() || p.file_name().is_none_or(|n| n != MANIFEST_NAME) {
                    return Err(MANIFEST_PATH);
                }
                manifest = Some(p.to_path_buf());
            }
            _ if arg.starts_with('-') => return Err("unknown or repeated option"),
            _ if binding.is_some() => return Err("ref takes one NAME=<slug>[#field]"),
            _ => binding = Some(arg),
        }
    }
    if restore_fd.is_some()
        && (binding.is_some() || unset.is_some() || profile.is_some() || undo_fd.is_some())
    {
        return Err("--restore-fd takes no binding, profile or recording option");
    }
    if restore_fd.is_none() && binding.is_some() == unset.is_some() {
        return Err("ref needs one binding or --unset NAME");
    }
    Ok(RefArgs {
        binding: binding
            .map(Binding::parse_arg)
            .transpose()
            .map_err(|_| "ref needs NAME=<slug>[#field]")?,
        unset,
        profile,
        manifest,
        json,
        undo_fd,
        restore_fd,
    })
}

fn private_fd(arg: Option<&&str>) -> Result<i32, &'static str> {
    arg.and_then(|s| s.parse::<i32>().ok())
        .filter(|n| *n >= 3)
        .ok_or("private undo descriptor must be 3 or greater")
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    // A value pasted as an argument is refused as one, before anything
    // about its grammar is said. A `--manifest` path is a path, not a name
    // in whose place a value gets pasted (a directory named like a hash is
    // common), so it is not looked at.
    let pieces: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(i, _)| *i == 0 || args[i - 1] != "--manifest")
        .flat_map(|(_, a)| a.split(['=', '#']))
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
    let found = match a.manifest {
        Some(m) => Ok(Some(m)),
        None => find_manifest(Path::new(".")),
    };
    let manifest = match found {
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
    let descriptor = |n| {
        envcloak_sys::claim_inherited_fd(n)
            .map(std::fs::File::from)
            .map_err(|_| {
                Failure::new(
                    "io",
                    "private undo channel unavailable; nothing was written",
                )
            })
    };
    // Validate the channel before the first edit. EOF bounds the private record.
    let mut recording = a.undo_fd.map(descriptor).transpose()?;
    if let Some(fd) = a.restore_fd {
        let record = UndoRecord::read(&mut descriptor(fd)?)?;
        if let Some(binding) = record.previous_binding()? {
            writable(check(format!(
                "{}={}",
                binding.env_name, binding.reference
            ))?)?;
        }
        restore_ref(&manifest, record)?;
        println!("{{\"restored\":true}}");
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(name) = a.unset {
        let (reference, record) = match record_unset(&manifest, &name, a.profile.as_ref()) {
            Ok(r) => r,
            Err(EditError::BindingAbsent) => {
                return Ok(Failure::from(EditError::BindingAbsent).report(1));
            }
            Err(e) => return Err(e.into()),
        };
        deliver_undo(record, &mut recording)?;
        print(
            &RefUnsetView {
                profile: a.profile.map(|p| p.as_str().to_owned()),
                env_name: name.as_str().to_owned(),
                reference: reference.to_string(),
            },
            a.json,
        );
        return Ok(ExitCode::SUCCESS);
    }
    let binding = a
        .binding
        .ok_or_else(|| Failure::new("manifest_invalid", "no binding was selected"))?;
    // What the reference names, from the daemon, before anything is
    // written: a login's field is never bound (SPEC §6.8), and a binding
    // the daemon did not check is not written either.
    let text = format!("{}={}", binding.env_name, binding.reference);
    let status = check(text)?;
    writable(status)?;
    let (e, record) = record_ref(&manifest, &binding, a.profile.as_ref())?;
    deliver_undo(record, &mut recording)?;
    let view = RefEditView {
        manifest: manifest.to_string_lossy().into_owned(),
        profile: a.profile.map(|p| p.as_str().to_owned()),
        env_name: binding.env_name.as_str().to_owned(),
        reference: binding.reference.to_string(),
        change: e.change,
        previous: e.previous.map(|r| r.to_string()),
        resolves: status,
    };
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

fn deliver_undo(
    record: Option<UndoRecord>,
    output: &mut Option<std::fs::File>,
) -> Result<(), Failure> {
    if let (Some(record), Some(output)) = (record, output) {
        record.write(output).map_err(|_| Failure::new("undo_unavailable",
            "the binding was saved, but its undo receipt could not be delivered; do not repeat the edit"))?;
    }
    Ok(())
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
    one_status(&answer.refs)
}

/// The status an `items.check` answer gives the one reference sent. An
/// answer with none, or with more (a status for a reference never sent),
/// answers something else, whatever its first status says: it fails
/// `protocol_error`, and nothing is written.
fn one_status(refs: &[RefStatus]) -> Result<RefStatus, Failure> {
    match refs {
        [status] => Ok(*status),
        _ => Err(Failure::from(ClientError::Protocol).with_tail(NOT_WRITTEN)),
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

    #[test]
    fn private_undo_descriptors_refuse_ambiguous_invocations() {
        for fd in ["0", "1", "2", "-1", "2147483648", "not-a-descriptor"] {
            assert!(parse(&["--restore-fd", fd]).is_err());
            assert!(parse(&["A=fixture", "--undo-fd", fd]).is_err());
        }
        for args in [
            vec!["--restore-fd", "3", "A=fixture"],
            vec!["--restore-fd", "3", "--unset", "A"],
            vec!["--restore-fd", "3", "--profile", "test"],
            vec!["--restore-fd", "3", "--undo-fd", "4"],
            vec!["--restore-fd", "3", "--restore-fd", "4"],
            vec!["A=fixture", "--undo-fd", "3", "--undo-fd", "4"],
            vec!["--undo-fd", "3"],
        ] {
            assert!(parse(&args).is_err());
        }
        assert_eq!(
            parse(&["--restore-fd", "3", "--json"]).unwrap().restore_fd,
            Some(3)
        );
        assert_eq!(
            parse(&["A=fixture", "--undo-fd", "3", "--json"])
                .unwrap()
                .undo_fd,
            Some(3)
        );
    }

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

    /// An answer is one status for the one reference, or nothing is
    /// written: none, two, or a status for a reference never sent fail
    /// `protocol_error` whatever the first says. Mutation checked (the
    /// verifier's survivor): the first of any number taken, and none taken
    /// as `ok` (`[status, ..] => Ok(*status), _ => Ok(RefStatus::Ok)`):
    /// this fails, and so does `login_refs`'s stand-in daemon test.
    #[test]
    fn an_answer_is_one_status_for_the_one_reference() {
        assert_eq!(one_status(&[RefStatus::Ok]), Ok(RefStatus::Ok));
        assert_eq!(
            one_status(&[RefStatus::LoginReference]),
            Ok(RefStatus::LoginReference)
        );
        for refs in [
            &[][..],
            &[RefStatus::Ok, RefStatus::Ok],
            &[RefStatus::Ok, RefStatus::LoginReference],
            &[RefStatus::LoginReference, RefStatus::Ok],
            &[RefStatus::UnknownItem; 3],
        ] {
            let f = one_status(refs).unwrap_err();
            assert_eq!(f.token(), "protocol_error", "{refs:?}");
            assert!(f.message().contains("nothing was written"), "{refs:?}");
        }
    }

    #[test]
    fn arguments_are_one_binding_and_names() {
        let a = parse(&["OPENAI_API_KEY=openai/acme-web", "--profile", "short"]).unwrap();
        assert_eq!(a.binding, Some(binding("OPENAI_API_KEY=openai/acme-web")));
        assert_eq!(a.profile, Some(ProfileName::new("short").unwrap()));
        for bad in [
            &[][..],
            &["A=b", "C=d"],
            &["A"],
            &["A=b", "--profile"],
            &["A=b", "--profile", "Bad"],
            &["A=b", "--value", "x"],
            &["=b"],
            // A `--manifest` that is relative, names another file, is
            // missing or given twice.
            &["A=b", "--manifest"],
            &["A=b", "--manifest", "envcloak.toml"],
            &["A=b", "--manifest", "./p/envcloak.toml"],
            &["A=b", "--manifest", "/p/other.toml"],
            &["A=b", "--manifest", "/p/"],
            &["A=b", "--manifest", "/"],
            &[
                "A=b",
                "--manifest",
                "/p/envcloak.toml",
                "--manifest",
                "/q/envcloak.toml",
            ],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let a = parse(&["--manifest", "/p q/envcloak.toml", "A=openai/acme-web"]).unwrap();
        assert_eq!(a.manifest, Some(PathBuf::from("/p q/envcloak.toml")));
        assert_eq!(a.binding, Some(binding("A=openai/acme-web")));
        assert_eq!(parse(&["A=b"]).unwrap().manifest, None);
    }
}
