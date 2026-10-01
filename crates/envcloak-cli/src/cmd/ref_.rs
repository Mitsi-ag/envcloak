//! `envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]` (SPEC §7:
//! an agent that needs a key finds it with `envcloak ls` and references
//! it here): binds a variable to an item in the nearest `envcloak.toml`.
//! The manifest holds names only, so this reads and writes no value, and
//! needs no daemon; when one answers, it says whether the reference
//! resolves.
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
use envcloak_ipc::view::RefEditView;
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
    let e = edit_manifest_ref(&manifest, &a.binding, a.profile.as_ref())?;
    // Whether the vault has the item: asked when a daemon answers, and
    // never a reason to fail.
    let text = format!("{}={}", a.binding.env_name, a.binding.reference);
    let resolves = connect()
        .ok()
        .and_then(|mut c| c.items_check(None, &[text]).ok())
        .and_then(|v| v.refs.first().copied());
    let view = RefEditView {
        manifest: manifest.to_string_lossy().into_owned(),
        profile: a.profile.map(|p| p.as_str().to_owned()),
        env_name: a.binding.env_name.as_str().to_owned(),
        reference: a.binding.reference.to_string(),
        change: e.change,
        previous: e.previous.map(|r| r.to_string()),
        resolves,
    };
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(s: &str) -> Binding {
        Binding::parse_arg(s).unwrap()
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
