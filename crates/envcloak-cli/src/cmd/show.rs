//! `envcloak show <slug> [--json]`: one item's metadata, its account,
//! links and allowed hosts included. Never its value: `envcloak run`
//! injects values into a command, and nothing prints them.

use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, USAGE, usage};
use envcloak_client::render::print;

use super::refuse_value_like;

const USAGE_TEXT: &str = "envcloak show <slug> [--json]";

pub fn run(args: &[&str]) -> ExitCode {
    let (slug, json) = match args {
        [slug] if !slug.starts_with('-') => (*slug, false),
        [slug, "--json"] | ["--json", slug] if !slug.starts_with('-') => (*slug, true),
        _ => return usage(USAGE_TEXT),
    };
    if let Err(f) = refuse_value_like(&[slug]) {
        return f.report(USAGE);
    }
    show(slug, json).unwrap_or_else(|f| f.report(FAILURE))
}

fn show(slug: &str, json: bool) -> Result<ExitCode, Failure> {
    let item = connect()?.items_show(slug)?;
    print(&item, json);
    Ok(ExitCode::SUCCESS)
}
