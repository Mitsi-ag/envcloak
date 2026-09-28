//! The command line as the audit log keeps it (SPEC §15.2 gate 33: command
//! lines are redacted before they are sealed; agents paste keys into
//! commands).
//!
//! 1. Every value the request binds is masked with the redactor
//!    (`envcloak-redact`): the raw value and the encodings it covers, each
//!    replaced by `[envcloak:<slug>]`. A value split across two arguments
//!    (`echo pa ss`) is found in the command line joined with spaces; the
//!    entry then keeps that one masked string instead of the arguments.
//! 2. Every word a provider's key pattern matches is masked too
//!    (`Registry::mask_keys`), for keys the request does not bind.
//!
//! Values shorter than the redactor's floor (8 bytes) are not masked, as
//! everywhere else: they are refused for injection (SPEC §6.1 step 6).
//!
//! This file is on security/expose-allowlist.txt: it hands the request's
//! values to the redactor. They stay in the daemon, and the redactor,
//! whose automata keep copies of them, is dropped (and wiped by the
//! allocator) before [`redact_argv`] returns.

use envcloak_core::SecretBytes;
use envcloak_providers::Registry;
use envcloak_redact::RedactorBuilder;
use secrecy::ExposeSecret;

/// `argv` with every value in `values` (labelled by slug) and every
/// key-shaped word masked.
pub fn redact_argv(
    argv: &[String],
    values: &[(String, SecretBytes)],
    registry: Option<&Registry>,
) -> Vec<String> {
    let mut builder = RedactorBuilder::new();
    for (label, v) in values {
        #[allow(clippy::disallowed_methods)] // The redactor needs the value to find it.
        let bytes: &[u8] = v.expose_secret();
        builder = builder.secret(label.clone(), bytes);
    }
    let (redactor, _) = builder.build();
    let each: Vec<String> = argv.iter().map(|a| redactor.redact_str(a)).collect();
    // Masking the arguments one by one gives the same line as masking the
    // whole line, unless a value runs across an argument boundary.
    let whole = redactor.redact_str(&argv.join(" "));
    let masked = if whole == each.join(" ") {
        each
    } else {
        vec![whole]
    };
    match registry {
        Some(r) => masked.iter().map(|a| r.mask_keys(a)).collect(),
        None => masked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(label: &str, value: &str) -> (String, SecretBytes) {
        (label.to_owned(), SecretBytes::copy_from(value.as_bytes()))
    }

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn values_and_keys_are_masked_and_the_rest_kept() {
        let secret = "a value with a space";
        let argv = strings(&["./emit", "--token", secret, "--x=a value with a spaceZ"]);
        let out = redact_argv(&argv, &[v("db/acme", secret)], None);
        assert_eq!(
            out,
            strings(&[
                "./emit",
                "--token",
                "[envcloak:db/acme]",
                "--x=[envcloak:db/acme]Z"
            ])
        );
    }

    #[test]
    fn a_value_split_across_arguments_is_found_in_the_joined_line() {
        let argv = strings(&["echo", "a value with", "a space"]);
        let out = redact_argv(&argv, &[v("db/acme", "a value with a space")], None);
        assert_eq!(out, strings(&["echo [envcloak:db/acme]"]));
    }

    /// The value whole in one argument and split across two others: the
    /// split one is caught too.
    #[test]
    fn a_split_value_is_caught_beside_a_whole_one() {
        let argv = strings(&["a value with a space", "a value", "with a space"]);
        let out = redact_argv(&argv, &[v("db/acme", "a value with a space")], None);
        assert_eq!(out, strings(&["[envcloak:db/acme] [envcloak:db/acme]"]));
    }

    #[test]
    fn no_values_and_no_registry_change_nothing() {
        let argv = strings(&["./emit", ""]);
        assert_eq!(redact_argv(&argv, &[], None), argv);
    }
}
