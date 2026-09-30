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
//! The redactor does not look for values shorter than its floor (8 bytes),
//! nor for their encodings: they are refused for injection (SPEC §6.1 step
//! 6). Nor does it find a value of 8 to 10 bytes inside a longer base64
//! stream (`Authorization: Basic base64(user:<value>)`) at every one of
//! the three alignments; it lists such a value as partial. When the
//! request binds a value of either kind (and it is not empty), nothing of
//! the command line is kept, since it could hold the value, raw or
//! encoded, in a form that is not masked.
//!
//! This file is on security/expose-allowlist.txt: it hands the request's
//! values to the redactor. They stay in the daemon, and the redactor,
//! whose automata keep copies of them, is dropped (and wiped by the
//! allocator) before [`redact_argv`] returns.

use envcloak_core::SecretBytes;
use envcloak_providers::Registry;
use envcloak_redact::RedactorBuilder;
use secrecy::ExposeSecret;

/// What the entry keeps instead of a command line that could hold a value
/// too short to mask.
pub const SHORT_VALUE_WITHHELD: &str =
    "[envcloak: command line not kept: the request binds a value too short to mask]";

/// `argv` with every value in `values` (labelled by slug) and every
/// key-shaped word masked; or only [`SHORT_VALUE_WITHHELD`] when a value
/// is too short for the redactor to mask in every encoding it covers.
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
    let (redactor, report) = builder.build();
    // Skipped: not looked for at all. Partial: not found inside a longer
    // base64 stream at every alignment.
    let short = values.iter().any(|(label, v)| {
        !v.is_empty() && (report.skipped.contains(label) || report.partial.contains(label))
    });
    if short {
        return vec![SHORT_VALUE_WITHHELD.to_owned()];
    }
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

    /// A value in an encoding the redactor covers is masked like the raw
    /// value.
    #[test]
    fn an_encoded_value_is_masked() {
        use base64::Engine as _;
        let secret = "a value with a space";
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
        let argv = strings(&["./emit", &format!("--b64={b64}"), &hex]);
        let out = redact_argv(&argv, &[v("db/acme", secret)], None);
        assert_eq!(
            out,
            strings(&["./emit", "--b64=[envcloak:db/acme]", "[envcloak:db/acme]"])
        );
    }

    /// A value under the redactor's floor could be anywhere in the command
    /// line, raw or encoded, and would not be found: none of the command
    /// line is kept. An empty value hides in nothing.
    #[test]
    fn a_value_too_short_to_mask_withholds_the_command_line() {
        let argv = strings(&["./emit", "--pin=7391", "--pin64=NzM5MQ=="]);
        let values = [v("db/acme", "a value with a space"), v("pin/acme", "7391")];
        let out = redact_argv(&argv, &values, None);
        assert_eq!(out, strings(&[SHORT_VALUE_WITHHELD]));
        assert!(!out.concat().contains("7391") && !out.concat().contains("NzM5"));

        let out = redact_argv(&argv, &[v("empty/acme", "")], None);
        assert_eq!(out, argv);
    }

    /// A value of 8 to 10 bytes is masked raw, but not inside a longer
    /// base64 stream at every alignment: none of the command line is kept.
    /// At 11 bytes every alignment is covered and the line is masked.
    #[test]
    fn a_value_masked_only_in_part_withholds_the_command_line() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        for len in 8..=10 {
            let secret = "k".repeat(len);
            let argv = strings(&[&format!("Basic {}", b64.encode(format!("user:{secret}")))]);
            let out = redact_argv(&argv, &[v("basic/acme", &secret)], None);
            assert_eq!(out, strings(&[SHORT_VALUE_WITHHELD]), "{len}");
        }
        let secret = "k".repeat(11);
        let argv = strings(&["./emit", &secret]);
        let out = redact_argv(&argv, &[v("basic/acme", &secret)], None);
        assert_eq!(out, strings(&["./emit", "[envcloak:basic/acme]"]));
    }

    #[test]
    fn no_values_and_no_registry_change_nothing() {
        let argv = strings(&["./emit", ""]);
        assert_eq!(redact_argv(&argv, &[], None), argv);
    }
}
