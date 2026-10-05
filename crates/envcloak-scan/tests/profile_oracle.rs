//! Independent cycle436 scalar, array and removal expectations.
use envcloak_core::SecretBytes;
use envcloak_scan::candidates::Disposition;
use envcloak_scan::profile::{Shell, parse_profile};

fn profile(source: &str) -> envcloak_scan::candidates::ScanReport {
    parse_profile(&SecretBytes::copy_from(source.as_bytes()), Shell::Posix)
}

#[test]
fn supported_literals_and_quoted_parentheses_remain_positive() {
    let atom = String::from_utf8(vec![97; 24]).expect("ascii");
    for (source, expected) in [
        (format!("A={atom}\n"), atom.clone()),
        (format!("export A='{atom}'\n"), atom.clone()),
        (format!("A=\"{atom}\" # comment\n"), atom.clone()),
        (format!("A='({atom})'\n"), format!("({atom})")),
        (format!("A=\"({atom})\"\n"), format!("({atom})")),
    ] {
        let report = profile(&source);
        assert!(report.complete(), "supported input incomplete");
        assert_eq!(report.findings.len(), 1, "finding count");
        let found = &report.findings[0];
        assert!(
            found.disposition == Disposition::Literal,
            "literal disposition"
        );
        assert!(
            found
                .value
                .as_ref()
                .is_some_and(|v| v.ct_eq(expected.as_bytes())),
            "decoded value"
        );
        assert!(found.single_complete_line, "simple removal shape");
    }
}

#[test]
fn templates_remain_names_only() {
    for source in ["A=$HOME\n", "A=`placeholder`\n"] {
        let report = profile(source);
        assert_eq!(report.findings.len(), 1);
        let found = &report.findings[0];
        assert!(
            found.disposition == Disposition::Template,
            "template disposition"
        );
        assert!(
            found.value.is_none() && !found.single_complete_line,
            "template value withheld"
        );
    }
}

fn assert_manual(source: &str) {
    let report = profile(source);
    assert!(!report.complete(), "unsupported array must be reported");
    assert_eq!(report.findings.len(), 1);
    let found = &report.findings[0];
    assert!(
        found.disposition == Disposition::Manual,
        "array is not a scalar literal"
    );
    assert!(
        found.value.is_none() && !found.single_complete_line,
        "array cleanup withheld"
    );
}

#[test]
fn empty_array_requires_manual_disposition() {
    assert_manual("A=()\n");
}

#[test]
fn single_element_array_requires_manual_disposition() {
    let atom = String::from_utf8(vec![97; 24]).expect("ascii");
    assert_manual(&format!("A=({atom})\n"));
}

#[test]
fn scalar_quote_comment_and_range_matrix() {
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 31, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 30, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 32, 35, 32, 111, 114, 100, 105,
                110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 50, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 32, 35, 32, 111, 114, 100, 105,
                110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 49, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 39, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 33, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 39,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 32, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 39, 32, 35, 32, 111, 114,
                100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 52, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 39, 32, 35, 32, 111, 114,
                100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 51, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 34, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 33, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 34,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 32, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 34, 32, 35, 32, 111, 114,
                100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 52, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 34, 32, 35, 32, 111, 114,
                100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 51, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 92, 41, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 35, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 92, 41,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 34, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 92, 41, 32, 35, 32, 111,
                114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 54, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 92, 41, 32, 35, 32, 111,
                114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 53, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 38, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 37, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101,
                110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 57, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109, 101,
                110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 56, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 39, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 40, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 39,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 39, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 39, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109,
                101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 59, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 39, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109,
                101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 58, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 34, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 40, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 34,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 39, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 34, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109,
                101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 59, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 34, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 109,
                101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 58, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100,
                101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100,
                101, 102, 92, 41, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 42, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100,
                101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100,
                101, 102, 92, 41,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 41, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100,
                101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100,
                101, 102, 92, 41, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111,
                109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 61, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                101, 120, 112, 111, 114, 116, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97, 98, 99, 100,
                101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100,
                101, 102, 92, 41, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111,
                109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 60, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99,
                100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99,
                100, 101, 102, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 41, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99,
                100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99,
                100, 101, 102,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 40, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99,
                100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99,
                100, 101, 102, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109,
                109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 60, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 97, 98, 99,
                100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99,
                100, 101, 102, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109,
                109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 59, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 39, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 43, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 39,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 42, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 39, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99,
                111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 62, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 39, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 39, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99,
                111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 61, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 34, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 43, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 34,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 42, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 34, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99,
                111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 62, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 34, 97, 98,
                99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98,
                99, 100, 101, 102, 34, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99,
                111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102,
                97, 98, 99, 100, 101, 102
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 61, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 92, 41, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 45, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 92, 41,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 44, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 92, 41, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121,
                32, 99, 111, 109, 109, 101, 110, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 64, "physical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                9, 32, 101, 120, 112, 111, 114, 116, 32, 32, 86, 65, 76, 85, 69, 61, 92, 40, 97,
                98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97,
                98, 99, 100, 101, 102, 92, 41, 32, 35, 32, 111, 114, 100, 105, 110, 97, 114, 121,
                32, 99, 111, 109, 109, 101, 110, 116,
            ]),
            Shell::Posix,
        );
        assert!(r.complete(), "supported scalar should be complete");
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && f.single_complete_line,
            "scalar removal metadata"
        );
        assert!(
            f.value.as_ref().is_some_and(|v| v.ct_eq(&[
                40, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101, 102, 97, 98, 99, 100, 101,
                102, 97, 98, 99, 100, 101, 102, 41
            ])),
            "scalar decoded bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 63, "physical range");
    }
}
#[test]
fn logical_lines_keep_value_without_physical_line_eligibility() {
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 34, 108, 101, 102, 116, 10, 114, 105, 103, 104, 116, 34, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && !f.single_complete_line,
            "logical-line metadata"
        );
        assert!(
            f.value
                .as_ref()
                .is_some_and(|v| v.ct_eq(&[108, 101, 102, 116, 10, 114, 105, 103, 104, 116])),
            "logical-line bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 19, "logical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 108, 101, 102, 116, 92, 10, 114, 105, 103, 104, 116, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && !f.single_complete_line,
            "logical-line metadata"
        );
        assert!(
            f.value
                .as_ref()
                .is_some_and(|v| v.ct_eq(&[108, 101, 102, 116, 114, 105, 103, 104, 116])),
            "logical-line bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 18, "logical range");
    }
    {
        let r = parse_profile(
            &SecretBytes::copy_from(&[
                86, 65, 76, 85, 69, 61, 39, 108, 101, 102, 116, 10, 114, 105, 103, 104, 116, 39, 10,
            ]),
            Shell::Posix,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Literal && !f.single_complete_line,
            "logical-line metadata"
        );
        assert!(
            f.value
                .as_ref()
                .is_some_and(|v| v.ct_eq(&[108, 101, 102, 116, 10, 114, 105, 103, 104, 116])),
            "logical-line bytes"
        );
        assert!(f.range.start == 0 && f.range.end == 19, "logical range");
    }
}
