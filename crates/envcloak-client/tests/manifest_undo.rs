//! Cycle536's independent original-byte, stale-state and LIFO controls.
use envcloak_client::manifest_edit::{EditError, record_ref, record_unset, restore_ref};
use envcloak_policy::{Binding, EnvName, ProfileName};
use std::fs;

fn fixture(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("ecu-")
        .tempdir_in("/tmp")
        .unwrap();
    let path = dir.path().join("envcloak.toml");
    fs::write(&path, text).unwrap();
    (dir, path)
}

#[test]
fn exact_original_bytes_and_lifo() {
    for (original, profile) in [
        (
            "[project]\r\nname='fixture'\r\n[env]\r\nA = { ref = 'first', field = 'value' } # keep me\r\nB='second'\r\n",
            None,
        ),
        (
            "env = { A = 'first', B = 'second' }\n[project]\nname='fixture'\n",
            None,
        ),
        (
            "[project]\nname='fixture'\n[env]\nshort.A='first' # final dotted profile\n",
            Some("short"),
        ),
    ] {
        let (_dir, path) = fixture(original);
        let profile = profile.map(|p| ProfileName::new(p).unwrap());
        let (_, first) =
            record_unset(&path, &EnvName::new("A").unwrap(), profile.as_ref()).unwrap();
        let first = first.unwrap();
        let middle = fs::read(&path).unwrap();
        let (_, second) = record_ref(&path, &Binding::parse_arg("C=third").unwrap(), None).unwrap();
        restore_ref(&path, second.unwrap()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), middle);
        restore_ref(&path, first).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
    }
}

#[test]
fn changed_document_and_project_refuse_without_writing() {
    let (_dir, path) = fixture("[project]\nname='fixture'\n[env]\nA='first'\n");
    let (_, receipt) = record_ref(&path, &Binding::parse_arg("A=second").unwrap(), None).unwrap();
    let after = fs::read(&path).unwrap();
    let hostile = String::from_utf8(after.clone())
        .unwrap()
        .replace("second", "xxxxxx");
    fs::write(&path, &hostile).unwrap();
    assert_eq!(
        restore_ref(&path, receipt.unwrap()).unwrap_err(),
        EditError::Changed
    );
    assert_eq!(fs::read(&path).unwrap(), hostile.as_bytes());
    fs::write(&path, &after).unwrap();
    let (_, receipt) = record_ref(&path, &Binding::parse_arg("A=third").unwrap(), None).unwrap();
    let (_other, other) = fixture(&fs::read_to_string(&path).unwrap());
    let bytes = fs::read(&other).unwrap();
    assert_eq!(
        restore_ref(&other, receipt.unwrap()).unwrap_err(),
        EditError::Changed
    );
    assert_eq!(fs::read(&other).unwrap(), bytes);
}

#[test]
fn unchanged_and_refused_edits_have_no_receipt() {
    let (_dir, path) = fixture("[project]\nname='fixture'\n[env]\nA='first'\n");
    let (_, receipt) = record_ref(&path, &Binding::parse_arg("A=first").unwrap(), None).unwrap();
    assert!(receipt.is_none());
    assert!(record_unset(&path, &EnvName::new("B").unwrap(), None).is_err());
}

#[test]
fn private_receipt_codec_is_bounded_and_never_debugs_source() {
    use envcloak_client::manifest_edit::UndoRecord;
    let original = "[project]\nname='fixture' # private comment\n[env]\nA='first'\n";
    let (_dir, path) = fixture(original);
    let (_, receipt) = record_ref(&path, &Binding::parse_arg("A=second").unwrap(), None).unwrap();
    let receipt = receipt.unwrap();
    assert_eq!(format!("{receipt:?}"), "UndoRecord { .. }");
    let mut bytes = Vec::new();
    receipt.write(&mut bytes).unwrap();
    for length in 0..bytes.len() {
        assert!(UndoRecord::read(&mut &bytes[..length]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(UndoRecord::read(&mut extra.as_slice()).is_err());
    let mut huge = bytes.clone();
    huge[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(UndoRecord::read(&mut huge.as_slice()).is_err());
    let decoded = UndoRecord::read(&mut bytes.as_slice()).unwrap();
    assert_eq!(
        decoded.previous_binding().unwrap().unwrap(),
        Binding::parse_arg("A=first").unwrap()
    );
    restore_ref(&path, decoded).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
}
