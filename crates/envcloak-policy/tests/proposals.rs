//! The layer a proposal advises from, from resolution to advice (SPEC
//! §10b "Live-key guard"; M2 plan M2-13): an independent model of
//! `resolve_sourced` over the public API. Every combination of a selected
//! profile or none, an explicit input (none, a `--ref`, an env file's
//! reference, an env file's plain variable), the same or another
//! reference, and the manifest's tables in either order: the winning
//! binding and the layer it came from are what the resolution rules say
//! (a later layer replaces an earlier one), the resolver without layers
//! gives the same bindings, another variable keeps its own layer, and a
//! proposal made from the winning layer advises an edit of that layer:
//! the manifest's `[env]` or the profile's table through `envcloak ref
//! --manifest`, the env file's line, or another `--ref`, never the
//! manifest for an explicit input. The fixtures elsewhere build proposals
//! by hand; this joins the resolver to the advice.
//!
//! Positive controls (each seen to fail this, and restored): a `--ref`
//! recorded as `[env]`; a profile's binding recorded as `[env]`; the
//! advice ignoring the layer (`[env]`'s whatever the source).
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use envcloak_policy::{
    Binding, BindingSource, EnvFileNames, EnvFileRef, EnvName, Manifest, ManifestErrorKind,
    ManifestPolicy, PlainName, ProfileName, Proposal, Reference, resolve, resolve_sourced,
};

/// The manifest's path the advice names.
const MANIFEST: &str = "/p/acme/envcloak.toml";

fn binding(name: &str, reference: &str) -> Binding {
    Binding {
        env_name: EnvName::new(name).unwrap(),
        reference: Reference::parse(reference).unwrap(),
    }
}

/// 32 cases: the profile selected or not, four explicit inputs, the
/// same or another reference, the tables in either order.
#[test]
fn resolution_keeps_the_winning_layer_and_the_advice_follows_it() {
    let profile = ProfileName::new("development").unwrap();
    let mut count = 0;
    for same_reference in [false, true] {
        for reverse in [false, true] {
            for selected in [false, true] {
                for explicit in 0..4 {
                    let base = binding("FOCUS_KEY", "service/base");
                    let over = binding(
                        "FOCUS_KEY",
                        if same_reference {
                            "service/base"
                        } else {
                            "service/profile"
                        },
                    );
                    let stable = binding("STABLE_KEY", "service/stable");
                    let mut env = vec![base.clone(), stable.clone()];
                    let mut profile_bindings = vec![over.clone(), stable.clone()];
                    if reverse {
                        env.reverse();
                        profile_bindings.reverse();
                    }
                    let manifest = Manifest {
                        project_name: None,
                        env,
                        profiles: BTreeMap::from([(profile.clone(), profile_bindings)]),
                        policy: ManifestPolicy::default(),
                        sha256: [0; 32],
                    };
                    let mut refs = Vec::new();
                    let mut file = EnvFileNames::default();
                    let replacement = binding(
                        "FOCUS_KEY",
                        if same_reference {
                            "service/base"
                        } else {
                            "service/explicit"
                        },
                    );
                    match explicit {
                        1 => refs.push(replacement.clone()),
                        2 => file.refs.push(EnvFileRef {
                            line: 9,
                            binding: replacement.clone(),
                        }),
                        3 => file.plain.push(PlainName {
                            line: 9,
                            name: EnvName::new("FOCUS_KEY").unwrap(),
                        }),
                        _ => {}
                    }
                    let selected_profile = selected.then_some(&profile);
                    let file_arg = (explicit >= 2).then_some(&file);
                    let got =
                        resolve_sourced(&manifest, selected_profile, &refs, file_arg).unwrap();
                    let expected_source = match explicit {
                        1 => BindingSource::Ref,
                        2 => BindingSource::EnvFile { line: 9 },
                        _ if selected => BindingSource::Profile {
                            profile: "development".into(),
                        },
                        _ => BindingSource::Env,
                    };
                    let focus = got.iter().find(|(b, _)| b.env_name.as_str() == "FOCUS_KEY");
                    if explicit == 3 {
                        // A plain variable of the env file removes the
                        // vault binding.
                        assert!(focus.is_none());
                        assert_eq!(got.len(), 1);
                    } else {
                        let (b, source) = focus.unwrap();
                        let expected = if explicit != 0 {
                            &replacement
                        } else if selected {
                            &over
                        } else {
                            &base
                        };
                        assert!(b == expected, "winning binding mismatch");
                        assert!(source == &expected_source, "winning source mismatch");
                        let proposed = Proposal {
                            env_name: b.env_name.as_str().into(),
                            live_slug: "service/live".into(),
                            test_slug: "service/test".into(),
                            test_field: None,
                            source: source.clone(),
                        };
                        let advice = proposed.advice(MANIFEST, &|_| false);
                        match explicit {
                            // An explicit input is replaced on the run's
                            // command line, never in the manifest.
                            1 => assert!(
                                advice.contains("--ref") && !advice.contains("envcloak ref"),
                                "wrong advice layer: {advice}"
                            ),
                            2 => assert!(
                                advice.contains("line 9") && !advice.contains("envcloak ref"),
                                "wrong advice layer: {advice}"
                            ),
                            _ if selected => assert!(
                                advice.contains(&format!(
                                    "envcloak ref --manifest {MANIFEST} --profile development \
                                     FOCUS_KEY="
                                )),
                                "wrong advice layer: {advice}"
                            ),
                            _ => assert!(
                                advice.contains(&format!(
                                    "envcloak ref --manifest {MANIFEST} FOCUS_KEY="
                                )) && !advice.contains("--profile"),
                                "wrong advice layer: {advice}"
                            ),
                        }
                        assert_eq!(got.len(), 2);
                    }
                    let stable_source = &got
                        .iter()
                        .find(|(b, _)| b.env_name.as_str() == "STABLE_KEY")
                        .unwrap()
                        .1;
                    assert!(
                        stable_source
                            == &if selected {
                                BindingSource::Profile {
                                    profile: "development".into(),
                                }
                            } else {
                                BindingSource::Env
                            }
                    );
                    let plain = resolve(&manifest, selected_profile, &refs, file_arg).unwrap();
                    assert!(
                        plain == got.iter().map(|(b, _)| b.clone()).collect::<Vec<_>>(),
                        "the resolver without layers changed"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 32);
}

/// Resolution with layers refuses what resolution without them refuses:
/// a variable two explicit inputs name (two `--ref`s, two env file lines,
/// a `--ref` and an env file line), and a profile the manifest lacks. The
/// control: one explicit input resolves.
#[test]
fn resolution_with_layers_keeps_explicit_conflicts_refused() {
    let b = binding("FOCUS_KEY", "service/base");
    let m = Manifest {
        project_name: None,
        env: vec![b.clone()],
        profiles: BTreeMap::default(),
        policy: ManifestPolicy::default(),
        sha256: [0; 32],
    };
    let one = EnvFileRef {
        line: 1,
        binding: b.clone(),
    };
    let two = EnvFileRef {
        line: 2,
        binding: b.clone(),
    };
    let file_one = EnvFileNames {
        refs: vec![one.clone()],
        plain: Vec::new(),
    };
    let file_two = EnvFileNames {
        refs: vec![one, two],
        plain: Vec::new(),
    };
    for (refs, file) in [
        (vec![b.clone(), b.clone()], None),
        (Vec::new(), Some(&file_two)),
        (vec![b.clone()], Some(&file_one)),
    ] {
        let error = resolve_sourced(&m, None, &refs, file).unwrap_err();
        assert!(error.kind() == ManifestErrorKind::DuplicateEnvName);
    }
    assert!(resolve_sourced(&m, None, &[], Some(&file_one)).is_ok());
    let missing = ProfileName::new("missing").unwrap();
    assert!(
        resolve_sourced(&m, Some(&missing), &[], None)
            .unwrap_err()
            .kind()
            == ManifestErrorKind::UnknownProfile
    );
}
