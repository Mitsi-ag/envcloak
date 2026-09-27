//! Gate 17, policy half: the manifest's `[policy]` only tightens. Checked
//! over every combination of vault policy, manifest policy and subject, so
//! no corner is left to a hand-picked case.
#![allow(clippy::unwrap_used)]

use envcloak_policy::{
    AgentsPolicy, EffectivePolicy, ManifestPolicy, Mode, SubjectKind, VaultProjectPolicy,
    effective_policy, parse_manifest,
};

const AGENTS: [AgentsPolicy; 2] = [AgentsPolicy::Approve, AgentsPolicy::Deny];
const MODES: [Mode; 2] = [Mode::Inject, Mode::Proxy];
const SUBJECTS: [SubjectKind; 3] = [
    SubjectKind::Agent,
    SubjectKind::Terminal,
    SubjectKind::Unknown,
];

fn vault_policies() -> Vec<VaultProjectPolicy> {
    let mut out = Vec::new();
    for agents in AGENTS {
        for redact in [false, true] {
            for mode in MODES {
                out.push(VaultProjectPolicy {
                    agents,
                    redact,
                    mode,
                });
            }
        }
    }
    out
}

fn manifest_policies() -> Vec<ManifestPolicy> {
    let mut out = Vec::new();
    for agents in AGENTS {
        for redact in [None, Some(false), Some(true)] {
            for mode in [None, Some(Mode::Inject), Some(Mode::Proxy)] {
                out.push(ManifestPolicy {
                    agents,
                    redact,
                    mode,
                });
            }
        }
    }
    out
}

/// `a` is at least as strict as `b`.
fn at_least_as_strict(a: &EffectivePolicy, b: &EffectivePolicy) -> bool {
    a.deny >= b.deny && a.redact >= b.redact && a.mode >= b.mode
}

#[test]
fn the_manifest_never_loosens_the_vault_policy() {
    let silent = ManifestPolicy::default();
    let mut checked = 0;
    for v in vault_policies() {
        for s in SUBJECTS {
            let base = effective_policy(&v, &silent, s);
            for m in manifest_policies() {
                let e = effective_policy(&v, &m, s);
                assert!(
                    at_least_as_strict(&e, &base),
                    "{v:?} {m:?} {s:?}: {e:?} looser than {base:?}"
                );
                // What the manifest asks for, it gets, where it tightens.
                assert!(
                    e.mode >= m.mode.unwrap_or(Mode::Inject),
                    "{v:?} {m:?} {s:?}"
                );
                if m.redact == Some(true) {
                    assert!(e.redact, "{v:?} {m:?} {s:?}");
                }
                if m.agents == AgentsPolicy::Deny && s != SubjectKind::Terminal {
                    assert!(e.deny, "{v:?} {m:?} {s:?}");
                }
                // The vault's own settings are a floor, stated here rather
                // than taken from `effective_policy` itself.
                assert!(e.mode >= v.mode, "{v:?} {m:?} {s:?}");
                if v.redact || s != SubjectKind::Terminal {
                    assert!(e.redact, "{v:?} {m:?} {s:?}");
                }
                if v.agents == AgentsPolicy::Deny && s != SubjectKind::Terminal {
                    assert!(e.deny, "{v:?} {m:?} {s:?}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 8 * 3 * 18);
}

#[test]
fn gate17_redact_false_does_not_loosen() {
    let m = parse_manifest(b"[policy]\nredact = false\n")
        .unwrap()
        .policy;
    for s in SUBJECTS {
        let v = VaultProjectPolicy::default();
        assert!(v.redact);
        assert!(effective_policy(&v, &m, s).redact, "{s:?}");
    }
    // Even where the vault has turned redaction off, an agent or a subject
    // of unknown kind is redacted; only a terminal subject goes without.
    let v = VaultProjectPolicy {
        redact: false,
        ..VaultProjectPolicy::default()
    };
    assert!(effective_policy(&v, &m, SubjectKind::Agent).redact);
    assert!(effective_policy(&v, &m, SubjectKind::Unknown).redact);
    assert!(!effective_policy(&v, &m, SubjectKind::Terminal).redact);
    let on = parse_manifest(b"[policy]\nredact = true\n").unwrap().policy;
    assert!(effective_policy(&v, &on, SubjectKind::Terminal).redact);
}

#[test]
fn gate17_mode_inject_does_not_loosen() {
    let m = parse_manifest(b"[policy]\nmode = \"inject\"\n")
        .unwrap()
        .policy;
    let v = VaultProjectPolicy {
        mode: Mode::Proxy,
        ..VaultProjectPolicy::default()
    };
    for s in SUBJECTS {
        assert_eq!(effective_policy(&v, &m, s).mode, Mode::Proxy, "{s:?}");
    }
    let proxy = parse_manifest(b"[policy]\nmode = \"proxy\"\n")
        .unwrap()
        .policy;
    let v = VaultProjectPolicy::default();
    assert_eq!(v.mode, Mode::Inject);
    for s in SUBJECTS {
        assert_eq!(effective_policy(&v, &proxy, s).mode, Mode::Proxy, "{s:?}");
    }
}

#[test]
fn agents_deny_holds_for_agents_and_unknown_subjects() {
    let deny = parse_manifest(b"[policy]\nagents = \"deny\"\n")
        .unwrap()
        .policy;
    let v = VaultProjectPolicy::default();
    assert!(effective_policy(&v, &deny, SubjectKind::Agent).deny);
    assert!(effective_policy(&v, &deny, SubjectKind::Unknown).deny);
    assert!(!effective_policy(&v, &deny, SubjectKind::Terminal).deny);
    let approve = ManifestPolicy::default();
    let v = VaultProjectPolicy {
        agents: AgentsPolicy::Deny,
        ..VaultProjectPolicy::default()
    };
    assert!(effective_policy(&v, &approve, SubjectKind::Agent).deny);
    assert!(effective_policy(&v, &approve, SubjectKind::Unknown).deny);
}

#[test]
fn the_defaults() {
    let v = VaultProjectPolicy::default();
    assert_eq!(v.agents, AgentsPolicy::Approve);
    assert!(v.redact);
    assert_eq!(v.mode, Mode::Inject);
    let m = ManifestPolicy::default();
    assert_eq!(m.agents, AgentsPolicy::Approve);
    assert_eq!((m.redact, m.mode), (None, None));
    for s in SUBJECTS {
        let e = effective_policy(&v, &m, s);
        assert!(!e.deny && e.redact && e.mode == Mode::Inject, "{s:?}");
    }
    // Strictness orders.
    assert!(Mode::Proxy > Mode::Inject);
    assert!(AgentsPolicy::Deny > AgentsPolicy::Approve);
}
