//! An independent oracle of the coverage report's contract (review cycle
//! 399), run against the public `coverage::assemble`: every report over
//! two hosts, the 256 combinations of eight configuration switches, three
//! platform and sandbox shapes, the 27 combinations of three hook states,
//! six observation profiles and current, stale and absent receipts
//! (746,496 reports) must hold six surfaces once each, failed probes
//! first, reasons sorted, unique and from an independently enumerated
//! token table, probe outcomes kept under degraders, `active` only for a
//! current passed output, and the conservative states for missing hooks,
//! the Linux sandboxed shell and a persisted blocked prompt; with 11
//! hand-specified positive controls, so that reporting everything
//! `unverified` cannot pass. Pure: no files, hosts or credentials. The
//! oracle's tables and controls are its own; it is adapted only to the
//! record's and the configuration's fields added since (the sentinel's
//! evidence, the cases not run, each hook's managed provenance, the probe
//! context), with every managed switch read as all three hooks managed,
//! as the oracle's one flag meant.
// The oracle keeps its two transcript branches apart, as written.
#![allow(clippy::unwrap_used, clippy::if_same_then_else)]

use envcloak_agents::coverage::{
    ConfigSet, Coverage, HookState, Hooks, ManagedHooks, Observed, Outcome, ProbeRecord, Probed,
    Reason, Sentinel, ServerFacts, ServerObserved, State, Surface, assemble,
};
use envcloak_agents::hook::Host;
const SURFACES: [Surface; 6] = [
    Surface::PromptToModel,
    Surface::Transcript,
    Surface::FileRead,
    Surface::Shell,
    Surface::Mcp,
    Surface::Output,
];
const OUTCOMES: [Outcome; 4] = [
    Outcome::Passed,
    Outcome::Failed,
    Outcome::Skipped,
    Outcome::NotQualified,
];
const REASONS: [&str; 18] = [
    "hooks_untrusted",
    "workspace_untrusted",
    "switched_off_user",
    "switched_off_project",
    "switched_off_local",
    "switched_off_managed",
    "managed_only",
    "config_dir_moved",
    "fails_open_on_timeout",
    "override_file",
    "needs_host_approval",
    "outside_host_sandbox",
    "persists_blocked_prompt",
    "sandbox_blocks_socket",
    "probe_needs_terminal",
    "hook_missing",
    "not_probed",
    "changed_since_probe",
];
fn record(host: Host, profile: usize) -> ProbeRecord {
    ProbeRecord {
        host: host.id().to_owned(),
        exe_sha256: String::new(),
        version: String::new(),
        config_digest: String::new(),
        os: std::env::consts::OS.to_owned(),
        flags: Vec::new(),
        surfaces: SURFACES
            .iter()
            .enumerate()
            .map(|(i, &surface)| Observed {
                surface,
                outcome: if profile < 4 {
                    OUTCOMES[profile]
                } else if profile == 4 {
                    Outcome::Failed
                } else {
                    OUTCOMES[i % 4]
                },
                persisted: profile == 4 && surface == Surface::Transcript,
                why: Vec::new(),
                skipped: Vec::new(),
            })
            .collect(),
        server: ServerObserved {
            outcome: Outcome::Skipped,
            sentinel: Sentinel::NotRun,
            control_ran: false,
            allowed_write: false,
            control_denied: false,
        },
    }
}
fn basic(host: Host) -> ConfigSet {
    ConfigSet {
        host: host.id().to_owned(),
        hooks: Hooks {
            prompt: HookState::Present,
            tools: HookState::Present,
            mcp: HookState::Present,
        },
        ..ConfigSet::default()
    }
}
fn rank(surface: Surface) -> usize {
    SURFACES.iter().position(|&x| x == surface).unwrap()
}
struct Counts {
    reports: u64,
    observations: u64,
    obligations: u64,
    mismatch: u64,
    positives: u64,
}
impl Counts {
    fn need(&mut self, pass: bool) {
        self.obligations += 1;
        if !pass {
            self.mismatch += 1;
        }
    }
    fn positive(&mut self, report: Coverage, surface: Surface, state: State, outcome: Outcome) {
        let row = report.surface(surface).unwrap();
        self.need(row.state == state && row.probe == outcome);
        self.positives += 1;
    }
}
fn check(c: &mut Counts, host: Host, config: &ConfigSet, receipt: &ProbeRecord, freshness: usize) {
    let probed = match freshness {
        0 => Probed::Current(receipt),
        1 => Probed::Stale,
        _ => Probed::None,
    };
    let report = assemble(host, "", config, probed);
    c.reports += 1;
    c.need(report.surfaces.len() == 6);
    let mut seen = [false; 6];
    let mut prev = None;
    for row in &report.surfaces {
        c.observations += 1;
        let i = rank(row.surface);
        c.need(!seen[i]);
        seen[i] = true;
        let order = (row.probe != Outcome::Failed, i);
        c.need(prev.is_none_or(|p| p <= order));
        prev = Some(order);
        let tokens: Vec<_> = row.reasons.iter().map(|r| r.name()).collect();
        c.need(tokens.windows(2).all(|p| p[0] < p[1]));
        c.need(tokens.iter().all(|t| REASONS.contains(t)));
        let expected = if freshness == 0 {
            receipt.surfaces[i].outcome
        } else {
            Outcome::Skipped
        };
        c.need(row.probe == expected);
        c.need(
            row.state != State::Active
                || (freshness == 0
                    && expected == Outcome::Passed
                    && row.surface == Surface::Output),
        );
        if row.surface == Surface::Output {
            c.need(
                row.state
                    == if freshness == 0 && expected == Outcome::Passed {
                        State::Active
                    } else {
                        State::Unverified
                    },
            );
            let expected_reasons = match freshness {
                0 => vec![],
                1 => vec![Reason::ChangedSinceProbe],
                _ => vec![Reason::NotProbed],
            };
            c.need(row.reasons == expected_reasons);
            continue;
        }
        let linux_shell = config.linux && config.sandboxed_shell && row.surface == Surface::Shell;
        let installed = match row.surface {
            Surface::PromptToModel | Surface::Transcript => {
                config.hooks.prompt == HookState::Present
            }
            Surface::FileRead | Surface::Shell => config.hooks.tools == HookState::Present,
            Surface::Mcp => config.hooks.mcp == HookState::Present,
            Surface::Output => unreachable!(),
        };
        if linux_shell {
            c.need(row.state == State::Unsupported && row.reasons == [Reason::SandboxBlocksSocket]);
        } else if !installed {
            c.need(row.state == State::Unverified && row.reasons.contains(&Reason::HookMissing));
        } else if freshness == 0 && expected == Outcome::Passed {
            c.need(
                row.state == State::Degraded && row.reasons.contains(&Reason::FailsOpenOnTimeout),
            );
            c.need(row.reasons.contains(&if host == Host::ClaudeCode {
                Reason::WorkspaceUntrusted
            } else {
                Reason::HooksUntrusted
            }));
        } else if freshness == 0
            && expected == Outcome::Failed
            && row.surface == Surface::Transcript
            && receipt.surfaces[i].persisted
        {
            c.need(
                row.state == State::Unsupported && row.reasons == [Reason::PersistsBlockedPrompt],
            );
        } else if freshness > 0 && row.surface == Surface::Transcript && host == Host::ClaudeCode {
            c.need(
                row.state == State::Unsupported && row.reasons == [Reason::PersistsBlockedPrompt],
            );
        } else {
            c.need(row.state != State::Active);
        }
    }
    c.need(seen.into_iter().all(|v| v));
    c.need(report.envcloak_server.is_none());
}
/// Every report of the oracle's matrix keeps the contract, and the 11
/// positive controls hold.
///
/// Mutations checked: `assemble` reading a current passed hook surface as
/// `active` when degraders apply (`Outcome::Passed => s(State::Active,
/// ...)` for both arms): the degraded-but-passed controls and the matrix's
/// `active` obligation fail; the failed-first sort dropped from
/// `Coverage::sorted`: the order obligation fails.
#[test]
fn the_coverage_report_keeps_its_contract_over_the_whole_matrix() {
    let mut c = Counts {
        reports: 0,
        observations: 0,
        obligations: 0,
        mismatch: 0,
        positives: 0,
    };
    for host in [Host::ClaudeCode, Host::Codex] {
        let config = basic(host);
        let passed = record(host, 0);
        let failed = record(host, 1);
        c.positive(
            assemble(host, "", &config, Probed::Current(&passed)),
            Surface::Output,
            State::Active,
            Outcome::Passed,
        );
        c.positive(
            assemble(host, "", &config, Probed::Current(&passed)),
            Surface::PromptToModel,
            State::Degraded,
            Outcome::Passed,
        );
        c.positive(
            assemble(host, "", &config, Probed::Current(&failed)),
            Surface::Output,
            State::Unverified,
            Outcome::Failed,
        );
        c.positive(
            assemble(host, "", &config, Probed::Stale),
            Surface::Output,
            State::Unverified,
            Outcome::Skipped,
        );
        let persisted = record(host, 4);
        c.positive(
            assemble(host, "", &config, Probed::Current(&persisted)),
            Surface::Transcript,
            State::Unsupported,
            Outcome::Failed,
        );
        let hooks = [
            HookState::Present,
            HookState::Missing,
            HookState::CommandMissing,
        ];
        for flags in 0..256u16 {
            for platform in 0..3 {
                for mask in 0..27 {
                    let config = ConfigSet {
                        host: host.id().to_owned(),
                        off_user: flags & 1 != 0,
                        off_project: flags & 2 != 0,
                        off_local: flags & 4 != 0,
                        off_managed: flags & 8 != 0,
                        managed_only: flags & 16 != 0,
                        config_dir_moved: flags & 32 != 0,
                        override_file: flags & 64 != 0,
                        managed_hooks: ManagedHooks {
                            prompt: flags & 128 != 0,
                            tools: flags & 128 != 0,
                            mcp: flags & 128 != 0,
                        },
                        linux: platform != 0,
                        sandboxed_shell: platform == 1,
                        hooks: Hooks {
                            prompt: hooks[mask % 3],
                            tools: hooks[(mask / 3) % 3],
                            mcp: hooks[mask / 9],
                        },
                        read_deny: true,
                        // What tells a refusal or a block as EnvCloak's in
                        // a probe; no state rests on them.
                        foreign_read_deny: false,
                        foreign_prompt_hook: false,
                        server: ServerFacts::default(),
                        context: Default::default(),
                        installed: Default::default(),
                    };
                    for profile in 0..6 {
                        let receipt = record(host, profile);
                        for freshness in 0..3 {
                            check(&mut c, host, &config, &receipt, freshness);
                        }
                    }
                }
            }
        }
    }
    c.positive(
        assemble(Host::ClaudeCode, "", &basic(Host::ClaudeCode), Probed::None),
        Surface::Transcript,
        State::Unsupported,
        Outcome::Skipped,
    );
    println!(
        "{{\"reports\":{},\"surface_observations\":{},\"contract_checks\":{},\"positive_controls\":{},\"mismatches\":{}}}",
        c.reports, c.observations, c.obligations, c.positives, c.mismatch
    );
    assert_eq!(c.reports, 746_496);
    assert_eq!(c.observations, 4_478_976);
    assert_eq!(c.positives, 11);
    assert_eq!(c.mismatch, 0);
}
