//! An independent oracle of the probe cache's life (review cycle 402),
//! run against the public API: every three-update history over two hosts
//! and passed, failed and skipped results (216), each saved and loaded
//! back (648 round trips), against an independent latest-record map: the
//! latest record wins per host, the producer's record keeps every field,
//! a reload keeps the report, its JSON and its display, a changed binary,
//! version, digest or system is stale, and a missing host is none. Unusable
//! receipts (empty, truncated, null, another shape, another format, an
//! unknown field or outcome, a missing digest, one byte over the cap, a
//! directory) give no record and no inherited pass, each followed by a
//! valid one that loads (the positive controls), with the exact-cap
//! receipt loading and a failed store removing its own temporary file.
//! Adapted only to the record's fields added since (the sentinel's
//! evidence, the cases not run). [`the_cache_follows_the_probe_context`]
//! adds the probe context's transitions (Codex F-132) on real files.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use envcloak_agents::coverage::{
    CACHE_FORMAT, Cache, ConfigSet, Coverage, Observed, Outcome, ProbeRecord, Probed, Reason,
    Sentinel, ServerObserved, Surface, assemble,
};
use envcloak_agents::hook::Host;
use envcloak_agents::probe::{Check, ProbeReport, ServerProbe, SurfaceProbe};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Default)]
struct Counts {
    checks: usize,
    writes: usize,
    roundtrips: usize,
    schedules: usize,
    controls: usize,
    rejected: usize,
    identity: usize,
}
impl Counts {
    fn check(&mut self, yes: bool, gate: &'static str) {
        self.checks += 1;
        assert!(yes, "gate: {gate}");
    }
}
fn expected(host: Host, step: usize, outcome: Outcome) -> ProbeRecord {
    ProbeRecord {
        host: host.id().into(),
        exe_sha256: "a".repeat(64),
        version: format!("v{step}"),
        config_digest: "b".repeat(64),
        os: std::env::consts::OS.into(),
        surfaces: Surface::ALL
            .into_iter()
            .map(|surface| Observed {
                surface,
                outcome,
                persisted: surface == Surface::Transcript && outcome == Outcome::Failed,
                why: if outcome == Outcome::Skipped {
                    vec![Reason::ProbeNeedsTerminal]
                } else {
                    vec![]
                },
                skipped: vec![],
            })
            .collect(),
        server: ServerObserved {
            outcome,
            sentinel: if outcome == Outcome::Passed {
                Sentinel::Appeared
            } else {
                Sentinel::NotRun
            },
            control_ran: outcome == Outcome::Passed,
            allowed_write: outcome == Outcome::Passed,
            control_denied: outcome == Outcome::Passed,
        },
        flags: vec![format!("fixture-context-{step}")],
    }
}
fn producer(host: Host, step: usize, outcome: Outcome) -> ProbeReport {
    ProbeReport {
        host,
        version: format!("v{step}"),
        surfaces: Surface::ALL
            .into_iter()
            .map(|surface| SurfaceProbe {
                surface,
                outcome,
                checks: vec![Check {
                    name: "inert receipt",
                    control: true,
                    passed: outcome == Outcome::Passed,
                    why: "",
                }],
                persisted: surface == Surface::Transcript && outcome == Outcome::Failed,
                why: if outcome == Outcome::Skipped {
                    vec![Reason::ProbeNeedsTerminal]
                } else {
                    vec![]
                },
                skipped: vec![],
            })
            .collect(),
        server: ServerProbe {
            outcome,
            sentinel: if outcome == Outcome::Passed {
                Sentinel::Appeared
            } else {
                Sentinel::NotRun
            },
            control_ran: outcome == Outcome::Passed,
            allowed_write: outcome == Outcome::Passed,
            control_denied: outcome == Outcome::Passed,
            checks: vec![],
        },
        runs: vec![],
        flags: vec![format!("fixture-context-{step}")],
    }
}
fn host(n: usize) -> Host {
    if n == 0 {
        Host::ClaudeCode
    } else {
        Host::Codex
    }
}
fn views(cache: &Cache, model: &BTreeMap<String, ProbeRecord>, c: &mut Counts) -> Vec<Coverage> {
    let mut out = vec![];
    for i in 0..2 {
        let h = host(i);
        match model.get(h.id()) {
            None => c.check(
                matches!(cache.probed(h.id(), "", "", ""), Probed::None),
                "missing host",
            ),
            Some(r) => {
                c.check(
                    cache.record(h.id()) == Some(r),
                    "record matches independent latest map",
                );
                c.check(matches!(cache.probed(h.id(), &r.exe_sha256, &r.version, &r.config_digest), Probed::Current(x) if x == r), "same identity current");
                c.controls += 1;
                for (exe, version, digest) in [
                    ("different", r.version.as_str(), r.config_digest.as_str()),
                    (r.exe_sha256.as_str(), "different", r.config_digest.as_str()),
                    (r.exe_sha256.as_str(), r.version.as_str(), "different"),
                ] {
                    c.check(
                        matches!(cache.probed(h.id(), exe, version, digest), Probed::Stale),
                        "identity change stale",
                    );
                    c.identity += 1;
                }
                let cs = ConfigSet::default();
                out.push(assemble(
                    h,
                    &r.version,
                    &cs,
                    cache.probed(h.id(), &r.exe_sha256, &r.version, &r.config_digest),
                ));
            }
        }
    }
    out
}
fn store(cache: &Cache, path: &Path, c: &mut Counts) {
    cache.store(path).expect("owned cache write");
    c.writes += 1;
    c.check(
        std::fs::metadata(path)
            .expect("owned cache metadata")
            .permissions()
            .mode()
            & 0o777
            == 0o600,
        "private cache mode",
    );
    c.check(
        std::fs::read_dir(path.parent().expect("owned parent"))
            .expect("owned listing")
            .count()
            == 1,
        "no temporary name after success",
    );
}
fn exercise(root: &Path, c: &mut Counts) {
    let outcomes = [Outcome::Passed, Outcome::Failed, Outcome::Skipped];
    for schedule in 0..216 {
        let dir = root.join(format!("s{schedule}"));
        std::fs::create_dir(&dir).expect("owned schedule root");
        let path = Cache::path(&dir);
        let mut cache = Cache::load(&path);
        let mut model = BTreeMap::new();
        c.check(cache.records.is_empty(), "missing file empty");
        let mut choices = schedule;
        for step in 0..3 {
            let op = choices % 6;
            choices /= 6;
            let h = host(op / 3);
            let outcome = outcomes[op % 3];
            let want = expected(h, step, outcome);
            let got = producer(h, step, outcome).record(&want.exe_sha256, &want.config_digest);
            c.check(got == want, "producer preserves receipt fields");
            model.insert(h.id().to_owned(), want);
            cache.put(got);
            c.check(cache.format == CACHE_FORMAT, "writer version");
            c.check(
                cache.records == model.values().cloned().collect::<Vec<_>>(),
                "latest host record and stable order",
            );
            let before = views(&cache, &model, c);
            store(&cache, &path, c);
            let reloaded = Cache::load(&path);
            c.roundtrips += 1;
            c.check(cache == reloaded, "all fields survive disk roundtrip");
            let after = views(&reloaded, &model, c);
            c.check(before == after, "assembled report survives reload");
            c.check(
                serde_json::to_vec(&before).expect("inert report serialization")
                    == serde_json::to_vec(&after).expect("inert report serialization"),
                "report JSON survives reload",
            );
            for (a, b) in before.iter().zip(&after) {
                for (x, y) in a.surfaces.iter().zip(&b.surfaces) {
                    c.check(
                        x.to_string() == y.to_string(),
                        "surface display survives reload",
                    );
                }
            }
            cache = reloaded;
        }
        std::fs::remove_dir_all(&dir).expect("owned schedule cleanup");
        c.check(!dir.exists(), "schedule cleanup complete");
        c.schedules += 1;
    }
    let dir = root.join("boundary");
    std::fs::create_dir(&dir).expect("owned boundary root");
    let path = dir.join("receipt.json");
    let mut cache = Cache::default();
    let r = expected(host(0), 0, Outcome::Passed);
    cache.put(r.clone());
    let mut other_os = r.clone();
    other_os.os = "other-platform".into();
    let mut other = Cache::default();
    other.put(other_os);
    c.check(
        matches!(
            other.probed(&r.host, &r.exe_sha256, &r.version, &r.config_digest),
            Probed::Stale
        ),
        "OS change stale",
    );
    c.identity += 1;
    c.check(
        matches!(
            cache.probed(host(1).id(), &r.exe_sha256, &r.version, &r.config_digest),
            Probed::None
        ),
        "record not shared across hosts",
    );
    let valid = serde_json::to_vec(&cache).expect("inert serialization");
    let value: serde_json::Value = serde_json::from_slice(&valid).expect("inert JSON");
    let mut cases = vec![vec![], b"{".to_vec(), b"null".to_vec(), b"[]".to_vec()];
    let mut changed = value.clone();
    changed["format"] = (CACHE_FORMAT + 1).into();
    cases.push(serde_json::to_vec(&changed).expect("inert JSON"));
    let mut changed = value.clone();
    changed["future_field"] = true.into();
    cases.push(serde_json::to_vec(&changed).expect("inert JSON"));
    let mut changed = value.clone();
    changed["records"][0]["surfaces"][0]["outcome"] = "unknown_outcome".into();
    cases.push(serde_json::to_vec(&changed).expect("inert JSON"));
    let mut changed = value.clone();
    changed["records"][0]
        .as_object_mut()
        .expect("inert object")
        .remove("config_digest");
    cases.push(serde_json::to_vec(&changed).expect("inert JSON"));
    let mut cap = valid.clone();
    cap.resize(1024 * 1024, b' ');
    std::fs::write(&path, &cap).expect("owned cap write");
    c.check(Cache::load(&path) == cache, "exact-cap positive");
    c.controls += 1;
    cap.push(b' ');
    cases.push(cap);
    for bytes in cases {
        std::fs::write(&path, bytes).expect("owned malformed write");
        let empty = Cache::load(&path);
        c.check(empty.records.is_empty(), "unusable receipt has no records");
        c.check(
            matches!(
                empty.probed(&r.host, &r.exe_sha256, &r.version, &r.config_digest),
                Probed::None
            ),
            "unusable receipt cannot be current",
        );
        c.rejected += 1;
        let cov = assemble(host(0), &r.version, &ConfigSet::default(), Probed::None);
        c.check(
            cov.surfaces.iter().all(|s| s.probe != Outcome::Passed),
            "missing evidence does not inherit pass",
        );
        std::fs::write(&path, &valid).expect("owned valid restore");
        c.check(Cache::load(&path) == cache, "valid control after refusal");
        c.controls += 1;
    }
    std::fs::remove_file(&path).expect("owned remove");
    std::fs::create_dir(&path).expect("owned nonfile");
    c.check(
        Cache::load(&path).records.is_empty(),
        "directory unreadable",
    );
    c.rejected += 1;
    c.check(
        cache.store(&path).is_err(),
        "directory destination store error",
    );
    c.check(
        std::fs::read_dir(&dir).expect("owned listing").count() == 1,
        "failed rename removes temporary file",
    );
    std::fs::remove_dir(&path).expect("owned remove dir");
    cache.store(&path).expect("owned recovery write");
    c.writes += 1;
    c.check(Cache::load(&path) == cache, "store recovery positive");
    c.controls += 1;
    let blocker = dir.join("regular-parent");
    std::fs::write(&blocker, &valid).expect("owned blocker");
    c.check(
        cache.store(&blocker.join("receipt")).is_err(),
        "non-directory parent refusal",
    );
    c.check(
        std::fs::read(&blocker).expect("owned blocker read") == valid,
        "unrelated file preserved",
    );
    std::fs::remove_dir_all(&dir).expect("owned boundary cleanup");
    c.check(!dir.exists(), "boundary cleanup complete");
}
/// The oracle's whole packet, in a temporary directory of its own.
///
/// Mutations checked: `Cache::put` keeping the older record of a host
/// (`retain` dropped): the latest-record map disagrees and this fails;
/// `Cache::load` accepting another format: the unknown-format receipt
/// loads and this fails.
#[test]
fn the_cache_keeps_the_latest_record_per_host_across_reloads() {
    let dir = tempfile::Builder::new()
        .prefix("ecq")
        .tempdir_in("/tmp")
        .expect("owned fixture root");
    let root = dir.path().join("cache-oracle-fixtures");
    std::fs::create_dir(&root).expect("owned fixture root");
    let mut counts = Counts::default();
    exercise(&root, &mut counts);
    std::fs::remove_dir_all(&root).expect("owned fixture cleanup");
    assert!(!root.exists(), "fixture cleanup verified");
    assert_eq!(counts.schedules, 216);
    assert_eq!(counts.roundtrips, 648);
    assert_eq!(counts.rejected, 10);
    println!(
        "{{\"schedules\":{},\"stores\":{},\"roundtrips\":{},\"contract_checks\":{},\"positive_controls\":{},\"unusable_receipts\":{},\"identity_refusals\":{}}}",
        counts.schedules,
        counts.writes,
        counts.roundtrips,
        counts.checks,
        counts.controls,
        counts.rejected,
        counts.identity
    );
}

/// The probe context's transitions on real files (Codex F-132): a result
/// kept under the context's fingerprint is current while nothing it
/// depends on changed, and stale after a hook's timeout changes, the
/// program a hook runs changes at its path, or the `envcloak` build
/// changes, each put back current again (the positive controls); a hook
/// program that cannot be read leaves no fingerprint, and no record is
/// current for it.
///
/// Mutation checked: `ConfigSet::fingerprint` without the hook programs
/// (`Context::programs` keeping no SHA-256): the program's change leaves
/// the result current and this fails.
#[test]
fn the_cache_follows_the_probe_context() {
    use envcloak_agents::hook::{Event, Host as Agent};
    use envcloak_agents::hosts::claude;
    use envcloak_agents::locations::Locations;
    use std::ffi::OsString;
    let dir = tempfile::Builder::new()
        .prefix("ecq")
        .tempdir_in("/tmp")
        .expect("owned fixture root");
    let root = std::fs::canonicalize(dir.path()).expect("owned root");
    let home = root.join("home");
    let managed = root.join("managed");
    let bin = root.join("bin");
    for d in [&home.join(".claude"), &managed, &bin] {
        std::fs::create_dir_all(d).expect("owned dir");
    }
    let program = bin.join("envcloak");
    std::fs::write(&program, "#!/bin/sh\n").expect("owned program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("owned mode");
    let build = bin.join("envcloak-build");
    std::fs::write(&build, "build one").expect("owned build");
    let settings = home.join(".claude").join("settings.json");
    let hooks = |timeout: u64| {
        let h = |e: Event| {
            serde_json::json!({"hooks": [{"type": "command",
                "command": envcloak_agents::hosts::hook_command(&program, Agent::ClaudeCode, e),
                "timeout": timeout}]})
        };
        let mut tools = h(Event::PreToolUse);
        tools["matcher"] = claude::TOOL_MATCHER.into();
        let mut mcp = h(Event::PreToolUse);
        mcp["matcher"] = claude::MCP_MATCHER.into();
        serde_json::json!({"hooks": {
            "UserPromptSubmit": [h(Event::UserPromptSubmit)],
            "PreToolUse": [tools, mcp],
        }})
        .to_string()
    };
    std::fs::write(&settings, hooks(10)).expect("owned settings");
    let vars: Vec<(String, OsString)> = vec![("HOME".to_owned(), home.clone().into())];
    let env = |k: &str| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let fingerprint = || {
        let l = Locations::new(&env).expect("home");
        ConfigSet::read(Agent::ClaudeCode, &l, &managed, &home, &env).fingerprint(&build)
    };
    let first = fingerprint().expect("a complete context");
    let sha = "a".repeat(64);
    let mut cache = Cache::default();
    cache.put(producer(Agent::ClaudeCode, 0, Outcome::Passed).record(&sha, &first));
    let current = |cache: &Cache| {
        let fp = fingerprint().unwrap_or_default();
        matches!(
            cache.probed(Agent::ClaudeCode.id(), &sha, "v0", &fp),
            Probed::Current(_)
        )
    };
    assert!(current(&cache), "the context it was kept for");
    // A hook's timeout.
    std::fs::write(&settings, hooks(1)).expect("owned settings");
    assert!(!current(&cache), "the hooks' timeout changed");
    std::fs::write(&settings, hooks(10)).expect("owned settings");
    assert!(current(&cache), "the timeout put back");
    // The program the hooks run, at the same path.
    std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("owned program");
    assert!(!current(&cache), "the hook program changed");
    std::fs::write(&program, "#!/bin/sh\n").expect("owned program");
    assert!(current(&cache), "the program put back");
    // The envcloak build.
    std::fs::write(&build, "build two").expect("owned build");
    assert!(!current(&cache), "the build changed");
    std::fs::write(&build, "build one").expect("owned build");
    assert!(current(&cache), "the build put back");
    // Kept on disk and loaded back, the same.
    let path = Cache::path(&root.join("data"));
    cache.store(&path).expect("owned store");
    assert!(current(&Cache::load(&path)), "reloaded");
    // A hook program that cannot be read: no fingerprint, nothing current.
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o111)).expect("owned mode");
    let none = fingerprint();
    let stale = !current(&cache);
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("owned mode");
    assert_eq!(none, None);
    assert!(stale, "a context not identified is current");
    assert!(current(&cache), "readable again");
}
