//! Standing approvals and `<data>/policy-epoch` over the daemon's socket
//! (SPEC §10b; M2 plan D-10, task M2-15; gate 40):
//! - creating a standing approval (`approve` with `standing: Some(ttl)`),
//!   minting session grants across agent restarts (`StandingGrant` audited
//!   durably before release), listing (`standing.list`), and revoking
//!   (`standing.revoke` by id or `--all`, ending standing records and their
//!   derived session grants while `grants.revoke` ends only active session
//!   grants);
//! - selective-revoke transaction crash points: crash before step 1
//!   (`standing.before_vault_commit`), between steps 1 and 2
//!   (`standing.after_vault_commit`), between steps 2 and 3
//!   (`standing.after_sidecar_write`), and after step 3
//!   (`standing.after_sidecar_sync`);
//! - `<data>/policy-epoch` anti-rollback: deleted sidecar, corrupted sidecar,
//!   and rollback of `vault.db` (`policies.sealed` / header) to an older
//!   generation or digest enter `PolicyEpochUnverified` (`-32046`);
//! - `standing.confirm` exits `PolicyEpochUnverified` with a valid passphrase
//!   and refuses an invalid one (`WrongPassphrase`);
//! - `items.reclassify` to `live` ends a standing record and its derived
//!   session grant;
//! - a re-registered or updated managed launch revision is not matched by an
//!   older standing record.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use common::{client, data_dir, passphrase, project, run_paths, seed_vault};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::vault::{LockedVault, VaultPaths};
use envcloak_ipc::proto::{
    ErrorKind, LaunchDeclParams, ManagedRegisterParams, ManagedServerDecl, RunRequestParams,
    StandingRevokeParams,
};
use envcloak_ipc::view::{
    ApprovedView, ClassificationView, DecisionView, StandingConfirmedView, StandingListView,
    StandingRevokedView, VaultState,
};
use envcloak_ipc::{Client, ClientError, ClientFds, RunPaths, WireSecret};
use envcloak_policy::standing::{StandingId, confirm_statement_digest, render_confirm_statement};
use envcloak_policy::{ApprovalOptions, Uses, render_statement, statement_digest};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, canaries, fresh_seed, testkit_bin,
};

const CHILD_ENV: &str = "ENVCLOAK_TEST_STANDING_CHILD";
const CHILD_AGENT: &str = "ENVCLOAK_TEST_STANDING_AGENT";

const TEST_ONLY_MANIFEST: &str = "[project]
name = \"acme-test\"

[env]
STRIPE_SECRET_KEY = \"stripe/acme-web\"
";

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// Installs a copy of `fixture-agent` at `dest` and, on macOS, ad hoc signs it
/// with signing identifier `identifier`.
fn install_agent_binary(dest: &Path, identifier: &str) {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::copy(testkit_bin("fixture-agent"), dest).unwrap();
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/bin/codesign")
            .args(["-f", "-s", "-", "-i", identifier])
            .arg(dest)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = identifier;
}

/// Runs only as the agent child of a test in this file.
#[test]
fn standing_child() {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut lines = spec.lines();
    let mode = lines.next().unwrap();
    let run_dir = lines.next().unwrap();

    if mode == "spawn_agent" {
        common::terminal_session();
        let agent_bin = std::env::var_os(CHILD_AGENT).unwrap();
        let mut cmd = Command::new(agent_bin);
        cmd.arg("--")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "standing_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, format!("worker\n{run_dir}"));
        let status = cmd.status().unwrap();
        std::process::exit(status.code().unwrap_or(1));
    }

    let paths = RunPaths::under(PathBuf::from(run_dir)).unwrap();
    println!("\nready");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line == "quit" {
            break;
        }
        let req: serde_json::Value = serde_json::from_str(&line).unwrap();
        let manifest = req["manifest"].as_str().unwrap().to_owned();
        let launch = req["launch"].as_str().map(str::to_owned);
        let claims: Vec<String> = req["claims"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default();
        let mut c = Client::connect(&paths).unwrap();
        let p = RunRequestParams {
            manifest,
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".to_owned()],
            claims,
            launch: launch.clone(),
            bridge: None,
            fds: Vec::new(),
        };
        let res = if launch.is_some() {
            let (server_in, _to_server) = envcloak_sys::pipe_cloexec().unwrap();
            let (_from_server, server_out) = envcloak_sys::pipe_cloexec().unwrap();
            let (life_read, _life_write) = envcloak_sys::pipe_cloexec().unwrap();
            let fds = ClientFds {
                stdin: server_in,
                stdout: server_out,
                stderr: None,
                lifeline: life_read,
            };
            c.run_request_with_fds(&p, &fds)
        } else {
            c.run_request(&p)
        };
        let reply = match res {
            Ok(out) => match out.decision {
                DecisionView::Covered { grant, .. } => {
                    serde_json::json!({"decision": "covered", "grant": grant})
                }
                DecisionView::Started {} => {
                    serde_json::json!({"decision": "started"})
                }
                DecisionView::Pending { request } => {
                    serde_json::json!({"decision": "pending", "request": request})
                }
                DecisionView::Denied { reason } => {
                    serde_json::json!({"decision": "denied", "reason": reason})
                }
            },
            Err(ClientError::Rpc(r)) => {
                serde_json::json!({"decision": "error", "kind": r.kind.token(), "reason": r.reason})
            }
            Err(other) => panic!("unexpected client error: {other:?}"),
        };
        println!("{reply}");
    }
}

struct AgentWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl AgentWorker {
    fn start(home: &TestHome, agent_bin: &Path, extra_env: &[(&str, &str)]) -> Self {
        let run_dir = envcloak_testkit::daemon_run_dir(home);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        home.apply(&mut cmd)
            .args([
                "--exact",
                "standing_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                CHILD_ENV,
                format!("spawn_agent\n{}", run_dir.to_str().unwrap()),
            )
            .env(CHILD_AGENT, agent_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            let n = stdout.read_line(&mut line).unwrap();
            assert!(n > 0, "agent worker exited before ready");
            if line.trim() == "ready" {
                break;
            }
        }
        AgentWorker {
            child,
            stdin,
            stdout,
        }
    }

    fn request(
        &mut self,
        manifest: &str,
        launch: Option<&str>,
        claims: &[&str],
    ) -> serde_json::Value {
        let q = serde_json::json!({
            "manifest": manifest,
            "launch": launch,
            "claims": claims,
        });
        writeln!(self.stdin, "{q}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        assert!(n > 0, "agent worker closed stdout");
        serde_json::from_str(line.trim()).unwrap()
    }
}

impl Drop for AgentWorker {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
    agent_bin: PathBuf,
    pause_release: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_daemon_env(&[])
    }

    fn with_daemon_env(extra_env: &[(&str, &str)]) -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);

        let agent_bin = home.home().join(".opencode/bin/opencode");
        install_agent_binary(&agent_bin, "opencode");

        let pause_release = home.home().join("pause-released");
        let d = Self::start_daemon(&home, &pause_release, extra_env);
        let mut c = client(&home);
        c.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
        let manifest = project(&home, "acme-test", TEST_ONLY_MANIFEST);
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
            agent_bin,
            pause_release,
        }
    }

    fn start_daemon(home: &TestHome, pause_release: &Path, extra_env: &[(&str, &str)]) -> Daemon {
        let mut cmd = Command::new(common::exe());
        home.apply(&mut cmd);
        cmd.env(
            envcloak_sys::testing::MAC_TEAM_IDS,
            "opencode=5NZ4Q7NXJ4,com.anthropic.claude-code=Q6L2SF6YDW",
        );
        if !cfg!(target_os = "macos") {
            cmd.env(envcloak_sys::testing::LINUX_STANDING, "1");
        }
        cmd.env(envcloak_sys::testing::PAUSE_RELEASE, pause_release);
        for &(k, v) in extra_env {
            cmd.env(k, v);
        }
        Daemon::start_command(cmd, &[])
    }

    fn restart_daemon(&mut self, extra_env: &[(&str, &str)]) {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        let _ = std::fs::remove_file(&self.pause_release);
        self.d = Self::start_daemon(&self.home, &self.pause_release, extra_env);
    }

    fn kill_and_restart_daemon(&mut self, extra_env: &[(&str, &str)]) {
        self.d.signal("-KILL");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        let _ = std::fs::remove_file(&self.pause_release);
        self.d = Self::start_daemon(&self.home, &self.pause_release, extra_env);
    }

    fn wait_paused(&mut self, site: &str) {
        let line = format!("envcloak test: paused at {site}");
        assert!(
            self.d.wait_for_log(&line, Duration::from_secs(30)),
            "daemon did not pause at {site}:\n{}",
            self.d.log()
        );
    }

    fn pass(&self) -> SecretBytes {
        passphrase(&self.cs)
    }

    fn approve_standing(&self, id: &str, ttl_secs: u64) -> Result<ApprovedView, ClientError> {
        let mut c = client(&self.home);
        let d = c.pending_get(id, &[])?;
        let opts = ApprovalOptions {
            uses: Uses::Session,
            ttl_secs: 3600,
            live: Vec::new(),
            standing: Some(Duration::from_secs(ttl_secs)),
        };
        let rendered = render_statement(&d, &opts);
        assert!(
            rendered.contains("standing approval ("),
            "statement missing standing banner:\n{rendered}"
        );
        let digest = statement_digest(&d, &opts);
        c.approve(id, opts, &digest, self.pass(), &[])
    }

    fn standing_list(&self) -> StandingListView {
        client(&self.home).standing_list().unwrap()
    }

    fn standing_revoke_id(&self, id: &str) -> Result<StandingRevokedView, ClientError> {
        client(&self.home).standing_revoke(&StandingRevokeParams {
            id: Some(id.to_owned()),
            ..StandingRevokeParams::default()
        })
    }

    fn standing_revoke_all(&self) -> Result<StandingRevokedView, ClientError> {
        client(&self.home).standing_revoke(&StandingRevokeParams {
            all: true,
            ..StandingRevokeParams::default()
        })
    }

    fn standing_confirm(&self, pass: SecretBytes) -> Result<StandingConfirmedView, ClientError> {
        let mut c = client(&self.home);
        let listed = c.standing_list()?;
        let digest = confirm_statement_digest(&listed.standing);
        let rendered = render_confirm_statement(&listed.standing);
        assert!(rendered.contains("Confirm standing approvals"));
        c.standing_confirm(&digest, pass, &[])
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

#[test]
fn standing_approval_mints_session_grants_and_revokes_cleanly() {
    let mut f = Fixture::new();
    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);

    let r1 = agent.request(&f.manifest, None, &[]);
    assert_eq!(r1["decision"], "pending", "{r1}");
    let req_id = r1["request"].as_str().unwrap();

    let approved = f.approve_standing(req_id, 7 * 86_400).unwrap();
    let standing_id = approved.standing.as_deref().expect("standing id returned");
    StandingId::parse(standing_id).unwrap();
    assert!(approved.standing_expires_in_secs.unwrap() > 6 * 86_400);

    // Status and standing.list reflect the new standing record.
    let st = client(&f.home).status().unwrap();
    assert_eq!(st.approvals.standing, 1);
    assert!(!st.approvals.policy_epoch_unverified);
    let list = f.standing_list();
    assert_eq!(list.standing.len(), 1);
    assert!(!list.policy_epoch_unverified);
    assert_eq!(list.standing[0].id, standing_id);
    assert_eq!(list.standing[0].agent_id, "opencode");
    assert_eq!(
        list.standing[0].bindings,
        vec!["STRIPE_SECRET_KEY=stripe/acme-web"]
    );

    // Repeat request from the agent is now covered via a derived session grant.
    let r2 = agent.request(&f.manifest, None, &[]);
    assert_eq!(r2["decision"], "covered", "{r2}");
    let g1 = r2["grant"].as_str().unwrap().to_owned();
    assert_eq!(client(&f.home).grants_list().unwrap().grants.len(), 1);

    // Restarting the agent process starts a fresh agent root, and the standing
    // record mints a fresh session grant without prompting.
    drop(agent);
    let mut agent2 = AgentWorker::start(&f.home, &f.agent_bin, &[]);
    let r3 = agent2.request(&f.manifest, None, &[]);
    assert_eq!(r3["decision"], "covered", "{r3}");
    let g2 = r3["grant"].as_str().unwrap().to_owned();
    assert_ne!(g1, g2);

    // `grants.revoke` clears active session grants only; the standing record
    // remains and mints another session grant on the next request.
    let revoked_grants = client(&f.home).grants_revoke(None).unwrap();
    assert!(revoked_grants.revoked >= 1);
    assert!(client(&f.home).grants_list().unwrap().grants.is_empty());
    assert_eq!(f.standing_list().standing.len(), 1);

    let r4 = agent2.request(&f.manifest, None, &[]);
    assert_eq!(r4["decision"], "covered", "{r4}");
    assert_eq!(client(&f.home).grants_list().unwrap().grants.len(), 1);

    // `standing.revoke` by id removes the standing record and ends its derived
    // session grant.
    let rev = f.standing_revoke_id(standing_id).unwrap();
    assert_eq!(rev.revoked, 1);
    assert_eq!(rev.grants_ended, 1);
    assert!(f.standing_list().standing.is_empty());
    assert!(client(&f.home).grants_list().unwrap().grants.is_empty());

    // Next request is pending again.
    let r5 = agent2.request(&f.manifest, None, &[]);
    assert_eq!(r5["decision"], "pending", "{r5}");
    drop(agent2);

    // Stop daemon and verify audit log records StandingCreate, StandingGrant,
    // and StandingRevoke.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let paths = VaultPaths::under(data_dir(&f.home));
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_passphrase(&f.pass())
        .map_err(|(_, e)| e)
        .unwrap();
    let (entries, report) = v.read_audit().unwrap();
    assert_eq!(report.problems, 0);
    assert!(
        entries
            .iter()
            .any(|e| e.record.kind == AuditKind::StandingCreate)
    );
    assert!(
        entries
            .iter()
            .any(|e| e.record.kind == AuditKind::StandingGrant)
    );
    assert!(
        entries
            .iter()
            .any(|e| e.record.kind == AuditKind::StandingRevoke)
    );
    drop(v);
    f.sweep();
}

#[test]
fn standing_refusals_enforce_identity_install_tree_and_test_only_keys() {
    // 1. Terminal subject (this test process) is refused `IdentityNotStandingCapable`.
    let f = Fixture::new();
    let p = RunRequestParams {
        manifest: f.manifest.clone(),
        profile: None,
        refs: Vec::new(),
        env_file: None,
        argv: vec!["./emit".to_owned()],
        claims: Vec::new(),
        launch: None,
        bridge: None,
        fds: Vec::new(),
    };
    let req_id = match client(&f.home).run_request(&p).unwrap().decision {
        DecisionView::Pending { request } => request,
        other => panic!("expected pending, got {other:?}"),
    };
    assert_eq!(
        rpc_kind(f.approve_standing(&req_id, 86_400).unwrap_err()).0,
        ErrorKind::IdentityNotStandingCapable
    );

    // 2. Agent with code_selecting_env (`BUN_BE_BUN=1` on opencode) is refused
    //    `IdentityNotStandingCapable`.
    let mut tainted = AgentWorker::start(&f.home, &f.agent_bin, &[("BUN_BE_BUN", "1")]);
    let r_tainted = tainted.request(&f.manifest, None, &[]);
    let tainted_id = r_tainted["request"].as_str().unwrap();
    assert_eq!(
        rpc_kind(f.approve_standing(tainted_id, 86_400).unwrap_err()).0,
        ErrorKind::IdentityNotStandingCapable
    );
    drop(tainted);

    // 3. Project with a `live` key (`openai/acme-web` in `common::MANIFEST`) is
    //    refused `LiveNotTicked` when `--standing` is requested without ticking.
    let live_manifest = project(&f.home, "acme-live", common::MANIFEST);
    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);
    let r_live = agent.request(live_manifest.to_str().unwrap(), None, &[]);
    let live_id = r_live["request"].as_str().unwrap();
    assert_eq!(
        rpc_kind(f.approve_standing(live_id, 86_400).unwrap_err()).0,
        ErrorKind::LiveNotTicked
    );
    drop(agent);
    f.sweep();

    // 4. Under Linux standing rules (`ENVCLOAK_TEST_LINUX_STANDING=1`), an agent
    //    binary outside its builtin `install_trees` is refused
    //    `IdentityOutsideInstallTree`.
    let f_linux = Fixture::with_daemon_env(&[(envcloak_sys::testing::LINUX_STANDING, "1")]);
    let outside_bin = f_linux.home.home().join("outside/opencode");
    install_agent_binary(&outside_bin, "opencode");
    let mut outside_agent = AgentWorker::start(&f_linux.home, &outside_bin, &[]);
    let r_out = outside_agent.request(&f_linux.manifest, None, &[]);
    let out_id = r_out["request"].as_str().unwrap();
    assert_eq!(
        rpc_kind(f_linux.approve_standing(out_id, 86_400).unwrap_err()).0,
        ErrorKind::IdentityOutsideInstallTree
    );
    drop(outside_agent);
    f_linux.sweep();
}

#[test]
fn items_reclassify_to_live_ends_standing_record_and_session_grant() {
    let f = Fixture::new();
    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);
    let r1 = agent.request(&f.manifest, None, &[]);
    let req_id = r1["request"].as_str().unwrap();
    f.approve_standing(req_id, 86_400).unwrap();

    // Mint a derived session grant.
    let r2 = agent.request(&f.manifest, None, &[]);
    assert_eq!(r2["decision"], "covered", "{r2}");
    assert_eq!(f.standing_list().standing.len(), 1);
    assert_eq!(client(&f.home).grants_list().unwrap().grants.len(), 1);

    // Reclassify `stripe/acme-web` from `test` to `live` (tightening: no proof).
    let mut c = client(&f.home);
    let updated = c.items_reclassify_live("stripe/acme-web", &[]).unwrap();
    assert_eq!(updated.classification, ClassificationView::Live);

    // The derived session grant is ended, and the standing record stops minting
    // because find_matching recomputes Classification::Test at use.
    assert_eq!(f.standing_list().standing.len(), 1);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // Subsequent agent request is pending again, not covered, and mints no grant.
    let r3 = agent.request(&f.manifest, None, &[]);
    assert_eq!(r3["decision"], "pending", "{r3}");
    assert!(c.grants_list().unwrap().grants.is_empty());
    drop(agent);
    f.sweep();
}

#[test]
fn reregistered_managed_launch_revision_is_not_matched_by_older_standing_record() {
    let f = Fixture::new();
    let bin_dir = f.home.root().join("acme-test/bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let srv_bin = bin_dir.join("ec-launch-fixture");
    std::fs::copy(testkit_bin("ec-launch-fixture"), &srv_bin).unwrap();

    let make_reg = |pass: SecretBytes| ManagedRegisterParams {
        name: "opencode/fixture-srv".to_owned(),
        manifest: f.manifest.clone(),
        server: ManagedServerDecl::Stdio {
            launch: LaunchDeclParams {
                argv: vec![srv_bin.to_str().unwrap().to_owned()],
                cwd: Some(f.home.root().join("acme-test").to_str().unwrap().to_owned()),
                env: Vec::new(),
                path_env: None,
            },
        },
        passphrase: WireSecret::new(pass),
        claims: Vec::new(),
    };
    let v1 = client(&f.home)
        .register_managed(&make_reg(f.pass()))
        .unwrap();
    let launch_id = v1.launch.as_deref().unwrap();
    assert_eq!(v1.revision, Some(1));

    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);
    let r1 = agent.request(&f.manifest, Some(launch_id), &[]);
    assert_eq!(r1["decision"], "pending", "{r1}");
    let req_id = r1["request"].as_str().unwrap();
    f.approve_standing(req_id, 86_400).unwrap();
    assert_eq!(f.standing_list().standing.len(), 1);
    assert_eq!(f.standing_list().standing[0].revision, Some(1));

    // Re-registering the managed launch bumps its revision to 2; the standing
    // record remains bound to revision 1 and no longer matches revision 2.
    let v2 = client(&f.home)
        .register_managed(&make_reg(f.pass()))
        .unwrap();
    assert_eq!(v2.launch.as_deref(), Some(launch_id));
    assert_eq!(v2.revision, Some(2));
    assert_eq!(f.standing_list().standing.len(), 1);
    assert_eq!(f.standing_list().standing[0].revision, Some(1));

    // Agent request for the launch is now pending, not started.
    let r2 = agent.request(&f.manifest, Some(launch_id), &[]);
    assert_eq!(r2["decision"], "pending", "{r2}");
    drop(agent);
    f.sweep();
}

#[test]
fn policy_epoch_detects_delete_corrupt_and_rollback_and_confirm_recovers() {
    let mut f = Fixture::new();
    let second_manifest = project(&f.home, "acme-test-2", TEST_ONLY_MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();
    let third_manifest = project(&f.home, "acme-test-3", TEST_ONLY_MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();
    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);

    // Create two standing approvals (generation 1, then generation 2).
    let r1 = agent.request(&f.manifest, None, &[]);
    let s1 = f
        .approve_standing(r1["request"].as_str().unwrap(), 86_400)
        .unwrap()
        .standing
        .unwrap();

    // Snapshot vault.db (and its WAL) at generation 1 (with s1 present).
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    let vault_db = VaultPaths::under(data_dir(&f.home)).db;
    let mut wal_os = vault_db.as_os_str().to_owned();
    wal_os.push("-wal");
    let vault_wal = PathBuf::from(wal_os);
    let snap_gen1 = f.home.home().join("vault-gen1.db");
    let snap_gen1_wal = f.home.home().join("vault-gen1.db-wal");
    std::fs::copy(&vault_db, &snap_gen1).unwrap();
    if vault_wal.exists() {
        std::fs::copy(&vault_wal, &snap_gen1_wal).unwrap();
    }

    f.d = Fixture::start_daemon(&f.home, &f.pause_release, &[]);
    client(&f.home).unlock(f.pass(), &[]).unwrap();

    let r2 = agent.request(&second_manifest, None, &[]);
    let s2 = f
        .approve_standing(r2["request"].as_str().unwrap(), 86_400)
        .unwrap()
        .standing
        .unwrap();
    assert_ne!(s1, s2);
    assert_eq!(f.standing_list().standing.len(), 2);

    let sidecar_path = data_dir(&f.home).join("policy-epoch");
    assert!(sidecar_path.is_file());

    // Case 1: Deleted `<data>/policy-epoch` while generation > 0 enters
    // `PolicyEpochUnverified`, refusing standing evaluation (`run.request`
    // for a covered project returns `policy_epoch_unverified`) and refusing
    // new standing approvals with `-32046` (`policy_epoch_unverified`), while
    // `standing.revoke --id` remains allowed.
    std::fs::remove_file(&sidecar_path).unwrap();
    assert!(f.standing_list().policy_epoch_unverified);
    assert!(
        client(&f.home)
            .status()
            .unwrap()
            .approvals
            .policy_epoch_unverified
    );

    // Clear active session grants; agent request for `f.manifest` (which would
    // match standing record `s1`) is refused `policy_epoch_unverified`, and a
    // request for `third_manifest` (which has no standing record) is pending
    // whose `--standing` approval is refused `PolicyEpochUnverified`.
    client(&f.home).grants_revoke(None).unwrap();
    let r_would_match = agent.request(&f.manifest, None, &[]);
    assert_eq!(r_would_match["decision"], "error", "{r_would_match}");
    assert_eq!(
        r_would_match["kind"],
        ErrorKind::PolicyEpochUnverified.token(),
        "{r_would_match}"
    );
    let r_unv = agent.request(&third_manifest, None, &[]);
    assert_eq!(r_unv["decision"], "pending", "{r_unv}");
    assert_eq!(
        rpc_kind(
            f.approve_standing(r_unv["request"].as_str().unwrap(), 86_400)
                .unwrap_err()
        )
        .0,
        ErrorKind::PolicyEpochUnverified
    );

    // `standing.confirm` refuses a wrong passphrase (`WrongPassphrase`) and
    // exits `PolicyEpochUnverified` with the right one.
    let bad_pass = SecretBytes::copy_from(b"definitely not the vault passphrase");
    assert_eq!(
        rpc_kind(f.standing_confirm(bad_pass).unwrap_err()).0,
        ErrorKind::WrongPassphrase
    );
    assert!(f.standing_list().policy_epoch_unverified);

    let confirmed = f.standing_confirm(f.pass()).unwrap();
    assert_eq!(confirmed.records, 2);
    assert_eq!(confirmed.generation, 3);
    assert!(!f.standing_list().policy_epoch_unverified);
    assert_eq!(agent.request(&f.manifest, None, &[])["decision"], "covered");

    // Case 2: Corrupted `<data>/policy-epoch` across restart enters
    // `PolicyEpochUnverified`. Selective revoke of one record (`s2`) while
    // `PolicyEpochUnverified` removes `s2` from the vault but preserves
    // `PolicyEpochUnverified` (so `s1` stays paused and restart does not
    // auto-heal without a passphrase proof).
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    std::fs::write(&sidecar_path, b"corrupted-sidecar-bytes").unwrap();
    f.d = Fixture::start_daemon(&f.home, &f.pause_release, &[]);
    client(&f.home).unlock(f.pass(), &[]).unwrap();
    assert!(f.standing_list().policy_epoch_unverified);
    assert_eq!(f.standing_list().standing.len(), 2);

    let rev_s2 = f.standing_revoke_id(&s2).unwrap();
    assert_eq!(rev_s2.revoked, 1);
    assert!(f.standing_list().policy_epoch_unverified);
    assert_eq!(f.standing_list().standing.len(), 1);
    let r_still_paused = agent.request(&f.manifest, None, &[]);
    assert_eq!(r_still_paused["decision"], "error");
    assert_eq!(
        r_still_paused["kind"],
        ErrorKind::PolicyEpochUnverified.token()
    );

    // Confirming the remaining record raises generation to 4 and restores Verified.
    let confirmed_after_selective = f.standing_confirm(f.pass()).unwrap();
    assert_eq!(confirmed_after_selective.records, 1);
    assert_eq!(confirmed_after_selective.generation, 4);
    assert!(!f.standing_list().policy_epoch_unverified);

    // Case 3: Rollback of `vault.db` (and its WAL) back to the generation-1
    // snapshot while `<data>/policy-epoch` is at generation 4 enters
    // `PolicyEpochUnverified` at unlock.
    f.d.signal("-TERM");
    assert!(f.d.wait_exit(Duration::from_secs(30)).is_some());
    std::fs::copy(&snap_gen1, &vault_db).unwrap();
    if snap_gen1_wal.exists() {
        std::fs::copy(&snap_gen1_wal, &vault_wal).unwrap();
    } else {
        let _ = std::fs::remove_file(&vault_wal);
    }
    f.d = Fixture::start_daemon(&f.home, &f.pause_release, &[]);
    client(&f.home).unlock(f.pass(), &[]).unwrap();
    assert!(f.standing_list().policy_epoch_unverified);
    assert_eq!(f.standing_list().standing.len(), 1);

    // Revoking the last standing record (`s1`) empties the standing set,
    // advances generation past the sidecar floor (to 5), and clears
    // `PolicyEpochUnverified`.
    let rev = f.standing_revoke_id(&s1).unwrap();
    assert_eq!(rev.revoked, 1);
    assert!(f.standing_list().standing.is_empty());
    assert!(!f.standing_list().policy_epoch_unverified);
    drop(agent);
    f.sweep();
}

#[test]
fn selective_revoke_transaction_crash_points_reconcile_cleanly() {
    let mut f = Fixture::new();
    let m2 = project(&f.home, "acme-test-b", TEST_ONLY_MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();
    let m3 = project(&f.home, "acme-test-c", TEST_ONLY_MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();
    let m4 = project(&f.home, "acme-test-d", TEST_ONLY_MANIFEST)
        .to_str()
        .unwrap()
        .to_owned();

    let mut agent = AgentWorker::start(&f.home, &f.agent_bin, &[]);
    let mut ids = Vec::new();
    for manifest in [&f.manifest, &m2, &m3, &m4] {
        let r = agent.request(manifest, None, &[]);
        let id = f
            .approve_standing(r["request"].as_str().unwrap(), 86_400)
            .unwrap()
            .standing
            .unwrap();
        ids.push(id);
    }
    drop(agent);
    assert_eq!(f.standing_list().standing.len(), 4);

    // 1. Crash BEFORE step 1 (`standing.before_vault_commit`): vault commit did
    //    not happen; after restart + unlock, all 4 standing records remain and
    //    `policy_epoch_unverified` is false.
    f.restart_daemon(&[(
        envcloak_sys::testing::PAUSE_SITE,
        "standing.before_vault_commit",
    )]);
    client(&f.home).unlock(f.pass(), &[]).unwrap();
    let paths = run_paths(&f.home);
    let target_id = ids[0].clone();
    let t = std::thread::spawn(move || {
        let _ = Client::connect(&paths)
            .unwrap()
            .standing_revoke(&StandingRevokeParams {
                id: Some(target_id),
                ..StandingRevokeParams::default()
            });
    });
    f.wait_paused("standing.before_vault_commit");
    f.kill_and_restart_daemon(&[]);
    let _ = t.join();
    client(&f.home).unlock(f.pass(), &[]).unwrap();
    let list = f.standing_list();
    assert!(!list.policy_epoch_unverified);
    assert_eq!(list.standing.len(), 4);

    // 2. Crash BETWEEN step 1 and step 2 (`standing.after_vault_commit`),
    //    BETWEEN step 2 and step 3 (`standing.after_sidecar_write`), and
    //    AFTER step 3 (`standing.after_sidecar_sync`):
    //    vault committed the deletion (generation advanced), and reconcile
    //    heals `<data>/policy-epoch` at unlock so `policy_epoch_unverified`
    //    is false and the revoked record is gone.
    for (site, idx, remaining) in [
        ("standing.after_vault_commit", 0usize, 3usize),
        ("standing.after_sidecar_write", 1usize, 2usize),
        ("standing.after_sidecar_sync", 2usize, 1usize),
    ] {
        f.restart_daemon(&[(envcloak_sys::testing::PAUSE_SITE, site)]);
        client(&f.home).unlock(f.pass(), &[]).unwrap();
        let paths = run_paths(&f.home);
        let target_id = ids[idx].clone();
        let t = std::thread::spawn(move || {
            let _ = Client::connect(&paths)
                .unwrap()
                .standing_revoke(&StandingRevokeParams {
                    id: Some(target_id),
                    ..StandingRevokeParams::default()
                });
        });
        f.wait_paused(site);
        f.kill_and_restart_daemon(&[]);
        let _ = t.join();
        client(&f.home).unlock(f.pass(), &[]).unwrap();
        let list = f.standing_list();
        assert!(
            !list.policy_epoch_unverified,
            "site {site} left policy_epoch_unverified"
        );
        assert_eq!(list.standing.len(), remaining, "site {site}");
        assert!(
            list.standing.iter().all(|r| r.id != ids[idx]),
            "site {site} did not revoke {}",
            ids[idx]
        );
    }

    // Revoke all remaining.
    assert_eq!(f.standing_revoke_all().unwrap().revoked, 1);
    assert!(f.standing_list().standing.is_empty());
    f.sweep();
}
