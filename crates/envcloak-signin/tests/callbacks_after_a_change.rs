//! Callbacks that meet a change of the world before any other call (b9,
//! b17 at the model level): an independent check of the operation store,
//! whose schedule and assertions were written apart from `tests/store.rs`
//! and `tests/enumeration.rs` and share only the fixture in `common`.
//!
//! For each of seven entry points (the password permit, the code permit,
//! the worker's capture, the claim of the declared state, the identity
//! response, the acknowledgement of publication and the per-call check)
//! and each of twenty-two events, a fresh operation is brought to the
//! entry point, the event happens, and the entry point is called at once.
//! The events: none; with no call after it, each change SPEC §10b's
//! "Match" rules 1 to 5 and "A grant ends on" list, and §6.8's sign-in
//! scope, can make to the world (the root's exit, a vault epoch, a login,
//! target or adapter revision, a replaced browser, the requester's exit, a
//! clock past the attempt's and the session's deadlines, the requester
//! reparented out of the root's tree, a known agent between them, the
//! project replaced, gone or reconfigured, the login item deleted or made
//! live, the target removed, its adapter replaced, its limits edited); the
//! owner's cancel; lock; and revocation of the authorization. With no
//! event the call is allowed: the positive control for each entry point.
//! After every event it is refused, the operation has stopped for the
//! event's own reason, the stop keeps the delivered flag its phase gives,
//! no password or code was spent, and a lock or a revocation ended the
//! authorization, which is first checked to be live so that check cannot
//! pass on an empty store. Each silent change is checked to be still
//! unseen by the store before the call, so the call is the first to see
//! it. The worker and supervisor ids are the ones the store's start
//! effects handed out.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{DAEMON, MCP, ROOT, Spec, TestWorld, at, identity, scope};
use envcloak_policy::Now;
use envcloak_signin::{
    AdapterId, Authorization, Channel, Effect, Environment, Fresh, Limits, Nonce, OperationKey,
    OperationStore, Options, PublishDecision, Request, RequestId, Step, StopReason, SupervisorId,
    WorkerId,
};
use serde_json::json;

/// The store's effects since the last call, keeping the ids they hand out.
fn take(
    store: &mut OperationStore,
    worker: &mut Option<WorkerId>,
    supervisor: &mut Option<SupervisorId>,
) {
    for e in store.drain_effects() {
        match e {
            Effect::StartAttempt { worker: w, .. } => *worker = Some(w),
            Effect::StartSupervisor { supervisor: s, .. } => *supervisor = Some(s),
            Effect::TearDown { .. } => {}
        }
    }
}

/// A change made with no call after it, and the reason it stops an
/// operation for.
type Silent = (fn(&mut TestWorld, &mut Now), StopReason);

/// Every change of the world or the clock the store is to see at the next
/// call, whatever that call is.
fn silent() -> Vec<Silent> {
    vec![
        (
            |w, _| {
                w.exited.insert(ROOT);
            },
            StopReason::RootExited,
        ),
        (|w, _| w.epochs.vault += 1, StopReason::EpochChanged),
        (|w, _| w.login += 1, StopReason::RevisionChanged),
        (|w, _| w.target += 1, StopReason::RevisionChanged),
        (|w, _| w.adapter += 1, StopReason::RevisionChanged),
        (|w, _| w.browser += 1, StopReason::RecipientReplaced),
        (
            |w, _| {
                w.exited.insert(MCP);
            },
            StopReason::RecipientReplaced,
        ),
        // Past the attempt's timeout (900 s) and the session's lifetime
        // (3,600 s), within the authorization's window (4 h): the deadline
        // is the attempt's or the session's own.
        (|_, now| *now = at(5000), StopReason::AttemptTimedOut),
        (|w, _| w.leave_root(), StopReason::SubjectIneligible),
        (|w, _| w.agent_between(), StopReason::SubjectIneligible),
        (|w, _| w.project.ino += 1, StopReason::ProjectChanged),
        (|w, _| w.project_gone = true, StopReason::ProjectChanged),
        (|w, _| w.project.config[0] ^= 1, StopReason::ProjectChanged),
        (|w, _| w.login_deleted = true, StopReason::RevisionChanged),
        (
            |w, _| w.environment = Environment::Live,
            StopReason::RevisionChanged,
        ),
        (|w, _| w.target_removed = true, StopReason::RevisionChanged),
        (
            |w, _| w.adapter_id = AdapterId::from_bytes([0x52; 16]),
            StopReason::RevisionChanged,
        ),
        (
            |w, _| {
                let l = scope(&Spec::dev(), w).limits().clone();
                let shorter = Limits::new(
                    l.tier(),
                    l.attempts(),
                    l.approval(),
                    l.attempt_timeout(),
                    l.session_lifetime() - Duration::from_secs(1),
                )
                .unwrap();
                w.limits_edit = Some((l, shorter));
            },
            StopReason::LimitsChanged,
        ),
    ]
}

#[test]
fn every_callback_after_an_unseen_change_is_refused() {
    let silent = silent();
    let (cancel, lock, revoke) = (silent.len() + 1, silent.len() + 2, silent.len() + 3);
    let mut rows = Vec::new();
    for stage in 0..7 {
        for event in 0..=revoke {
            let mut world = TestWorld::new();
            let spec = Spec::dev();
            let mut store = OperationStore::new(DAEMON);
            let id = RequestId::from_bytes([1; 16]);
            store
                .lookup_or_reserve(
                    Request {
                        key: OperationKey::parse("barrier").unwrap(),
                        scope: scope(&spec, &world),
                    },
                    Fresh {
                        request: id,
                        nonce: Nonce::from_bytes([2; 32]),
                    },
                    &at(0),
                    &world,
                )
                .unwrap();
            let options = Options::default_for(store.operation(&id).unwrap().scope().limits());
            let digest = store
                .statement(&id, options, &at(0), &world)
                .unwrap()
                .digest();
            store
                .approve(&id, options, &digest, &at(0), &world)
                .unwrap();
            let (mut worker, mut supervisor) = (None, None);
            take(&mut store, &mut worker, &mut supervisor);
            let worker = worker.expect("the approval started the attempt");
            if stage >= 3 {
                store.worker_captured(&id, &worker, &at(0), &world).unwrap();
            }
            let mut unused = None;
            take(&mut store, &mut unused, &mut supervisor);
            let channel = supervisor.map(Channel::Supervisor);
            if stage >= 4 {
                store
                    .inject_state(&channel.unwrap(), &id, &at(0), &world)
                    .unwrap();
            }
            if stage >= 5 {
                assert_eq!(
                    store
                        .identity_response(
                            &channel.unwrap(),
                            &id,
                            &identity(spec.role),
                            &at(0),
                            &world
                        )
                        .unwrap(),
                    PublishDecision::Publish
                );
            }
            if stage >= 6 {
                store
                    .published(&channel.unwrap(), &id, &at(0), &world)
                    .unwrap();
            }
            store.drain_effects();
            let authorization_live_before_event =
                store.authorizations().count() == 1 && store.authorizations().all(|a| !a.ended());
            let auth = store.operation(&id).unwrap().authorization().unwrap();
            let mut now = at(0);
            let is_silent = (1..=silent.len()).contains(&event);
            let reason = match event {
                0 => None,
                e if e == cancel => {
                    store.cancel(&ROOT, &id, &now, &world).unwrap();
                    Some(StopReason::Cancelled)
                }
                e if e == lock => {
                    store.lock(&now, &world);
                    Some(StopReason::Locked)
                }
                e if e == revoke => {
                    assert!(store.revoke(&auth, &now, &world));
                    Some(StopReason::Revoked)
                }
                e => {
                    let (change, why) = silent[e - 1];
                    change(&mut world, &mut now);
                    // A deadline passed: the attempt's before the decision,
                    // the session's after it.
                    Some(match why {
                        StopReason::AttemptTimedOut if stage >= 5 => StopReason::SessionExpired,
                        why => why,
                    })
                }
            };
            let unseen_before_entry = is_silent && store.operation(&id).unwrap().stop().is_none();
            let allowed = match stage {
                0 => store
                    .permit(&id, &worker, Step::Password, &now, &world)
                    .is_ok(),
                1 => store.permit(&id, &worker, Step::Code, &now, &world).is_ok(),
                2 => store.worker_captured(&id, &worker, &now, &world).is_ok(),
                3 => store
                    .inject_state(&channel.unwrap(), &id, &now, &world)
                    .is_ok(),
                4 => store
                    .identity_response(&channel.unwrap(), &id, &identity(spec.role), &now, &world)
                    .is_ok_and(|d| d == PublishDecision::Publish),
                5 => store
                    .published(&channel.unwrap(), &id, &now, &world)
                    .is_ok(),
                6 => store.check(&channel.unwrap(), &id, &now, &world).is_ok(),
                _ => unreachable!(),
            };
            let op = store.operation(&id).unwrap();
            let stop = op.stop();
            let expected_allowed = event == 0;
            let lock_ended_authorizations = (event != lock && event != revoke)
                || store.authorizations().all(Authorization::ended);
            let own_reason = stop.map(|s| s.reason) == reason;
            let no_extra_spend = event == 0 || (op.passwords() == 0 && op.codes() == 0);
            let delivered = stage >= 5;
            let delivery_retained = event == 0 || stop.is_some_and(|s| s.delivered == delivered);
            rows.push(json!({
                "stage": stage,
                "event": event,
                "allowed": allowed,
                "expected_allowed": expected_allowed,
                "contract_passed": authorization_live_before_event
                    && allowed == expected_allowed
                    && no_extra_spend
                    && delivery_retained
                    && lock_ended_authorizations
                    && own_reason
                    && (!is_silent || unseen_before_entry),
            }));
        }
    }
    assert_eq!(rows.len(), 7 * (silent.len() + 4));
    let live = rows
        .iter()
        .filter(|r| r["event"] == 0 && r["allowed"] == true);
    assert_eq!(live.count(), 7);
    for row in rows {
        assert_eq!(
            row["contract_passed"], true,
            "stage {} event {}",
            row["stage"], row["event"]
        );
    }
}
