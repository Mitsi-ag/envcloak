//! One generation controls its callbacks and its cleanup (b9, b14, b17 and
//! the no-refund and serialization parts of b8, at the model level): an
//! independent check of the operation store, whose schedule and assertions
//! were written apart from `tests/store.rs` and `tests/enumeration.rs` and
//! share only the fixture in `common`.
//!
//! Callbacks: for each worker callback (the password and code permits, the
//! capture, the failure) and each supervisor message (the claim, the
//! identity response, publication, the per-call check), the operation's
//! own id is allowed (the positive control) and another live attempt's
//! id, another generation's supervisor, a client in the owner root and a
//! sibling client are refused, each leaving the whole store as it was.
//! Both attempts run on different accounts with different generations.
//!
//! Cleanup: for each stop (cancel, the owner's end, the worker's failure),
//! with the close first reported failed or not, and confirmed before or
//! after the retry window: exactly one teardown is asked for; an attempt
//! queued on the same account does not start until the close is confirmed,
//! while an attempt on another account keeps running;
//! reports for another generation, another request or an unknown one are
//! discarded and change nothing; an unconfirmed close outlives the retry
//! window; only the exact confirmation starts exactly one new generation;
//! a duplicate confirmation is discarded; the old generation's callbacks
//! do not reach the new attempt; the credit is not given back; and the new
//! attempt's own password permit is allowed (the positive control). The
//! worker and supervisor ids are the ones the store's start effects handed
//! out.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use common::{DAEMON, ROOT, SIBLING, Spec, TestWorld, at, identity, label, scope};
use envcloak_core::vault::ItemId;
use envcloak_signin::{
    AttemptFailure, Channel, Cleanup, Discarded, Effect, Fresh, Lookup, Nonce, Operation,
    OperationKey, OperationStore, Options, Phase, PublishDecision, RETRY_WINDOW, Request,
    RequestId, SignInScope, Step, SupervisorId, WorkerId,
};
use serde_json::json;

/// The ids the store's start effects handed out, by request.
#[derive(Default)]
struct Ids {
    workers: BTreeMap<RequestId, WorkerId>,
    supervisors: BTreeMap<RequestId, SupervisorId>,
}

/// The store's effects since the last call, keeping the ids they hand out.
fn take(store: &mut OperationStore, ids: &mut Ids) -> Vec<Effect> {
    let effects = store.drain_effects();
    for e in &effects {
        match *e {
            Effect::StartAttempt {
                request, worker, ..
            } => {
                ids.workers.insert(request, worker);
            }
            Effect::StartSupervisor {
                request,
                supervisor,
            } => {
                ids.supervisors.insert(request, supervisor);
            }
            Effect::TearDown { .. } => {}
        }
    }
    effects
}

/// Another login item for another account at the same app: an attempt
/// the first one's never waits for.
fn separate_account(original: &SignInScope) -> SignInScope {
    let mut account = original.account().clone();
    account.login_item = ItemId::from_bytes([0x55; 16]);
    account.account = label("viewer@fixture.test");
    SignInScope::new(
        original.subject().clone(),
        original.project().clone(),
        account,
        original.target().clone(),
        original.delivery().clone(),
        original.limits().clone(),
        *original.epochs(),
    )
    .unwrap()
}

fn reserve(
    store: &mut OperationStore,
    ids: &mut Ids,
    world: &TestWorld,
    spec: &Spec,
    tag: u8,
    separate: bool,
) -> RequestId {
    let id = RequestId::from_bytes([tag; 16]);
    let normal = scope(spec, world);
    let sc = if separate {
        separate_account(&normal)
    } else {
        normal
    };
    let lookup = store
        .lookup_or_reserve(
            Request {
                key: OperationKey::parse(&format!("key-{tag}")).unwrap(),
                scope: sc,
            },
            Fresh {
                request: id,
                nonce: Nonce::from_bytes([tag; 32]),
            },
            &at(0),
            world,
        )
        .unwrap();
    assert!(matches!(lookup, Lookup::Reserved(_)));
    if store.operation(&id).unwrap().phase() == Phase::PendingApproval {
        let options = Options::default_for(store.operation(&id).unwrap().scope().limits());
        let digest = store
            .statement(&id, options, &at(0), world)
            .unwrap()
            .digest();
        store.approve(&id, options, &digest, &at(0), world).unwrap();
    }
    take(store, ids);
    id
}

fn op(store: &OperationStore, id: &RequestId) -> Operation {
    store.operation(id).unwrap().clone()
}

fn callbacks() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for stage in 0..8u8 {
        let modes = if stage < 4 { 2 } else { 4 };
        for mode in 0..modes {
            let world = TestWorld::new();
            let spec = Spec::dev();
            let mut store = OperationStore::new(DAEMON);
            let mut ids = Ids::default();
            let a = reserve(&mut store, &mut ids, &world, &spec, 1, false);
            let c = reserve(&mut store, &mut ids, &world, &spec, 2, true);
            let (wa, wc) = (ids.workers[&a], ids.workers[&c]);
            // `c` captures, so its generation's supervisor exists.
            store.worker_captured(&c, &wc, &at(0), &world).unwrap();
            take(&mut store, &mut ids);
            let sc = ids.supervisors[&c];
            let controls = wa.generation() != wc.generation()
                && op(&store, &a).phase() == Phase::AttemptRunning
                && op(&store, &c).phase() == Phase::Captured;
            if stage >= 4 {
                store.worker_captured(&a, &wa, &at(0), &world).unwrap();
                take(&mut store, &mut ids);
            }
            let own = ids.supervisors.get(&a).map(|s| Channel::Supervisor(*s));
            if stage >= 5 {
                store
                    .inject_state(&own.unwrap(), &a, &at(0), &world)
                    .unwrap();
            }
            if stage >= 6 {
                assert_eq!(
                    store
                        .identity_response(&own.unwrap(), &a, &identity(spec.role), &at(0), &world)
                        .unwrap(),
                    PublishDecision::Publish
                );
            }
            if stage >= 7 {
                store.published(&own.unwrap(), &a, &at(0), &world).unwrap();
            }
            take(&mut store, &mut ids);
            let before = store.clone();
            let worker = if mode == 0 { wa } else { wc };
            let channel = match mode {
                0 => own,
                1 => Some(Channel::Supervisor(sc)),
                2 => Some(Channel::Client(ROOT)),
                _ => Some(Channel::Client(SIBLING)),
            };
            let allowed = match stage {
                0 => store
                    .permit(&a, &worker, Step::Password, &at(0), &world)
                    .is_ok(),
                1 => store
                    .permit(&a, &worker, Step::Code, &at(0), &world)
                    .is_ok(),
                2 => store.worker_captured(&a, &worker, &at(0), &world).is_ok(),
                3 => store
                    .worker_failed(&a, &worker, AttemptFailure::WorkerLost, &at(0), &world)
                    .is_ok(),
                4 => store
                    .inject_state(&channel.unwrap(), &a, &at(0), &world)
                    .is_ok(),
                5 => store
                    .identity_response(&channel.unwrap(), &a, &identity(spec.role), &at(0), &world)
                    .is_ok_and(|p| p == PublishDecision::Publish),
                6 => store
                    .published(&channel.unwrap(), &a, &at(0), &world)
                    .is_ok(),
                _ => store.check(&channel.unwrap(), &a, &at(0), &world).is_ok(),
            };
            let expected_allowed = mode == 0;
            let refused_unchanged = mode == 0 || store == before;
            rows.push(json!({
                "family": 0,
                "stage": stage,
                "mode": mode,
                "allowed": allowed,
                "contract_passed": controls
                    && allowed == expected_allowed
                    && refused_unchanged,
            }));
        }
    }
    rows
}

#[allow(clippy::too_many_lines)]
fn cleanup() -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    for stop in 0..3u8 {
        for failed in [false, true] {
            for late in [false, true] {
                let world = TestWorld::new();
                let spec = Spec {
                    approval: Duration::from_secs(86400),
                    attempt_timeout: Duration::from_secs(3600),
                    ..Spec::dev()
                };
                let mut store = OperationStore::new(DAEMON);
                let mut ids = Ids::default();
                let a = reserve(&mut store, &mut ids, &world, &spec, 1, false);
                let b = reserve(&mut store, &mut ids, &world, &spec, 2, false);
                let c = reserve(&mut store, &mut ids, &world, &spec, 3, true);
                let (wa, wc) = (ids.workers[&a], ids.workers[&c]);
                // The supervisor id `a`'s generation would have, minted by
                // a capture in a copy of the store: `a` itself is stopped
                // while it runs.
                let old_supervisor = {
                    let mut copy = store.clone();
                    copy.worker_captured(&a, &wa, &at(0), &world).unwrap();
                    let mut copy_ids = Ids::default();
                    take(&mut copy, &mut copy_ids);
                    copy_ids.supervisors[&a]
                };
                let auth = op(&store, &a).authorization().unwrap();
                let queued_control = op(&store, &b).phase() == Phase::Approved
                    && op(&store, &b).generation().is_none();
                let independent_control = op(&store, &c).phase() == Phase::AttemptRunning
                    && wc.generation() != wa.generation();
                let budget_control = op(&store, &b).authorization() == Some(auth)
                    && store
                        .authorization(&auth)
                        .is_some_and(|a| a.credits() - a.remaining() == 2);
                take(&mut store, &mut ids);
                match stop {
                    0 => {
                        store.cancel(&ROOT, &a, &at(0), &world).unwrap();
                    }
                    1 => {
                        store.end(&ROOT, &a, &at(0), &world).unwrap();
                    }
                    _ => {
                        store
                            .worker_failed(&a, &wa, AttemptFailure::WorkerLost, &at(0), &world)
                            .unwrap();
                    }
                }
                let teardown = take(&mut store, &mut ids);
                let exact_teardown = matches!(
                    teardown.as_slice(),
                    [Effect::TearDown { request, generation, delivered: false }]
                        if *request == a && *generation == wa.generation()
                );
                let held_after_stop = op(&store, &b).phase() == Phase::Approved
                    && op(&store, &b).generation().is_none();
                let mut wrong_ack_unchanged = true;
                let unknown = RequestId::from_bytes([0xee; 16]);
                for (request, worker) in [(a, wc), (b, wa), (unknown, wa)] {
                    let before = store.clone();
                    let mut probe = before.clone();
                    wrong_ack_unchanged &=
                        probe.cleanup_result(&request, &worker, true, &at(0), &world)
                            == Err(Discarded)
                            && probe == before;
                }
                let mut failure_control = true;
                if failed {
                    failure_control = store.cleanup_result(&a, &wa, false, &at(0), &world)
                        == Ok(())
                        && op(&store, &a).cleanup() == Cleanup::Failed;
                    let before = store.clone();
                    failure_control &= store.cleanup_result(&a, &wa, false, &at(0), &world)
                        == Err(Discarded)
                        && store == before;
                }
                let now = at(if late {
                    RETRY_WINDOW.as_secs() * 2 + 1
                } else {
                    0
                });
                store.reconcile(&now, &world);
                let unconfirmed_retained = store.operation(&a).is_some_and(|o| {
                    o.cleanup()
                        == if failed {
                            Cleanup::Failed
                        } else {
                            Cleanup::Pending
                        }
                });
                let queued_held = op(&store, &b).phase() == Phase::Approved
                    && op(&store, &b).generation().is_none();
                let independent_still_live = op(&store, &c).phase() == Phase::AttemptRunning;
                take(&mut store, &mut ids);
                let confirmed = store.cleanup_result(&a, &wa, true, &now, &world) == Ok(());
                let effects = take(&mut store, &mut ids);
                let starts = effects
                    .iter()
                    .filter(|e| matches!(e, Effect::StartAttempt { request, .. } if *request == b))
                    .count();
                let gb = op(&store, &b).generation();
                let fresh_start = gb.is_some_and(|g| g != wa.generation() && g != wc.generation())
                    && op(&store, &b).phase() == Phase::AttemptRunning
                    && starts == 1
                    && effects.len() == 1;
                let swept_correctly = if late {
                    store.operation(&a).is_none()
                } else {
                    store
                        .operation(&a)
                        .is_some_and(|o| o.cleanup() == Cleanup::Done)
                };
                let before = store.clone();
                let duplicate_refused = store.cleanup_result(&a, &wa, true, &now, &world)
                    == Err(Discarded)
                    && store == before;
                let mut stale_unchanged = true;
                for stage in 0..4 {
                    let before = store.clone();
                    let mut probe = before.clone();
                    let refused = match stage {
                        0 => probe.permit(&b, &wa, Step::Password, &now, &world).is_err(),
                        1 => probe.worker_captured(&b, &wa, &now, &world).is_err(),
                        2 => probe
                            .worker_failed(&b, &wa, AttemptFailure::WorkerLost, &now, &world)
                            .is_err(),
                        _ => probe
                            .inject_state(&Channel::Supervisor(old_supervisor), &b, &now, &world)
                            .is_err(),
                    };
                    stale_unchanged &= refused && probe == before;
                }
                let no_refund = store
                    .authorization(&auth)
                    .is_some_and(|a| a.credits() - a.remaining() == 2 && a.remaining() == 1);
                let password_positive = ids
                    .workers
                    .get(&b)
                    .is_some_and(|w| store.permit(&b, w, Step::Password, &now, &world).is_ok())
                    && op(&store, &b).passwords() == 1;
                let controls = queued_control
                    && independent_control
                    && budget_control
                    && confirmed
                    && password_positive
                    && independent_still_live;
                rows.push(json!({
                    "family": 1,
                    "stop": stop,
                    "failed_first": failed,
                    "past_retry": late,
                    "contract_passed": controls
                        && exact_teardown
                        && held_after_stop
                        && wrong_ack_unchanged
                        && failure_control
                        && unconfirmed_retained
                        && queued_held
                        && fresh_start
                        && swept_correctly
                        && duplicate_refused
                        && stale_unchanged
                        && no_refund,
                }));
            }
        }
    }
    rows
}

#[test]
fn one_generation_controls_its_callbacks_and_its_cleanup() {
    let mut rows = callbacks();
    rows.extend(cleanup());
    assert_eq!(rows.len(), 36);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["contract_passed"], true, "case {index}: {row}");
    }
}
