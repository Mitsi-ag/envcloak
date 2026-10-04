//! Callbacks that meet a change of the world before any other call (b9,
//! b17 at the model level): an independent check of the operation store,
//! whose schedule and assertions were written apart from `tests/store.rs`
//! and `tests/enumeration.rs` and share only the fixture in `common`.
//!
//! For each of seven entry points (the password permit, the code permit,
//! the worker's capture, the claim of the declared state, the identity
//! response, the acknowledgement of publication and the per-call check)
//! and each of eleven events (none; the root's exit, a vault epoch, a
//! login, target or adapter revision, a replaced browser, the requester's
//! exit and a clock past the attempt's and the session's deadlines, each
//! with no call after it; the owner's cancel; lock), a fresh operation is
//! brought to the entry point, the event happens, and the entry point is
//! called at once. With no event the call is allowed: the positive control
//! for each entry point. After every event it is refused, the operation
//! has stopped, the stop keeps the delivered flag its phase gives, no
//! password or code was spent, and a lock ended the authorization, which
//! is first checked to be live so that check cannot pass on an empty
//! store. Each silent change is checked to be still unseen by the store
//! before the call, so the call is the first to see it. The worker and
//! supervisor ids are the ones the store's start effects handed out.
#![allow(clippy::unwrap_used)]

mod common;

use common::{DAEMON, MCP, ROOT, Spec, TestWorld, at, identity, scope};
use envcloak_signin::{
    Authorization, Channel, Effect, Fresh, Nonce, OperationKey, OperationStore, Options,
    PublishDecision, Request, RequestId, Step, SupervisorId, WorkerId,
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

#[test]
fn every_callback_after_an_unseen_change_is_refused() {
    let mut rows = Vec::new();
    for stage in 0..7 {
        for event in 0..11 {
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
            let mut now = at(0);
            match event {
                0 => {}
                1 => {
                    world.exited.insert(ROOT);
                }
                2 => world.epochs.vault += 1,
                3 => world.login += 1,
                4 => world.target += 1,
                5 => world.adapter += 1,
                6 => world.browser += 1,
                7 => {
                    world.exited.insert(MCP);
                }
                8 => now = at(5000),
                9 => {
                    store.cancel(&ROOT, &id, &now, &world).unwrap();
                }
                10 => store.lock(&now, &world),
                _ => unreachable!(),
            }
            let unseen_before_entry =
                (1..=8).contains(&event) && store.operation(&id).unwrap().stop().is_none();
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
            let lock_ended_authorizations =
                event != 10 || store.authorizations().all(Authorization::ended);
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
                    && (event == 0 || stop.is_some())
                    && (!(1..=8).contains(&event) || unseen_before_entry),
            }));
        }
    }
    assert_eq!(rows.len(), 77);
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
