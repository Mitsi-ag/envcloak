//! How a request held back by a full pending cap is audited (M2 plan
//! D-04; docs/GRANTS.md "Bounds").
//!
//! A request over a pending cap opens nothing and is answered
//! `too_many_pending`, and a waiter (`envcloak run --wait`, and from M2
//! the MCP server and `mcp-bridge`) asks again as often as every 2
//! seconds until a place frees or its wait ends. An entry for every answer
//! would grow the audit log with waiting time rather than with decisions:
//! about 300 for one wait of 10 minutes. So for each request (its
//! fingerprint, which covers its root, project, bindings, mode and command
//! line) [`Crowded`]:
//!
//! - writes the first `too_many_pending` at once, `count=1`;
//! - counts the ones after it, for [`WINDOW`] after the last entry it
//!   wrote, without writing them;
//! - writes them as one entry when that window is over (the daemon's
//!   one-second tick asks, [`Crowded::due`]), `count` saying how many
//!   answers it stands for, and starts the next window then; a request
//!   with nothing counted in a whole window is let go, and its next
//!   answer is written at once again;
//! - writes everything still counted when the vault locks
//!   ([`Crowded::drain`]), the daemon's stop included.
//!
//! So each answer is in exactly one entry, unless the daemon is killed,
//! and a request crowded out for 10 minutes writes about 11 entries. The
//! entry written for counted answers is the last of them, stamped when it
//! is written. At most [`MAX_HELD`] requests are counted at once; past
//! that, an answer is written at once, `count=1`, as if none were held:
//! no count is dropped to make room.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::audit::RequestAudit;

/// How long answers are counted before their entry is written.
pub const WINDOW: Duration = Duration::from_secs(60);

/// How many requests' answers are counted at once.
pub const MAX_HELD: usize = 64;

/// Answers to one request not yet written.
#[derive(Debug)]
struct Held {
    /// Awake time of the last entry written for it.
    written: Duration,
    /// Answers since, not written.
    counted: u64,
    /// The last of them.
    last: Option<Box<RequestAudit>>,
}

/// `too_many_pending` entries, held back and counted (see the module
/// documentation).
#[derive(Debug, Default)]
pub struct Crowded {
    held: BTreeMap<[u8; 32], Held>,
}

impl Crowded {
    /// A `too_many_pending` answer to the request with fingerprint `key`,
    /// whose entry is `e`, at awake time `now`: the entry to write now,
    /// with its count, or none when it is counted toward a later one.
    pub fn answer(
        &mut self,
        key: [u8; 32],
        mut e: RequestAudit,
        now: Duration,
    ) -> Option<RequestAudit> {
        if let Some(h) = self.held.get_mut(&key) {
            if now.saturating_sub(h.written) < WINDOW {
                h.counted = h.counted.saturating_add(1);
                h.last = Some(Box::new(e));
                return None;
            }
            // The window is over and no tick has written it yet: this
            // entry stands for the counted answers too.
            e.count = Some(h.counted.saturating_add(1));
            h.written = now;
            h.counted = 0;
            h.last = None;
            return Some(e);
        }
        if self.held.len() < MAX_HELD {
            self.held.insert(
                key,
                Held {
                    written: now,
                    counted: 0,
                    last: None,
                },
            );
        }
        e.count = Some(1);
        Some(e)
    }

    /// The entries due at awake time `now`: one for each request whose
    /// window is over with answers counted, `count` saying how many. A
    /// request with none counted in its window is let go.
    pub fn due(&mut self, now: Duration) -> Vec<RequestAudit> {
        let mut out = Vec::new();
        self.held.retain(|_, h| {
            if now.saturating_sub(h.written) < WINDOW {
                return true;
            }
            match h.last.take() {
                Some(mut e) => {
                    e.count = Some(h.counted);
                    out.push(*e);
                    h.written = now;
                    h.counted = 0;
                    true
                }
                None => false,
            }
        });
        out
    }

    /// Every count still held, as entries, and nothing held after: the
    /// vault is locking.
    pub fn drain(&mut self) -> Vec<RequestAudit> {
        std::mem::take(&mut self.held)
            .into_values()
            .filter_map(|h| {
                h.last.map(|mut e| {
                    e.count = Some(h.counted);
                    *e
                })
            })
            .collect()
    }

    /// How many requests' answers are being counted.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_core::audit::SubjectSummary;

    fn entry(pid: i32) -> RequestAudit {
        RequestAudit {
            pid,
            decision: "too_many_pending",
            request_id: None,
            grant_id: None,
            reason: Some("pending_per_root"),
            subject: SubjectSummary::default(),
            project: None,
            items: Vec::new(),
            argv: Vec::new(),
            count: None,
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(1000 + n)
    }

    /// A waiter asking every 2 seconds for 10 minutes and a few seconds,
    /// then no more: its first answer is written at once, then one entry
    /// a minute, by the tick, for the answers counted, the last of them a
    /// minute after it stopped; every answer is in exactly one entry, and
    /// nothing is left for the lock. The lock writes what is still
    /// counted.
    ///
    /// Mutation: write every answer (return the entry from `answer`
    /// whatever is held): 303 entries are written and this fails.
    /// Mutation: never write at the tick (`due` returns nothing): the last
    /// answers stay counted, unwritten, and this fails. Mutation: drop
    /// what is counted at the lock (`drain` returns nothing): this fails.
    #[test]
    fn a_crowded_request_is_written_once_a_minute_with_its_count() {
        let mut c = Crowded::default();
        let key = [7u8; 32];
        let mut written: Vec<RequestAudit> = Vec::new();
        let mut answers = 0u64;
        for t in 0..=730 {
            // The tick, every second.
            written.extend(c.due(secs(t)));
            if t % 2 == 0 && t <= 604 {
                answers += 1;
                written.extend(c.answer(key, entry(42), secs(t)));
            }
        }
        assert_eq!(c.held(), 0, "let go after a quiet window");
        assert!(c.drain().is_empty());
        let counts: Vec<u64> = written.iter().map(|e| e.count.unwrap()).collect();
        assert_eq!(counts.first(), Some(&1));
        assert_eq!(counts.iter().sum::<u64>(), answers, "{counts:?}");
        assert_eq!(written.len(), 12, "{counts:?}");
        assert_eq!(counts.last(), Some(&3), "{counts:?}");
        assert!(written.iter().all(|e| e.decision == "too_many_pending"));

        // Locked with answers counted: they are written then.
        let mut c = Crowded::default();
        assert_eq!(c.answer(key, entry(42), secs(0)).unwrap().count, Some(1));
        assert!(c.answer(key, entry(43), secs(2)).is_none());
        assert!(c.answer(key, entry(44), secs(4)).is_none());
        let drained = c.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!((drained[0].pid, drained[0].count), (44, Some(2)));
        assert_eq!(c.held(), 0);
    }

    /// A request let go after a quiet window has its next answer written
    /// at once; another request is counted apart.
    #[test]
    fn a_quiet_request_is_let_go_and_requests_are_counted_apart() {
        let mut c = Crowded::default();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(c.answer(a, entry(1), secs(0)).unwrap().count, Some(1));
        assert_eq!(c.answer(b, entry(2), secs(1)).unwrap().count, Some(1));
        assert!(c.answer(a, entry(1), secs(2)).is_none());
        // a's window ends with one answer counted; b's with none.
        let due = c.due(secs(61));
        assert_eq!(due.len(), 1);
        assert_eq!((due[0].pid, due[0].count), (1, Some(1)));
        assert!(c.due(secs(62)).is_empty());
        assert_eq!(c.held(), 1, "b, quiet for its window, is let go");
        assert_eq!(c.answer(b, entry(2), secs(63)).unwrap().count, Some(1));
        // a answered after its window, before the tick wrote it: this
        // entry stands for the ones counted too.
        assert!(c.answer(a, entry(1), secs(70)).is_none());
        assert_eq!(c.answer(a, entry(1), secs(121)).unwrap().count, Some(2));
    }

    /// Past MAX_HELD requests, an answer is written at once, as if none
    /// were held: nothing is dropped to make room.
    #[test]
    fn past_the_bound_every_answer_is_written() {
        let mut c = Crowded::default();
        for n in 0..MAX_HELD {
            let key = [u8::try_from(n).unwrap(); 32];
            assert!(c.answer(key, entry(1), secs(0)).is_some());
        }
        let over = [0xffu8; 32];
        for _ in 0..3 {
            assert_eq!(c.answer(over, entry(9), secs(1)).unwrap().count, Some(1));
        }
        assert_eq!(c.held(), MAX_HELD);
        // Every held request counts its own.
        assert!(c.answer([0u8; 32], entry(1), secs(2)).is_none());
        let drained = c.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].count, Some(1));
    }
}
