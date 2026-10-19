//! App-role paged audit log reading (`app.audit.list`; SPEC §4.3, §4.4, M3-16).

use envcloak_core::audit::{AuditEntry, AuditKind};
use envcloak_ipc::app::{
    AppAuditEntryView, AppAuditListParams, AppAuditListView, AppAuditSubjectView,
};
use envcloak_ipc::proto::{self, ErrorKind};
use envcloak_ipc::{FrameError, RpcError};
use envcloak_policy::SubjectKind;

use crate::server::{Shared, locked, refuse_if_traced};

/// Default and maximum number of entries returned by one `app.audit.list` call.
const MAX_AUDIT_LIST_LIMIT: usize = 200;

/// `app.audit.list`: returns a reverse-chronological page of metadata-only
/// audit entries from the unlocked vault (including a vault opened read-only
/// after an integrity or rollback failure), filtered by optional `before_seq`,
/// `project`, `item`, `agent`, and `kinds`.
pub(crate) fn list(shared: &Shared, p: AppAuditListParams) -> Result<AppAuditListView, RpcError> {
    refuse_if_traced()?;
    let limit = p.limit.unwrap_or(MAX_AUDIT_LIST_LIMIT);
    if limit == 0 || limit > MAX_AUDIT_LIST_LIMIT {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }
    if p.kinds
        .iter()
        .any(|k| !AuditKind::ALL.iter().any(|ak| ak.token() == k))
    {
        return Err(RpcError::new(ErrorKind::InvalidParams));
    }

    let (all_entries, _report) = {
        let s = locked(&shared.state);
        s.unlocked_any_integrity()?
            .read_audit()
            .map_err(|_| RpcError::new(ErrorKind::AuditUnavailable))?
    };

    let mut iter = all_entries
        .iter()
        .rev()
        .filter(|e| matches_filters(e, &p))
        .peekable();

    let mut entries = Vec::new();
    let mut stopped_for_frame = false;
    while entries.len() < limit {
        let Some(entry) = iter.next() else {
            break;
        };
        entries.push(to_entry_view(entry));
        let probe = AppAuditListView {
            entries: entries.clone(),
            next_before_seq: Some(u64::MAX),
        };
        if matches!(
            proto::result_frame(u64::MAX, &probe),
            Err(FrameError::TooLarge)
        ) {
            if entries.len() > 1 {
                entries.pop();
            }
            stopped_for_frame = true;
            break;
        }
    }

    let has_more = stopped_for_frame || iter.peek().is_some();
    let next_before_seq = if has_more {
        entries.last().map(|e| e.seq)
    } else {
        None
    };

    Ok(AppAuditListView {
        entries,
        next_before_seq,
    })
}

fn matches_filters(e: &AuditEntry, p: &AppAuditListParams) -> bool {
    if let Some(before) = p.before_seq
        && e.seq >= before
    {
        return false;
    }
    if let Some(project) = p.project.as_deref()
        && e.record.project.as_ref().map(|pr| pr.dir.as_str()) != Some(project)
    {
        return false;
    }
    if let Some(item) = p.item.as_deref()
        && !e.record.items.iter().any(|(_, s)| s.as_str() == item)
    {
        return false;
    }
    if let Some(agent) = p.agent.as_deref()
        && e.record.subject.agent.as_deref() != Some(agent)
    {
        return false;
    }
    if !p.kinds.is_empty() && !p.kinds.iter().any(|k| k == e.record.kind.token()) {
        return false;
    }
    true
}

fn parse_subject_kind(raw: &str) -> Option<SubjectKind> {
    match raw {
        "agent" => Some(SubjectKind::Agent),
        "terminal" => Some(SubjectKind::Terminal),
        "unknown" => Some(SubjectKind::Unknown),
        _ => None,
    }
}

fn to_entry_view(e: &AuditEntry) -> AppAuditEntryView {
    let r = &e.record;
    let time_secs =
        r.at.duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
    let subject = if r.subject.pid != 0
        || r.subject.kind.is_some()
        || r.subject.agent.is_some()
        || r.subject.root_pid.is_some()
        || r.subject.root_exe.is_some()
    {
        Some(AppAuditSubjectView {
            kind: r.subject.kind.as_deref().and_then(parse_subject_kind),
            agent: r.subject.agent.clone(),
            pid: r.subject.pid,
            root_pid: r.subject.root_pid,
            root_exe: r.subject.root_exe.clone(),
        })
    } else {
        None
    };
    AppAuditEntryView {
        seq: e.seq,
        time_secs,
        kind: r.kind.token().to_owned(),
        outcome: r.decision.outcome.clone(),
        subject,
        project_dir: r.project.as_ref().map(|p| p.dir.clone()),
        slugs: r.items.iter().map(|(_, s)| s.as_str().to_owned()).collect(),
        argv_masked: r.argv_redacted.clone(),
        reason: r.decision.reason.clone(),
        grant: r.grant_id.clone(),
        request: r.request_id.clone(),
    }
}
