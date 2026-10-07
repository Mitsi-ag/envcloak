//! M3-04: client-role project metadata, paged by encoded JSON bytes.

use envcloak_core::vault::ProjectRecord;
use envcloak_ipc::proto::{ErrorKind, ProjectsListParams};
use envcloak_ipc::view::{ProjectBindingView, ProjectCursor, ProjectView, ProjectsView};
use envcloak_ipc::{Frame, RpcError};

use crate::server::{Shared, locked};

const PAGE_BYTES: usize = 768 * 1024;

fn view(shared: &Shared, p: &ProjectRecord) -> ProjectView {
    let shown = |s: &str| {
        if crate::items::looks_like_value(shared, s) {
            envcloak_policy::HIDDEN.to_owned()
        } else {
            s.to_owned()
        }
    };
    ProjectView {
        dir: shown(&p.display_path),
        manifest_sha256: p
            .manifest_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        bindings: p
            .bindings
            .iter()
            .map(|b| ProjectBindingView {
                env_name: shown(&b.env_name),
                reference: shown(&b.reference),
            })
            .collect(),
        last_seen_secs: p.last_seen,
    }
}

/// Like `items.list`, observes idle locking at dispatch and does not reset
/// the idle timer: polling metadata cannot keep an unused vault unlocked.
/// Every page checks the vault again, including continuations after lock.
pub fn list(shared: &Shared, p: ProjectsListParams) -> Result<ProjectsView, RpcError> {
    if let Some(c) = &p.after {
        if c.id.len() != 26
            || !c
                .id
                .bytes()
                .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
            || !matches!(c.id.as_bytes().first(), Some(b'0'..=b'7'))
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
    }
    let state = locked(&shared.state);
    let vault = state.unlocked()?;
    let mut rows: Vec<_> = vault
        .projects()
        .map_err(|_| RpcError::new(ErrorKind::VaultTampered))?
        .filter(|(id, row)| {
            p.after
                .as_ref()
                .is_none_or(|c| (row.last_seen, id.to_string()) < (c.last_seen, c.id.clone()))
        })
        .collect();
    rows.sort_unstable_by(|(aid, a), (bid, b)| (b.last_seen, bid).cmp(&(a.last_seen, aid)));
    let mut rows = rows.into_iter().peekable();
    let mut out = ProjectsView::default();
    let mut bytes = 0;
    while let Some((id, row)) = rows.next() {
        let item = view(shared, row);
        let item_bytes = Frame::encode(&item)
            .map_err(|_| RpcError::new(ErrorKind::FrameTooLarge))?
            .len();
        let next = rows.peek().map(|_| ProjectCursor {
            last_seen: row.last_seen,
            id: id.to_string(),
        });
        let overhead = Frame::encode(&ProjectsView {
            projects: vec![],
            next: next.clone(),
        })
        .map_err(|_| RpcError::new(ErrorKind::Internal))?
        .len();
        let total = overhead + bytes + item_bytes + out.projects.len();
        if total > PAGE_BYTES {
            if out.projects.is_empty() {
                return Err(RpcError::new(ErrorKind::FrameTooLarge));
            }
            break;
        }
        bytes += item_bytes;
        out.projects.push(item);
        out.next = next;
    }
    Ok(out)
}
