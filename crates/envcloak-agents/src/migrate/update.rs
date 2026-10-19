use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use envcloak_client::fail::Failure;
use envcloak_client::managed::{
    plan_update as client_plan_update, refuse_key_shaped_changes, update as client_update,
};
use envcloak_ipc::view::{LaunchReceiptView, UpdateStatementView};
use envcloak_policy::managed::LaunchChanges;
use envcloak_scan::{
    BackedUpFile, ModifyErrorKind, create_atomically, open_root, remove_checked, restore_over_left,
};
use envcloak_sys::InUse;

use crate::coverage::Cache;
use crate::writer::{Journal, Stamp, StateFile};

use super::{MigrateError, MigrateProof};

const MIGRATIONS_FILE: &str = "agents/migrations.json";
const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationRegistry {
    #[serde(default)]
    pub servers: BTreeMap<String, MigratedServerRecord>,
    #[serde(default)]
    pub backups: BTreeMap<String, BackupMigrationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigratedServerRecord {
    pub agent: String,
    pub server: String,
    #[serde(default)]
    pub launch_id: Option<String>,
    pub policy_id: String,
    pub manifest: PathBuf,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupMigrationRecord {
    pub backup_id: String,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    #[serde(default)]
    pub server_keys: Vec<String>,
    #[serde(default)]
    pub files: Vec<PathBuf>,
    #[serde(default)]
    pub deleted_files: Vec<PathBuf>,
}

impl MigrationRegistry {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(MIGRATIONS_FILE)
    }

    pub fn open(data_dir: &Path) -> Result<Self, MigrateError> {
        let path = Self::path(data_dir);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| MigrateError::Io {
                path,
                message: format!("corrupt migrations.json: {e}"),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(MigrateError::Io {
                path,
                message: e.to_string(),
            }),
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), MigrateError> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| MigrateError::Io {
                path: parent.to_path_buf(),
                message: e.to_string(),
            })?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| MigrateError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        let tmp = path.with_extension("json.tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| MigrateError::Io {
                path: tmp.clone(),
                message: e.to_string(),
            })?;
        f.write_all(&bytes).map_err(|e| MigrateError::Io {
            path: tmp.clone(),
            message: e.to_string(),
        })?;
        f.sync_all().map_err(|e| MigrateError::Io {
            path: tmp.clone(),
            message: e.to_string(),
        })?;
        drop(f);
        fs::rename(&tmp, &path).map_err(|e| MigrateError::Io {
            path,
            message: e.to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReport {
    pub server: String,
    pub launch_id: String,
    pub revision: u64,
    pub old: LaunchReceiptView,
    pub new: LaunchReceiptView,
    pub receipt: LaunchReceiptView,
    pub statement: UpdateStatementView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoReport {
    pub backup_id: String,
    pub restored_files: Vec<PathBuf>,
    pub unregistered_servers: Vec<String>,
}

pub fn lookup_launch_id(data_dir: &Path, server_key: &str) -> Result<String, MigrateError> {
    let Some((agent, server)) = server_key.split_once('/') else {
        return Err(MigrateError::UnmigratedServer {
            server: server_key.to_string(),
        });
    };
    if agent.is_empty() || server.is_empty() || server.contains('/') {
        return Err(MigrateError::UnmigratedServer {
            server: server_key.to_string(),
        });
    }

    let reg = MigrationRegistry::open(data_dir)?;
    if let Some(rec) = reg.servers.get(server_key)
        && let Some(id) = &rec.launch_id
    {
        return Ok(id.clone());
    }

    let launch_id_file = data_dir
        .join("mcp")
        .join(format!(
            "{}-{}",
            sanitize_segment(agent),
            sanitize_segment(server)
        ))
        .join("launch_id");
    if let Ok(raw) = fs::read_to_string(&launch_id_file) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    Err(MigrateError::UnmigratedServer {
        server: server_key.to_string(),
    })
}

fn check_changes(changes: &LaunchChanges) -> Result<(), MigrateError> {
    refuse_key_shaped_changes(changes).map_err(|f| {
        MigrateError::Client(
            f.with_tail("add it with `envcloak add` and bind it in the managed manifest"),
        )
    })
}

pub fn plan_update(
    server: &str,
    changes: &LaunchChanges,
    proof: &MigrateProof<'_>,
) -> Result<(String, UpdateStatementView), MigrateError> {
    check_changes(changes)?;
    let launch_id = lookup_launch_id(&proof.data_dir, server)?;
    let plan_view = client_plan_update(|| (proof.connect)(), &launch_id, changes, &proof.claims)
        .map_err(MigrateError::Client)?;
    let stmt = plan_view
        .statement
        .ok_or_else(|| MigrateError::UnmigratedServer {
            server: server.to_string(),
        })?;
    Ok((launch_id, stmt))
}

pub fn update(
    server: &str,
    changes: LaunchChanges,
    proof: &MigrateProof<'_>,
) -> Result<UpdateReport, MigrateError> {
    check_changes(&changes)?;
    let (launch_id, stmt) = plan_update(server, &changes, proof)?;
    if let Some(expected) = &proof.expected_statement_digest
        && expected != &stmt.digest
    {
        return Err(MigrateError::StatementMismatch);
    }
    let passphrase = proof
        .passphrase
        .as_ref()
        .map(envcloak_scan::first_run::secret_copy)
        .ok_or(MigrateError::MissingPassphrase)?;
    let updated = client_update(
        || (proof.connect)(),
        &launch_id,
        &changes,
        &stmt.digest,
        passphrase,
        &proof.claims,
    )
    .map_err(MigrateError::Client)?;

    Ok(UpdateReport {
        server: server.to_string(),
        launch_id,
        revision: updated.revision,
        old: stmt.old.clone(),
        new: stmt.new.clone(),
        receipt: updated.receipt,
        statement: stmt,
    })
}

struct RestoreTarget {
    path: PathBuf,
    root: envcloak_scan::ScanRoot,
    rel: PathBuf,
    file_idx: u32,
    sha256_hex: String,
    backed: BackedUpFile,
    create_empty_first: bool,
}

pub fn undo(backup_id: &str, proof: &MigrateProof<'_>) -> Result<UndoReport, MigrateError> {
    let passphrase = proof
        .passphrase
        .as_ref()
        .map(envcloak_scan::first_run::secret_copy)
        .ok_or(MigrateError::MissingPassphrase)?;
    let mut client = (proof.connect)().map_err(MigrateError::Client)?;
    let lease_view = client
        .backup_v2_open_restore(
            backup_id,
            envcloak_scan::first_run::secret_copy(&passphrase),
            proof.created_by_agent,
            proof.unrecorded,
            &proof.claims,
        )
        .map_err(|e| MigrateError::Client(Failure::from(e)))?;

    let mut reg = MigrationRegistry::open(&proof.data_dir)?;
    let deleted_set: BTreeSet<PathBuf> = reg
        .backups
        .get(backup_id)
        .map(|b| b.deleted_files.iter().cloned().collect())
        .unwrap_or_default();

    let mut targets = Vec::with_capacity(lease_view.statement.files.len());
    for f in &lease_view.statement.files {
        let path = PathBuf::from(&f.path);
        let sha256 = parse_hex32(&f.sha256).ok_or_else(|| MigrateError::RestoreRefused {
            path: path.clone(),
            reason: "invalid pre-change digest in backup".to_string(),
        })?;
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(MigrateError::RestoreRefused {
                path,
                reason: "invalid file path in backup".to_string(),
            });
        };
        let root = open_root(parent).map_err(|_| MigrateError::RestoreRefused {
            path: path.clone(),
            reason: "parent directory could not be opened".to_string(),
        })?;

        let is_deleted = deleted_set.contains(&path);
        match envcloak_sys::open_beneath(root.dir(), name) {
            Ok(open_fd) => {
                if matches!(envcloak_sys::open_elsewhere(&open_fd), InUse::Yes) {
                    return Err(MigrateError::OpenElsewhere { path });
                }
                if is_deleted {
                    if proof.unrecorded
                        && f.sha256_after.is_none()
                        && envcloak_scan::scrub::current_digest(&path) == Ok(sha256)
                    {
                        targets.push(RestoreTarget {
                            path: path.clone(),
                            root,
                            rel: PathBuf::from(name),
                            file_idx: f.file,
                            sha256_hex: f.sha256.clone(),
                            backed: BackedUpFile {
                                size: f.size,
                                sha256,
                                sha256_after: sha256,
                            },
                            create_empty_first: false,
                        });
                    } else {
                        return Err(MigrateError::RestoreRefused {
                            path,
                            reason: "file on disk was modified since migration".to_string(),
                        });
                    }
                } else {
                    let sha256_after = match &f.sha256_after {
                        Some(after_hex) => {
                            parse_hex32(after_hex).ok_or_else(|| MigrateError::RestoreRefused {
                                path: path.clone(),
                                reason: "invalid post-change digest in backup".to_string(),
                            })?
                        }
                        None if proof.unrecorded => envcloak_scan::scrub::current_digest(&path)
                            .map_err(|_| MigrateError::RestoreRefused {
                                path: path.clone(),
                                reason: "file is missing or unreadable on disk".to_string(),
                            })?,
                        None => {
                            return Err(MigrateError::RestoreRefused {
                                path,
                                reason: "backup has no post-change digest recorded".to_string(),
                            });
                        }
                    };
                    targets.push(RestoreTarget {
                        path: path.clone(),
                        root,
                        rel: PathBuf::from(name),
                        file_idx: f.file,
                        sha256_hex: f.sha256.clone(),
                        backed: BackedUpFile {
                            size: f.size,
                            sha256,
                            sha256_after,
                        },
                        create_empty_first: false,
                    });
                }
            }
            Err(_) => {
                let recorded_empty = f.sha256_after.as_deref() == Some(EMPTY_SHA256_HEX);
                if !is_deleted && !recorded_empty {
                    return Err(MigrateError::RestoreRefused {
                        path,
                        reason: "file is missing or unreadable on disk".to_string(),
                    });
                }
                if f.sha256_after.is_none() && !proof.unrecorded {
                    return Err(MigrateError::RestoreRefused {
                        path,
                        reason: "backup has no post-change digest recorded".to_string(),
                    });
                }
                if let Some(after_hex) = &f.sha256_after
                    && after_hex != EMPTY_SHA256_HEX
                {
                    return Err(MigrateError::RestoreRefused {
                        path,
                        reason: "file is missing or unreadable on disk".to_string(),
                    });
                }
                let empty_sha: [u8; 32] = Sha256::digest(b"").into();
                targets.push(RestoreTarget {
                    path: path.clone(),
                    root,
                    rel: PathBuf::from(name),
                    file_idx: f.file,
                    sha256_hex: f.sha256.clone(),
                    backed: BackedUpFile {
                        size: f.size,
                        sha256,
                        sha256_after: empty_sha,
                    },
                    create_empty_first: true,
                });
            }
        }
    }

    let (mut state_file, mut state) =
        StateFile::open(&proof.data_dir).map_err(|r| MigrateError::Io {
            path: proof.data_dir.join("agents/state.json"),
            message: r.message,
        })?;
    let mut restored_files = Vec::new();
    let mut touched_mcp_json = false;

    for t in &targets {
        let empty_stamp = if t.create_empty_first {
            Some(create_atomically(&t.root, &t.rel, b"", 0o600).map_err(|e| {
                MigrateError::RestoreRefused {
                    path: t.path.clone(),
                    reason: e.kind.message().to_string(),
                }
            })?)
        } else {
            None
        };
        let lease_id = lease_view.lease.clone();
        let new_stamp = match restore_over_left(&t.root, &t.rel, &t.backed, &mut |chunk_idx| {
            let chunk_u32 = u32::try_from(chunk_idx).ok()?;
            client
                .backup_v2_read(&lease_id, t.file_idx, chunk_u32)
                .ok()
                .map(|c| c.data.into_inner())
        }) {
            Ok(stamp) => stamp,
            Err(e) => {
                if let Some(es) = &empty_stamp {
                    let _ = remove_checked(&t.root, &t.rel, es);
                }
                let reason = match e.kind {
                    ModifyErrorKind::EditedSince => {
                        "file on disk was modified since migration".to_string()
                    }
                    _ => e.kind.message().to_string(),
                };
                return Err(MigrateError::RestoreRefused {
                    path: t.path.clone(),
                    reason,
                });
            }
        };

        let k = crate::writer::key(&t.path);
        let s = Stamp::from(new_stamp);
        state.written.insert(k.clone(), s);
        if let Some(rec) = state.files.get_mut(&k) {
            rec.stamp = Some(s);
            rec.post_sha256 = t.sha256_hex.clone();
        }
        if t.path.file_name() == Some(OsStr::new(".mcp.json")) {
            touched_mcp_json = true;
        }
        restored_files.push(t.path.clone());
    }

    state_file.save(&state).map_err(|r| MigrateError::Io {
        path: proof.data_dir.join("agents/state.json"),
        message: r.message,
    })?;

    if touched_mcp_json {
        invalidate_shared_mcp_cache(&proof.data_dir);
    }

    let mut unregistered_servers = Vec::new();
    if let Some(backup_rec) = reg.backups.get(backup_id).cloned() {
        for srv_key in &backup_rec.server_keys {
            if let Some(srv_rec) = reg.servers.get(srv_key).cloned() {
                client
                    .unregister_managed(
                        &srv_rec.policy_id,
                        envcloak_scan::first_run::secret_copy(&passphrase),
                        &proof.claims,
                    )
                    .map_err(|e| MigrateError::Client(Failure::from(e)))?;
                if let Some(parent) = srv_rec.manifest.parent() {
                    let _ = fs::remove_file(parent.join("launch_id"));
                }
                reg.servers.remove(srv_key);
            } else {
                client
                    .unregister_managed(
                        srv_key,
                        envcloak_scan::first_run::secret_copy(&passphrase),
                        &proof.claims,
                    )
                    .map_err(|e| MigrateError::Client(Failure::from(e)))?;
            }
            unregistered_servers.push(srv_key.clone());
        }
        reg.backups.remove(backup_id);
        reg.save(&proof.data_dir)?;
    }

    Ok(UndoReport {
        backup_id: backup_id.to_string(),
        restored_files,
        unregistered_servers,
    })
}

fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub(crate) fn sanitize_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "server".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn invalidate_shared_mcp_cache(data_dir: &Path) {
    let cache_path = Cache::path(data_dir);
    if !cache_path.exists() {
        return;
    }
    let mut cache = Cache::load(&cache_path);
    let mut changed = false;
    for rec in &mut cache.records {
        if rec.host == "claude-code" || rec.host == "copilot" {
            rec.config_digest.clear();
            changed = true;
        }
    }
    if changed {
        let _ = cache.store(&cache_path);
    }
}
