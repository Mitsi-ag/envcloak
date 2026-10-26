//! D-28 loopback test-session adapter client (`SPEC.md` §6.8, `docs/SIGNIN-ADAPTER.md`,
//! gate `b19`, task `M2b-07`).
//!
//! Sends an HMAC-SHA-256 authenticated `POST /__envcloak/test-session` request to
//! a registered loopback application origin, verifies the returned identity
//! (`verify_identity_json`), and validates the returned cookies and storage
//! through [`filter_declared_state`] just like a browser transfer.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use envcloak_signin::origin::parse_registered;
use envcloak_signin::{Origin, Scheme, TransferScope};

use crate::extract::{DeclaredState, RawWorkerCookie, WorkerSessionFormat, filter_declared_state};
use crate::identity::{ExpectedIdentity, WorkerStopReason, verify_identity_json};
use crate::origin_guard::{GuardPhase, OriginGuard};

/// Canonical endpoint path for the D-28 test-session adapter.
pub const TEST_SESSION_PATH: &str = "/__envcloak/test-session";

/// Computes an RFC 2104 HMAC-SHA-256 hex digest using `sha2::Sha256`.
/// Intermediate key pads are wiped via [`Zeroizing`].
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_LEN: usize = 64;
    let mut k_block = Zeroizing::new([0u8; BLOCK_LEN]);
    if key.len() > BLOCK_LEN {
        let digest = Sha256::digest(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; BLOCK_LEN]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK_LEN]);
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(*ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(*opad);
    outer.update(inner_digest);
    let tag = outer.finalize();
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

/// Computes the D-28 HMAC-SHA-256 signature over the canonical 5-line payload.
pub fn sign_test_session_request(
    adapter_key: &[u8],
    method: &str,
    path: &str,
    timestamp_secs: u64,
    nonce: &str,
    body: &str,
) -> String {
    let payload = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp_secs,
        nonce,
        body
    );
    hmac_sha256_hex(adapter_key, payload.as_bytes())
}

/// Executes a D-28 test-session mint request against `endpoint_origin`,
/// enforcing `guard`, `expected`, `transfer`, and `format`.
///
/// # Errors
/// Returns:
/// - [`WorkerStopReason::OffOrigin`] if `endpoint_origin` is not a registered
///   loopback origin in `guard`.
/// - [`WorkerStopReason::CredentialsRejected`] if the adapter rejects the HMAC
///   request (`401`/`403`/`404`).
/// - [`WorkerStopReason::IdentityUnverified`] if the minted identity does not
///   match `expected`.
/// - [`WorkerStopReason::UnsupportedSessionScope`] if the minted state does not
///   satisfy `transfer` and `format`.
pub fn execute_test_session_adapter(
    endpoint_origin: &str,
    adapter_key: &[u8],
    ttl_secs: u64,
    guard: &mut OriginGuard,
    expected: &ExpectedIdentity,
    transfer: &TransferScope,
    format: WorkerSessionFormat,
) -> Result<DeclaredState, WorkerStopReason> {
    if format == WorkerSessionFormat::Unsupported {
        return Err(WorkerStopReason::UnsupportedSessionScope);
    }

    let origin = guard
        .check_url(endpoint_origin, GuardPhase::CredentialSubmission, false)
        .map_err(|v| WorkerStopReason::from(guard.record_violation(v)))?;

    if !origin.host().is_loopback() || origin.scheme() != Scheme::Http {
        return Err(WorkerStopReason::OffOrigin);
    }

    let body = json!({
        "identity": expected.account.as_str(),
        "account": expected.account.as_str(),
        "tenant": expected.tenant.as_ref().map(|t| t.as_str()),
        "role": expected.role.as_str(),
        "ttl": ttl_secs,
    })
    .to_string();

    static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);
    let ts_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000);
    let seq = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nonce = format!("ec-drv-{}-{:016x}", std::process::id(), seq);
    let sig = sign_test_session_request(
        adapter_key,
        "POST",
        TEST_SESSION_PATH,
        ts_secs,
        &nonce,
        &body,
    );

    let (status, resp_body) = loopback_http_post(
        &origin,
        TEST_SESSION_PATH,
        &ts_secs.to_string(),
        &nonce,
        &sig,
        &body,
    )?;

    if status != 200 {
        return Err(WorkerStopReason::CredentialsRejected);
    }

    let parsed: Value =
        serde_json::from_str(&resp_body).map_err(|_| WorkerStopReason::CredentialsRejected)?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(WorkerStopReason::CredentialsRejected);
    }

    // Normalize `identity` -> `account` if the server returned `identity` without `account`
    let mut id_obj = parsed.clone();
    if id_obj.get("account").is_none()
        && let Some(id_val) = id_obj.get("identity").cloned()
        && let Some(map) = id_obj.as_object_mut()
    {
        map.insert("account".to_owned(), id_val);
    }
    verify_identity_json(&id_obj, expected)?;

    let mut raw_cookies = Vec::new();
    if let Some(arr) = parsed.get("cookies").and_then(Value::as_array) {
        for item in arr {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = Zeroizing::new(
                item.get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            );
            let domain = item
                .get("domain")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| origin.host().to_string());
            let path = item
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_owned();
            let secure = item.get("secure").and_then(Value::as_bool).unwrap_or(false);
            let http_only = item
                .get("httpOnly")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let same_site = item
                .get("sameSite")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let expires = item.get("expires").and_then(Value::as_f64);
            let partition_top_site = item
                .get("partitionTopSite")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let partition_has_cross_site_ancestor = item
                .get("partitionHasCrossSiteAncestor")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            raw_cookies.push(RawWorkerCookie {
                name,
                value,
                domain,
                path,
                secure,
                http_only,
                same_site,
                expires,
                partition_top_site,
                partition_has_cross_site_ancestor,
            });
        }
    }

    let mut raw_storage: BTreeMap<(Origin, String), Zeroizing<String>> = BTreeMap::new();
    if let Some(arr) = parsed.get("storage").and_then(Value::as_array) {
        for entry in arr {
            let orig_str = entry.get("origin").and_then(Value::as_str).unwrap_or("");
            let Ok(st_origin) = parse_registered(orig_str) else {
                return Err(WorkerStopReason::UnsupportedSessionScope);
            };
            if let Some(ls) = entry.get("localStorage").and_then(Value::as_array) {
                for kv in ls {
                    let k = kv
                        .get("name")
                        .or_else(|| kv.get("key"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let v = kv.get("value").and_then(Value::as_str).unwrap_or("");
                    if !k.is_empty() {
                        raw_storage.insert(
                            (st_origin.clone(), k.to_owned()),
                            Zeroizing::new(v.to_owned()),
                        );
                    }
                }
            }
        }
    }

    filter_declared_state(transfer, format, &raw_cookies, &raw_storage)
}

fn loopback_http_post(
    origin: &Origin,
    path: &str,
    timestamp: &str,
    nonce: &str,
    signature: &str,
    body: &str,
) -> Result<(u16, String), WorkerStopReason> {
    let port = origin.port();
    let host_hdr = if port == origin.scheme().default_port() {
        origin.host().to_string()
    } else {
        format!("{}:{port}", origin.host())
    };

    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|_| WorkerStopReason::WorkerLost)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    // Note: never send an `Origin` header on D-28 adapter requests.
    let req = format!(
        "POST {path} HTTP/1.0\r\n\
         Host: {host_hdr}\r\n\
         Connection: close\r\n\
         Content-Type: application/json\r\n\
         X-EnvCloak-Timestamp: {timestamp}\r\n\
         X-EnvCloak-Nonce: {nonce}\r\n\
         X-EnvCloak-Signature: {signature}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    );

    stream
        .write_all(req.as_bytes())
        .map_err(|_| WorkerStopReason::WorkerLost)?;
    stream.flush().map_err(|_| WorkerStopReason::WorkerLost)?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|_| WorkerStopReason::WorkerLost)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or(WorkerStopReason::WorkerLost)?;
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(WorkerStopReason::WorkerLost)?;
    Ok((status, resp_body.to_owned()))
}
