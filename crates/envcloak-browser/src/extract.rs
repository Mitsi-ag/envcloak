//! Declared session-state extraction (`SPEC.md` §6.8 "Delivery" & "Cookie scope",
//! M2 plan gate `b5`, task `M2b-07`).
//!
//! Extracts only the cookies and `localStorage` keys declared in the target's
//! [`TransferScope`]:
//! - Never captures cookies or storage from identity-provider origins, other
//!   origins, or undeclared cookie names / storage keys.
//! - Preserves cookie attributes (`domain`, `host_only`, `path`, `name`,
//!   `partition`, `secure`, `http_only`, `same_site`, `expires`) byte-for-byte
//!   without rewriting a broader cookie to fit a narrower declaration.
//! - Rejects unsupported session formats (`device_bound`, `indexeddb`, etc.)
//!   and broader-than-declared cookies with
//!   [`WorkerStopReason::UnsupportedSessionScope`].
//! - Holds all cookie and storage values in [`Zeroizing<String>`] buffers whose
//!   [` fmt::Debug`] implementation redacts the secret value.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use envcloak_signin::origin::parse_registered;
use envcloak_signin::{
    CookieDomain, CookiePartition, CookiePath, DeclaredCookie, DeclaredStorage, Host, HostName,
    Label, Origin, Site, TransferScope,
};

use crate::cdp::CdpClient;
use crate::identity::WorkerStopReason;

/// Session format configured on the target adapter (`M2b-07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerSessionFormat {
    /// HTTP cookies only.
    Cookies,
    /// `localStorage` keys only.
    Storage,
    /// Both HTTP cookies and `localStorage` keys.
    CookiesAndStorage,
    /// Unsupported session mechanism (e.g., `device_bound`, `indexeddb`, `service_worker`).
    Unsupported,
}

/// Serde helper for [`Zeroizing<String>`].
pub(crate) mod serde_zeroizing_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(val: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
        val.as_str().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Zeroizing::new(s))
    }
}

mod serde_declared_cookie {
    use super::*;
    use serde::de::Error as _;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct WireDeclaredCookie {
        name: String,
        domain: String,
        host_only: bool,
        path: String,
        partition_site: Option<String>,
        partition_cross_site_ancestor: bool,
    }

    pub fn serialize<S: Serializer>(val: &DeclaredCookie, s: S) -> Result<S::Ok, S::Error> {
        let (domain, host_only) = match &val.domain {
            CookieDomain::HostOnly(h) => (h.to_string(), true),
            CookieDomain::Domain(n) => (n.as_str().to_owned(), false),
        };
        let (partition_site, partition_cross_site_ancestor) = match &val.partition {
            CookiePartition::Unpartitioned => (None, false),
            CookiePartition::Partitioned {
                site,
                cross_site_ancestor,
            } => (
                Some(format!("{}://{}", site.scheme.as_str(), site.host)),
                *cross_site_ancestor,
            ),
        };
        let wire = WireDeclaredCookie {
            name: val.name.as_str().to_owned(),
            domain,
            host_only,
            path: val.path.as_str().to_owned(),
            partition_site,
            partition_cross_site_ancestor,
        };
        wire.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeclaredCookie, D::Error> {
        let wire = WireDeclaredCookie::deserialize(d)?;
        let name = Label::new(&wire.name).map_err(|_| D::Error::custom("invalid cookie name"))?;
        let path =
            CookiePath::new(&wire.path).map_err(|_| D::Error::custom("invalid cookie path"))?;
        let domain = if wire.host_only {
            CookieDomain::HostOnly(
                Host::parse(&wire.domain)
                    .map_err(|_| D::Error::custom("invalid host-only cookie domain"))?,
            )
        } else {
            let trimmed = wire.domain.strip_prefix('.').unwrap_or(&wire.domain);
            CookieDomain::Domain(
                HostName::new(trimmed)
                    .map_err(|_| D::Error::custom("invalid domain cookie hostname"))?,
            )
        };
        let partition = match wire.partition_site {
            None => CookiePartition::Unpartitioned,
            Some(site_str) => {
                let origin = parse_registered(&site_str)
                    .map_err(|_| D::Error::custom("invalid partition site"))?;
                CookiePartition::Partitioned {
                    site: Site {
                        scheme: origin.scheme(),
                        host: origin.host().clone(),
                    },
                    cross_site_ancestor: wire.partition_cross_site_ancestor,
                }
            }
        };
        Ok(DeclaredCookie {
            name,
            domain,
            path,
            partition,
        })
    }
}

mod serde_declared_storage {
    use super::*;
    use serde::de::Error as _;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize, Deserialize)]
    struct WireDeclaredStorage {
        origin: String,
        key: String,
    }

    pub fn serialize<S: Serializer>(val: &DeclaredStorage, s: S) -> Result<S::Ok, S::Error> {
        let wire = WireDeclaredStorage {
            origin: val.origin.to_string(),
            key: val.key.as_str().to_owned(),
        };
        wire.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeclaredStorage, D::Error> {
        let wire = WireDeclaredStorage::deserialize(d)?;
        let origin = parse_registered(&wire.origin)
            .map_err(|_| D::Error::custom("invalid storage origin"))?;
        let key = Label::new(&wire.key).map_err(|_| D::Error::custom("invalid storage key"))?;
        Ok(DeclaredStorage { origin, key })
    }
}

/// Raw cookie returned by CDP `Network.getAllCookies` or adapter response.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RawWorkerCookie {
    pub name: String,
    #[serde(with = "serde_zeroizing_string")]
    pub value: Zeroizing<String>,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<f64>,
    pub partition_top_site: Option<String>,
    pub partition_has_cross_site_ancestor: bool,
}

impl fmt::Debug for RawWorkerCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawWorkerCookie")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("domain", &self.domain)
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .field("partition_top_site", &self.partition_top_site)
            .finish()
    }
}

/// One captured cookie matching a [`DeclaredCookie`] in the target's [`TransferScope`].
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CapturedCookie {
    #[serde(with = "serde_declared_cookie")]
    pub declaration: DeclaredCookie,
    #[serde(with = "serde_zeroizing_string")]
    pub value: Zeroizing<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<f64>,
}

impl fmt::Debug for CapturedCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedCookie")
            .field("declaration", &self.declaration)
            .field("value", &"[REDACTED]")
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .finish()
    }
}

/// One captured `localStorage` entry matching a [`DeclaredStorage`] in the
/// target's [`TransferScope`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedStorage {
    #[serde(with = "serde_declared_storage")]
    pub declaration: DeclaredStorage,
    #[serde(with = "serde_zeroizing_string")]
    pub value: Zeroizing<String>,
}

impl fmt::Debug for CapturedStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedStorage")
            .field("declaration", &self.declaration)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Extracted session state ready to be sent over the driver pipe to the daemon.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeclaredState {
    pub cookies: Vec<CapturedCookie>,
    pub storage: Vec<CapturedStorage>,
}

/// Parses a [`RawWorkerCookie`]'s key attributes into a [`DeclaredCookie`] without
/// rewriting or normalizing any attribute.
pub fn parse_raw_cookie_declaration(raw: &RawWorkerCookie) -> Option<DeclaredCookie> {
    let name = Label::new(&raw.name).ok()?;
    let path = CookiePath::new(&raw.path).ok()?;
    let domain = if let Some(stripped) = raw.domain.strip_prefix('.') {
        CookieDomain::Domain(HostName::new(stripped).ok()?)
    } else {
        CookieDomain::HostOnly(Host::parse(&raw.domain).ok()?)
    };
    let partition = match &raw.partition_top_site {
        None => CookiePartition::Unpartitioned,
        Some(s) if s.is_empty() => CookiePartition::Unpartitioned,
        Some(site_str) => {
            let origin = parse_registered(site_str).ok()?;
            if origin.port() != origin.scheme().default_port() {
                return None;
            }
            CookiePartition::Partitioned {
                site: Site {
                    scheme: origin.scheme(),
                    host: origin.host().clone(),
                },
                cross_site_ancestor: raw.partition_has_cross_site_ancestor,
            }
        }
    };
    Some(DeclaredCookie {
        name,
        domain,
        path,
        partition,
    })
}

/// Filters `raw_cookies` and `raw_storage` (mapped by `(origin_string, key) -> value`)
/// against `transfer` and `format`.
///
/// - Rejects [`WorkerSessionFormat::Unsupported`] with
///   [`WorkerStopReason::UnsupportedSessionScope`].
/// - Never rewrites a cookie's domain, host-only flag, path, or partition to fit
///   a declaration; if a cookie shares a declared cookie's name on a related
///   domain but has broader or mismatched attributes while the declared cookie
///   itself is absent, fails with [`WorkerStopReason::UnsupportedSessionScope`].
/// - Ignores undeclared cookies (such as IdP session cookies or other origins'
///   cookies) and undeclared storage keys.
///
/// # Errors
/// Returns [`WorkerStopReason::UnsupportedSessionScope`] if the format is
/// unsupported or any declared cookie/storage item cannot be satisfied cleanly.
pub fn filter_declared_state(
    transfer: &TransferScope,
    format: WorkerSessionFormat,
    raw_cookies: &[RawWorkerCookie],
    raw_storage: &BTreeMap<(Origin, String), Zeroizing<String>>,
) -> Result<DeclaredState, WorkerStopReason> {
    match format {
        WorkerSessionFormat::Unsupported => {
            return Err(WorkerStopReason::UnsupportedSessionScope);
        }
        WorkerSessionFormat::Cookies => {
            if !transfer.storage.is_empty() {
                return Err(WorkerStopReason::UnsupportedSessionScope);
            }
        }
        WorkerSessionFormat::Storage => {
            if !transfer.cookies.is_empty() {
                return Err(WorkerStopReason::UnsupportedSessionScope);
            }
        }
        WorkerSessionFormat::CookiesAndStorage => {}
    }

    let mut captured_cookies = Vec::new();
    for declared in transfer.cookies.iter() {
        let mut matched: Option<CapturedCookie> = None;
        for raw in raw_cookies {
            if let Some(cand) = parse_raw_cookie_declaration(raw) {
                if &cand == declared {
                    matched = Some(CapturedCookie {
                        declaration: declared.clone(),
                        value: raw.value.clone(),
                        secure: raw.secure,
                        http_only: raw.http_only,
                        same_site: raw.same_site.clone(),
                        expires: raw.expires,
                    });
                    break;
                }
            } else if raw.name == declared.name.as_str() {
                // Cookie with a declared name has undeclarable attributes (e.g. non-ASCII path).
                return Err(WorkerStopReason::UnsupportedSessionScope);
            }
        }
        let Some(cookie) = matched else {
            // Either the declared cookie was never set or it was set with broader
            // attributes (e.g. Domain instead of HostOnly, or path "/" instead of "/app").
            return Err(WorkerStopReason::UnsupportedSessionScope);
        };
        captured_cookies.push(cookie);
    }

    let mut captured_storage = Vec::new();
    for declared in transfer.storage.iter() {
        let lookup_key = (declared.origin.clone(), declared.key.as_str().to_owned());
        let Some(val) = raw_storage.get(&lookup_key) else {
            return Err(WorkerStopReason::UnsupportedSessionScope);
        };
        captured_storage.push(CapturedStorage {
            declaration: declared.clone(),
            value: val.clone(),
        });
    }

    Ok(DeclaredState {
        cookies: captured_cookies,
        storage: captured_storage,
    })
}

/// Extracts [`DeclaredState`] from the worker browser over `cdp` for `session_id`.
///
/// # Errors
/// Returns [`WorkerStopReason::UnsupportedSessionScope`] if the format or state
/// violates [`TransferScope`], or [`WorkerStopReason::WorkerLost`] on CDP error.
pub fn extract_from_cdp<R: Read, W: Write>(
    cdp: &mut CdpClient<R, W>,
    session_id: &str,
    transfer: &TransferScope,
    format: WorkerSessionFormat,
) -> Result<DeclaredState, WorkerStopReason> {
    if format == WorkerSessionFormat::Unsupported {
        return Err(WorkerStopReason::UnsupportedSessionScope);
    }

    let cookies_res = cdp
        .call(Some(session_id), "Network.getAllCookies", json!({}))
        .map_err(|_| WorkerStopReason::WorkerLost)?;

    let mut raw_cookies = Vec::new();
    if let Some(arr) = cookies_res.get("cookies").and_then(Value::as_array) {
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
                .unwrap_or("")
                .to_owned();
            let path = item
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_owned();
            let secure = item.get("secure").and_then(Value::as_bool).unwrap_or(false);
            let http_only = item
                .get("httpOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let same_site = item
                .get("sameSite")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let expires = item.get("expires").and_then(Value::as_f64);

            let (partition_top_site, partition_has_cross_site_ancestor) =
                match item.get("partitionKey") {
                    Some(Value::String(s)) if !s.is_empty() => (Some(s.clone()), false),
                    Some(Value::Object(map)) => {
                        let top = map
                            .get("topLevelSite")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        let cross = map
                            .get("hasCrossSiteAncestor")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        (top, cross)
                    }
                    _ => (None, false),
                };

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
    let mut storage_origins = Vec::new();
    for decl in transfer.storage.iter() {
        if !storage_origins.contains(&decl.origin) {
            storage_origins.push(decl.origin.clone());
        }
    }

    for origin in storage_origins {
        let sec_origin = origin.to_string();
        if let Ok(dom_res) = cdp.call(
            Some(session_id),
            "DOMStorage.getDOMStorageItems",
            json!({
                "storageId": {
                    "securityOrigin": sec_origin,
                    "isLocalStorage": true
                }
            }),
        ) {
            if let Some(entries) = dom_res.get("entries").and_then(Value::as_array) {
                for pair in entries {
                    if let Some(arr) = pair.as_array()
                        && arr.len() >= 2
                        && let (Some(k), Some(v)) = (arr[0].as_str(), arr[1].as_str())
                    {
                        raw_storage
                            .insert((origin.clone(), k.to_owned()), Zeroizing::new(v.to_owned()));
                    }
                }
            }
        }
    }

    filter_declared_state(transfer, format, &raw_cookies, &raw_storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_signin::SortedSet;

    #[test]
    fn filters_only_declared_cookies_and_storage_and_rejects_broader_or_unsupported() {
        let app_origin = parse_registered("http://acme.localhost:4100").unwrap();
        let idp_origin = parse_registered("http://idp-acme.localhost:4101").unwrap();

        let decl_cookie = DeclaredCookie {
            name: Label::new("app_sid").unwrap(),
            domain: CookieDomain::HostOnly(Host::parse("acme.localhost").unwrap()),
            path: CookiePath::new("/").unwrap(),
            partition: CookiePartition::Unpartitioned,
        };
        let decl_storage = DeclaredStorage {
            origin: app_origin.clone(),
            key: Label::new("acme_token").unwrap(),
        };
        let transfer = TransferScope {
            cookies: SortedSet::new(vec![decl_cookie.clone()]).unwrap(),
            storage: SortedSet::new(vec![decl_storage.clone()]).unwrap(),
        };

        let raw_cookies = vec![
            RawWorkerCookie {
                name: "app_sid".into(),
                value: Zeroizing::new("secret-session-123".into()),
                domain: "acme.localhost".into(),
                path: "/".into(),
                secure: false,
                http_only: true,
                same_site: Some("Lax".into()),
                expires: None,
                partition_top_site: None,
                partition_has_cross_site_ancestor: false,
            },
            RawWorkerCookie {
                name: "idp_sid".into(),
                value: Zeroizing::new("idp-secret-999".into()),
                domain: "idp-acme.localhost".into(),
                path: "/".into(),
                secure: false,
                http_only: true,
                same_site: Some("Lax".into()),
                expires: None,
                partition_top_site: None,
                partition_has_cross_site_ancestor: false,
            },
            RawWorkerCookie {
                name: "undeclared_pref".into(),
                value: Zeroizing::new("dark-mode".into()),
                domain: "acme.localhost".into(),
                path: "/".into(),
                secure: false,
                http_only: false,
                same_site: None,
                expires: None,
                partition_top_site: None,
                partition_has_cross_site_ancestor: false,
            },
        ];

        let mut raw_storage = BTreeMap::new();
        raw_storage.insert(
            (app_origin.clone(), "acme_token".into()),
            Zeroizing::new("tok-abc".into()),
        );
        raw_storage.insert(
            (app_origin.clone(), "extra_local_key".into()),
            Zeroizing::new("should-not-capture".into()),
        );
        raw_storage.insert(
            (idp_origin, "idp_local_key".into()),
            Zeroizing::new("idp-should-not-capture".into()),
        );

        let extracted = filter_declared_state(
            &transfer,
            WorkerSessionFormat::CookiesAndStorage,
            &raw_cookies,
            &raw_storage,
        )
        .unwrap();

        assert_eq!(extracted.cookies.len(), 1);
        assert_eq!(extracted.cookies[0].declaration, decl_cookie);
        assert_eq!(extracted.cookies[0].value.as_str(), "secret-session-123");
        assert_eq!(extracted.storage.len(), 1);
        assert_eq!(extracted.storage[0].declaration, decl_storage);
        assert_eq!(extracted.storage[0].value.as_str(), "tok-abc");

        // Unsupported format fails immediately (gate b5)
        assert_eq!(
            filter_declared_state(
                &transfer,
                WorkerSessionFormat::Unsupported,
                &raw_cookies,
                &raw_storage,
            ),
            Err(WorkerStopReason::UnsupportedSessionScope)
        );

        // Broader domain cookie (`.acme.localhost`) is never rewritten to fit a HostOnly declaration
        let broader_cookies = vec![RawWorkerCookie {
            name: "app_sid".into(),
            value: Zeroizing::new("secret-session-123".into()),
            domain: ".acme.localhost".into(),
            path: "/".into(),
            secure: false,
            http_only: true,
            same_site: Some("Lax".into()),
            expires: None,
            partition_top_site: None,
            partition_has_cross_site_ancestor: false,
        }];
        assert_eq!(
            filter_declared_state(
                &transfer,
                WorkerSessionFormat::CookiesAndStorage,
                &broader_cookies,
                &raw_storage,
            ),
            Err(WorkerStopReason::UnsupportedSessionScope)
        );
    }
}
