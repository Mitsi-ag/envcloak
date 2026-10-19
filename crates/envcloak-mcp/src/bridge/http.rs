//! `envcloak mcp-bridge --manifest <path> --url <url> --header-ref
//! <Header>=<slug>[#<field>]...`: the HTTP client bridge for a remote MCP
//! server (SPEC §6.4, §6.6; M2 plan D-04, D-18, D-36; task M2-18).
//!
//! Validates the URL (requiring `https://` for every non-loopback host and
//! allowing `http://` only for `127.0.0.1`, `[::1]` and `localhost`) and
//! header references before contacting the daemon, hands pipe ends and a
//! lifeline to `envcloakd` via `run.request` (`SCM_RIGHTS`), receives only
//! `DecisionView::Started` (never the secret header values), sends the
//! target URL to the daemon-started relay (`envcloak mcp-bridge --relay`),
//! and forwards MCP JSON-RPC messages between its own standard streams and
//! the relay.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use envcloak_client::claims::claims;
use envcloak_client::fail::Failure;
use envcloak_core::vault::{FieldName, Slug};
use envcloak_ipc::proto::{BridgeDecl, RunRequestParams};
use envcloak_policy::load_project;
use envcloak_policy::managed::{bridge_binding_name, bridge_headers};
use serde_json::{Value, json};

use super::handoff::{StartedPipes, WaitBudget, request_pipes};

/// Maximum URL length accepted on `--url`.
pub const MAX_URL_LEN: usize = 2048;

/// Maximum number of `--header-ref` bindings.
pub const MAX_HEADERS: usize = 32;

/// Parsed and validated bridge endpoint URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeUrl {
    /// Canonical full URL (`<origin><path_and_query>`).
    pub url: String,
    /// Origin (`<scheme>://<host>[:<non_default_port>]`).
    pub origin: String,
    /// `"https"` or `"http"`.
    pub scheme: String,
    /// Lowercase host (`"api.example.com"`, `"127.0.0.1"`, `"[::1]"`).
    pub host: String,
    /// Explicit port when non-default.
    pub port: Option<u16>,
    /// Path and optional query, always starting with `'/'`.
    pub path_and_query: String,
}

impl BridgeUrl {
    /// Parses and validates an MCP HTTP endpoint URL.
    ///
    /// Requires `https://` for every non-loopback host; `http://` is
    /// permitted only when the host is `127.0.0.1`, `[::1]` or `localhost`.
    ///
    /// # Errors
    /// Returns a static usage error description when the URL is malformed or
    /// uses `http://` for a non-loopback host.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.is_empty() || raw.len() > MAX_URL_LEN {
            return Err("--url needs a valid https:// URL (or http:// on loopback)");
        }
        if raw.bytes().any(|b| !b.is_ascii_graphic() || b == b'#') {
            return Err("--url must not contain spaces, control characters or a #fragment");
        }
        let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = raw.strip_prefix("http://") {
            ("http", r)
        } else {
            return Err("--url must start with https:// (or http:// for loopback only)");
        };
        let split_at = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..split_at];
        let tail = &rest[split_at..];
        if authority.is_empty() || authority.contains('@') {
            return Err("--url needs a host and must not contain user credentials");
        }
        let (host_raw, port_raw) = if let Some(after_bracket) = authority.strip_prefix('[') {
            let Some((ipv6, after)) = after_bracket.split_once(']') else {
                return Err("--url has an unclosed IPv6 literal");
            };
            if ipv6.is_empty()
                || !ipv6
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            {
                return Err("--url has an invalid IPv6 literal");
            }
            let port = if after.is_empty() {
                None
            } else if let Some(p) = after.strip_prefix(':') {
                Some(p)
            } else {
                return Err("--url has invalid characters after the IPv6 literal");
            };
            (format!("[{}]", ipv6.to_ascii_lowercase()), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
                None => (authority.to_ascii_lowercase(), None),
            }
        };
        if host_raw.is_empty()
            || (!host_raw.starts_with('[')
                && (!host_raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                    || host_raw.starts_with('.')
                    || host_raw.ends_with('.')
                    || host_raw.contains("..")))
        {
            return Err("--url has an invalid host");
        }
        let port = match port_raw {
            None => None,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("--url has an invalid port");
                }
                let n = p.parse::<u16>().map_err(|_| "--url has an invalid port")?;
                if n == 0 {
                    return Err("--url port must be between 1 and 65535");
                }
                let default_port = (scheme == "https" && n == 443) || (scheme == "http" && n == 80);
                if default_port { None } else { Some(n) }
            }
        };
        if scheme == "http" && !is_loopback_host(&host_raw) {
            return Err(
                "--url with http:// is allowed only for loopback (127.0.0.1, [::1], localhost); \
                 use https://",
            );
        }
        let origin = match port {
            Some(p) => format!("{scheme}://{host_raw}:{p}"),
            None => format!("{scheme}://{host_raw}"),
        };
        let path_and_query = if tail.is_empty() {
            "/".to_owned()
        } else if tail.starts_with('?') {
            format!("/{tail}")
        } else {
            tail.to_owned()
        };
        let url = format!("{origin}{path_and_query}");
        Ok(BridgeUrl {
            url,
            origin,
            scheme: scheme.to_owned(),
            host: host_raw,
            port,
            path_and_query,
        })
    }

    /// Host without IPv6 brackets, for provider `allowed_hosts` matching.
    #[must_use]
    pub fn bare_host(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&self.host)
    }
}

/// Whether `host` is a loopback host (`127.0.0.1`, `[::1]`, or `localhost`).
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("[::1]")
        || host.eq_ignore_ascii_case("::1")
        || host.eq_ignore_ascii_case("localhost")
}

/// One `--header-ref <Header>=<slug>[#<field>]` binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRef {
    /// Header name, such as `Authorization` or `X-Api-Key`.
    pub name: String,
    /// Vault item slug, such as `openai/main`.
    pub slug: String,
    /// Optional field name when not the default field.
    pub field: Option<String>,
}

impl HeaderRef {
    /// Parses `<Header>=<slug>[#<field>]`.
    ///
    /// # Errors
    /// Returns a static usage error message if the header name, slug or
    /// field is malformed.
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        let Some((header, target)) = raw.split_once('=') else {
            return Err("--header-ref needs <Header>=<slug>[#<field>]");
        };
        if header.is_empty()
            || header.len() > 128
            || bridge_binding_name(header, "https://example.test").is_none()
        {
            return Err(
                "--header-ref header name must start with a letter and contain only ASCII \
                 letters, digits, - and _",
            );
        }
        let (slug_raw, field_raw) = match target.split_once('#') {
            Some((s, f)) => (s, Some(f)),
            None => (target, None),
        };
        if Slug::new(slug_raw).is_err() {
            return Err("--header-ref needs a valid item slug: <Header>=<slug>[#<field>]");
        }
        let field = match field_raw {
            None => None,
            Some(f) => {
                if FieldName::new(f).is_err() {
                    return Err("--header-ref has an invalid #field name");
                }
                Some(f.to_owned())
            }
        };
        Ok(HeaderRef {
            name: header.to_owned(),
            slug: slug_raw.to_owned(),
            field,
        })
    }

    /// The `<slug>` or `<slug>#<field>` string.
    #[must_use]
    pub fn reference(&self) -> String {
        match &self.field {
            Some(f) => format!("{}#{f}", self.slug),
            None => self.slug.clone(),
        }
    }
}

/// Configuration for `envcloak mcp-bridge` in HTTP client mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBridgeConfig {
    /// Absolute path to the managed `envcloak.toml`.
    pub manifest: PathBuf,
    /// Validated target URL.
    pub url: BridgeUrl,
    /// Header references (`--header-ref`).
    pub headers: Vec<HeaderRef>,
    /// Optional explicit wait budget (`--wait`).
    pub wait: Option<WaitBudget>,
}

/// Runs the HTTP client bridge for `config`.
///
/// # Errors
/// Returns a [`Failure`] when the daemon refuses, the request is pending or
/// denied, or the relay reports a refusal or transport failure.
pub fn run_http(config: &HttpBridgeConfig) -> Result<(), Failure> {
    let header_names: Vec<String> = config.headers.iter().map(|h| h.name.clone()).collect();
    let Some(expected_bindings) = bridge_headers(&header_names, &config.url.origin) else {
        return Err(Failure::new(
            "managed_command_mismatch",
            "the bridged server's headers are invalid or collide",
        ));
    };

    // Preserve BindingSource::Env when the manifest's [env] already binds the
    // exact same `<HEADER>_O<16hex> = "<slug>[#<field>]"`; otherwise pass the
    // explicit `--header-ref` bindings in `refs` so the daemon resolves them.
    let explicit_refs: Vec<String> = expected_bindings
        .iter()
        .zip(&config.headers)
        .map(|((_, binding_name), h)| format!("{binding_name}={}", h.reference()))
        .collect();
    let refs = match load_project(&config.manifest) {
        Ok(proj)
            if proj.manifest.env.len() == expected_bindings.len()
                && expected_bindings.iter().zip(&config.headers).all(
                    |((_, binding_name), h)| {
                        proj.manifest.env.iter().any(|b| {
                            b.env_name.as_str() == binding_name
                                && b.reference.to_string() == h.reference()
                        })
                    },
                ) =>
        {
            Vec::new()
        }
        _ => explicit_refs,
    };

    let manifest_str = config.manifest.to_string_lossy().into_owned();
    let mut argv = vec![
        "mcp-bridge".to_owned(),
        "--manifest".to_owned(),
        manifest_str.clone(),
        "--url".to_owned(),
        config.url.url.clone(),
    ];
    for h in &config.headers {
        argv.push("--header-ref".to_owned());
        argv.push(format!("{}={}", h.name, h.reference()));
    }

    let params = RunRequestParams {
        manifest: manifest_str,
        profile: None,
        refs,
        env_file: None,
        argv,
        claims: claims(),
        launch: None,
        bridge: Some(BridgeDecl {
            origin: config.url.origin.clone(),
            header_names,
        }),
        fds: Vec::new(),
    };

    let pipes = request_pipes(&params, false, config.wait)?;
    pump_http(&config.url, pipes)
}

fn pump_http(url: &BridgeUrl, pipes: StartedPipes) -> Result<(), Failure> {
    let StartedPipes {
        mut to_child,
        from_child,
        from_errors: _,
        lifeline,
    } = pipes;

    // Send the full target URL to the relay and read its startup readiness
    // line before forwarding MCP traffic.
    let mut hello = serde_json::to_vec(&json!({ "envcloak_relay_url": url.url }))
        .map_err(|_| relay_failed("the relay handshake could not be encoded"))?;
    hello.push(b'\n');
    to_child
        .write_all(&hello)
        .and_then(|()| to_child.flush())
        .map_err(|_| relay_failed("the relay closed before accepting the target URL"))?;

    let mut reader = BufReader::new(from_child);
    let mut first_line = String::new();
    let n = reader
        .read_line(&mut first_line)
        .map_err(|_| relay_failed("the relay closed before reporting readiness"))?;
    if n == 0 {
        return Err(relay_failed("the relay exited before reporting readiness"));
    }
    if let Ok(v) = serde_json::from_str::<Value>(first_line.trim()) {
        if v.get("ok").and_then(Value::as_bool) == Some(false) {
            let kind = v.get("token").and_then(Value::as_str).unwrap_or("");
            let msg = v
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the relay refused the bridged session")
                .to_owned();
            return Err(match kind {
                "policy_denied" => Failure::new("policy_denied", msg),
                "value_too_short" => Failure::new("value_too_short", msg),
                "managed_command_mismatch" => Failure::new("managed_command_mismatch", msg),
                _ => Failure::new("run_failed", msg),
            });
        }
    }

    // Pump stdin -> relay in a background thread.
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_child.write_all(&buf[..n]).is_err() || to_child.flush().is_err() {
                        break;
                    }
                }
            }
        }
        drop(to_child);
    });

    // Read lines from relay -> stdout, intercepting any internal relay error
    // frame `{"envcloak_relay_error": ...}` so it is reported on stderr.
    let mut stdout = std::io::stdout().lock();
    let mut line = String::new();
    let mut fatal: Option<Failure> = None;
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(f) = parse_relay_error_line(&line) {
                    fatal = Some(f);
                    continue;
                }
                if stdout.write_all(line.as_bytes()).is_err() || stdout.flush().is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    drop(stdout);
    drop(reader);
    drop(lifeline);

    if let Some(f) = fatal {
        return Err(f);
    }
    Ok(())
}

fn parse_relay_error_line(line: &str) -> Option<Failure> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    let err = v.get("envcloak_relay_error")?;
    let kind = err.get("token").and_then(Value::as_str).unwrap_or("");
    let msg = err
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the HTTP relay refused the request")
        .to_owned();
    Some(match kind {
        "policy_denied" => Failure::new("policy_denied", msg),
        "managed_command_mismatch" => Failure::new("managed_command_mismatch", msg),
        _ => Failure::new("run_failed", msg),
    })
}

fn relay_failed(msg: &'static str) -> Failure {
    Failure::new("run_failed", msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_enforces_https_and_loopback_http() {
        let https = BridgeUrl::parse("https://api.example.com/v1/mcp?mode=sse").unwrap();
        assert_eq!(https.origin, "https://api.example.com");
        assert_eq!(https.host, "api.example.com");
        assert_eq!(https.path_and_query, "/v1/mcp?mode=sse");
        assert_eq!(https.url, "https://api.example.com/v1/mcp?mode=sse");

        let https_port = BridgeUrl::parse("https://api.example.com:8443/mcp").unwrap();
        assert_eq!(https_port.origin, "https://api.example.com:8443");
        assert_eq!(https_port.port, Some(8443));

        // Default port 443 is normalized away in the origin.
        let default_port = BridgeUrl::parse("https://api.example.com:443/mcp").unwrap();
        assert_eq!(default_port.origin, "https://api.example.com");
        assert_eq!(default_port.port, None);

        // Loopback http:// is allowed for 127.0.0.1, [::1], and localhost.
        for good in [
            "http://127.0.0.1:8080/mcp",
            "http://[::1]:9000/mcp",
            "http://localhost:3000/mcp",
        ] {
            assert!(BridgeUrl::parse(good).is_ok(), "{good}");
        }

        // Non-loopback http:// is refused.
        for bad in [
            "http://api.example.com/mcp",
            "http://192.168.1.10:8080/mcp",
            "http://10.0.0.1/mcp",
            "ftp://api.example.com/mcp",
            "https://user:pass@api.example.com/mcp",
            "https://api.example.com/mcp#frag",
            "https://",
        ] {
            assert!(BridgeUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn header_ref_parsing_validates_names_slugs_and_fields() {
        let h = HeaderRef::parse("Authorization=openai/prod").unwrap();
        assert_eq!(h.name, "Authorization");
        assert_eq!(h.slug, "openai/prod");
        assert_eq!(h.field, None);
        assert_eq!(h.reference(), "openai/prod");

        let wf = HeaderRef::parse("X-Api-Key=stripe/test#secret").unwrap();
        assert_eq!(wf.name, "X-Api-Key");
        assert_eq!(wf.slug, "stripe/test");
        assert_eq!(wf.field.as_deref(), Some("secret"));
        assert_eq!(wf.reference(), "stripe/test#secret");

        for bad in [
            "Authorization",
            "=openai/prod",
            "Bad Header=openai/prod",
            "123Header=openai/prod",
            "Authorization=not a slug",
            "Authorization=openai/prod#",
        ] {
            assert!(HeaderRef::parse(bad).is_err(), "{bad}");
        }
    }
}
