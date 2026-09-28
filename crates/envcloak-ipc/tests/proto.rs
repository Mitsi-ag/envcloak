//! Messages (SPEC §4.3, §4.4, §5 "Logging"): requests and responses
//! round-trip, malformed input is refused with a fixed kind, and no error,
//! log label or `Debug` output repeats what the other side sent.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_ipc::proto::{
    self, APP_METHODS, CLIENT_METHODS, IncomingRequest, Lock, NoParams, ResponseError, Status,
    Unlock, UnlockParams, VaultCreate, VaultCreateParams, loggable_method, required_role,
};
use envcloak_ipc::view::{LockedView, UnlockedView};
use envcloak_ipc::{ErrorKind, Frame, Method, Role, RpcError, WireSecret};
use envcloak_testkit::{Canary, assert_no_canary, by_label, canaries, fresh_seed, labels};

fn frame(v: &serde_json::Value) -> Frame {
    Frame::encode(v).unwrap()
}

fn parse_error(f: &Frame) -> RpcError {
    match IncomingRequest::parse(f) {
        Ok(req) => req.params::<UnlockParams>().unwrap_err(),
        Err(e) => e,
    }
}

#[test]
fn a_request_carries_its_secret_to_the_daemon_intact() {
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let params = UnlockParams {
        passphrase: WireSecret::new(SecretBytes::copy_from(pass)),
        claims: Vec::new(),
    };
    let f = proto::request_frame::<Unlock>(41, &params).unwrap();
    let req = IncomingRequest::parse(&f).unwrap();
    assert_eq!(req.id, 41);
    assert_eq!(req.method, "unlock");
    let got: UnlockParams = req.params().unwrap();
    assert!(got.passphrase.as_secret().ct_eq(pass));
    // Debug output of every layer is value-free.
    assert_no_canary(format!("{params:?} {got:?} {req:?} {f:?}").as_bytes(), &cs);

    let create = VaultCreateParams {
        passphrase: WireSecret::new(SecretBytes::copy_from(pass)),
        recovery_kit: WireSecret::new(SecretBytes::copy_from(b"ABCD-EFGH")),
        kdf_memory_kib: Some(65536),
    };
    let f = proto::request_frame::<VaultCreate>(1, &create).unwrap();
    let got: VaultCreateParams = IncomingRequest::parse(&f).unwrap().params().unwrap();
    assert!(got.passphrase.as_secret().ct_eq(pass));
    assert!(got.recovery_kit.as_secret().ct_eq(b"ABCD-EFGH"));
    assert_eq!(got.kdf_memory_kib, Some(65536));
}

#[test]
fn methods_without_parameters_accept_none_or_an_empty_object() {
    let f = proto::request_frame::<Status>(1, &NoParams {}).unwrap();
    let req = IncomingRequest::parse(&f).unwrap();
    req.params::<NoParams>().unwrap();
    let f = frame(&serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "lock"}));
    let req = IncomingRequest::parse(&f).unwrap();
    assert_eq!(req.method, Lock::NAME);
    req.params::<NoParams>().unwrap();
    let f = frame(
        &serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "lock", "params": {"x": 1}}),
    );
    let e = IncomingRequest::parse(&f)
        .unwrap()
        .params::<NoParams>()
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidParams);
}

#[test]
fn malformed_requests_get_fixed_kinds() {
    use serde_json::json;
    let cases = [
        (
            json!({"jsonrpc": "1.0", "id": 1, "method": "status"}),
            ErrorKind::InvalidRequest,
        ),
        (
            json!({"id": 1, "method": "status"}),
            ErrorKind::InvalidRequest,
        ),
        (
            json!({"jsonrpc": "2.0", "method": "status"}),
            ErrorKind::InvalidRequest,
        ),
        (
            json!({"jsonrpc": "2.0", "id": -1, "method": "status"}),
            ErrorKind::InvalidRequest,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "method": "status", "extra": 1}),
            ErrorKind::InvalidRequest,
        ),
        (json!([1, 2]), ErrorKind::InvalidRequest),
        (
            json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {}}),
            ErrorKind::InvalidParams,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {"passphrase": 5}}),
            ErrorKind::InvalidParams,
        ),
        (
            json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {"passphrase": "a\\/bc"}}),
            ErrorKind::InvalidParams,
        ),
    ];
    for (v, kind) in cases {
        assert_eq!(parse_error(&frame(&v)).kind, kind, "{v}");
    }
    for bad in [&b"{"[..], b"not json", b"{\"jsonrpc\":\"2.0\",\"id\":1,"] {
        let f = Frame::read_from(
            &mut &[&u32::try_from(bad.len()).unwrap().to_be_bytes()[..], bad].concat()[..],
        )
        .unwrap();
        assert_eq!(
            IncomingRequest::parse(&f).unwrap_err().kind,
            ErrorKind::ParseError
        );
    }
    // An escaped secret is refused: it could not be decoded in place.
    // `YWJj` then `d` written as a JSON unicode escape; built at run time
    // so no tool rewrites the backslash.
    let escaped = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"unlock\",\"params\":{{\"passphrase\":\"YWJj{}u0064\"}}}}",
        '\\'
    );
    assert!(escaped.contains("YWJj\\u0064"));
    let f = Frame::read_from(
        &mut &[
            &u32::try_from(escaped.len()).unwrap().to_be_bytes()[..],
            escaped.as_bytes(),
        ]
        .concat()[..],
    )
    .unwrap();
    let e = IncomingRequest::parse(&f)
        .unwrap()
        .params::<UnlockParams>()
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidParams);
}

/// SPEC §5 "Logging": parsers of secret-bearing input return value-free
/// errors. A canary placed in every field a client controls never shows up
/// in an error's `Display` or `Debug`, or in a logged method name.
#[test]
fn errors_never_repeat_what_the_client_sent() {
    use serde_json::json;
    let cs = canaries(fresh_seed());
    let secret = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let not_b64 = format!("{secret}!!");
    let cases = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {"passphrase": not_b64}}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {"passphrase": 1, secret: 2}}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "unlock", "params": {"passphrase": [secret]}}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "vault.create", "params": {"passphrase": "YQ==", "recovery_kit": "YQ==", "kdf_memory_kib": secret}}),
        json!({"jsonrpc": secret, "id": 1, "method": "status"}),
        json!({"jsonrpc": "2.0", "id": secret, "method": "status"}),
        json!({"jsonrpc": "2.0", "id": 1, "method": "status", secret: 1}),
        json!({secret: secret}),
    ];
    for v in cases {
        let e = parse_error(&frame(&v));
        assert_no_canary(format!("{e} {e:?}").as_bytes(), &cs);
        let out = proto::error_frame(Some(1), &e).unwrap();
        let v: serde_json::Value = out.decode().unwrap();
        assert_no_canary(v.to_string().as_bytes(), &cs);
    }
    // A method name is logged only when it is a known one.
    for name in [
        secret.to_owned(),
        format!("app.{secret}"),
        format!("{secret}.status"),
    ] {
        let label = loggable_method(&name);
        assert!(!label.contains(secret));
        assert!(label == "(unknown)" || label == "app.(unknown)", "{label}");
    }
}

#[test]
fn every_app_method_needs_the_app_role() {
    for m in APP_METHODS {
        assert_eq!(required_role(m), Role::App, "{m}");
        assert_eq!(loggable_method(m), m);
    }
    assert_eq!(required_role("app.anything.else"), Role::App);
    assert_eq!(loggable_method("app.anything.else"), "app.(unknown)");
    for m in CLIENT_METHODS {
        assert_eq!(required_role(m), Role::Client, "{m}");
        assert_eq!(loggable_method(m), m);
    }
    assert_eq!(required_role("apple"), Role::Client);
}

#[test]
fn error_kinds_have_distinct_codes_and_tokens() {
    let mut codes: Vec<i32> = ErrorKind::ALL.iter().map(|k| k.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), ErrorKind::ALL.len());
    for k in ErrorKind::ALL {
        assert_eq!(ErrorKind::from_token(k.token()), Some(k));
        assert!(!k.message().is_empty());
        assert!(
            k.token()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
        );
    }
    assert_eq!(ErrorKind::from_token("nope"), None);
}

#[test]
fn responses_round_trip_and_answer_their_own_request() {
    let f = proto::result_frame(9, &LockedView { was_unlocked: true }).unwrap();
    let got: LockedView = proto::parse_response(&f, 9).unwrap();
    assert!(got.was_unlocked);
    // A result for another request, or of another shape, is refused.
    assert_eq!(
        proto::parse_response::<LockedView>(&f, 10).unwrap_err(),
        ResponseError::Protocol
    );
    assert_eq!(
        proto::parse_response::<UnlockedView>(&f, 9).unwrap_err(),
        ResponseError::Protocol
    );

    let e = RpcError::with_reason(ErrorKind::PassphraseRejected, "too_short");
    let f = proto::error_frame(Some(3), &e).unwrap();
    assert_eq!(
        proto::parse_response::<LockedView>(&f, 3).unwrap_err(),
        ResponseError::Rpc(e)
    );
    // An error to an unreadable request has no id; it answers any.
    let f = proto::error_frame(None, &RpcError::new(ErrorKind::ParseError)).unwrap();
    assert_eq!(
        proto::parse_response::<LockedView>(&f, 5).unwrap_err(),
        ResponseError::Rpc(RpcError::new(ErrorKind::ParseError))
    );
    // Unknown reasons are dropped; unknown kinds are a protocol error.
    assert_eq!(
        RpcError::with_reason(ErrorKind::VaultUnavailable, "made up").reason,
        None
    );
    let odd = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "x", "data": {"kind": "made_up"}}});
    assert_eq!(
        proto::parse_response::<LockedView>(&frame(&odd), 1).unwrap_err(),
        ResponseError::Protocol
    );
}

/// A response that carries a value (as the run path will) decodes it into
/// a wiped buffer, and a client never prints the daemon's message text.
#[test]
fn a_response_can_carry_a_value_and_messages_are_never_shown() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Released {
        value: WireSecret,
    }
    let cs: Vec<Canary> = canaries(fresh_seed());
    let v = by_label(&cs, labels::STRIPE_SECRET_KEY).value();
    let f = proto::result_frame(
        4,
        &Released {
            value: WireSecret::new(SecretBytes::copy_from(v)),
        },
    )
    .unwrap();
    let got: Released = proto::parse_response(&f, 4).unwrap();
    assert!(got.value.as_secret().ct_eq(v));

    let secret = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let hostile = serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": secret, "data": {"kind": "wrong_passphrase", "reason": secret}}});
    let e = proto::parse_response::<LockedView>(&frame(&hostile), 1).unwrap_err();
    assert_eq!(
        e,
        ResponseError::Rpc(RpcError::new(ErrorKind::WrongPassphrase))
    );
    assert_no_canary(format!("{e:?}").as_bytes(), &cs);
}

/// `--env-file` crosses the socket as its references and the names of its
/// ordinary variables, each with its line (SPEC §6.1 step 2): the values
/// never do, and the daemon reads back exactly what the CLI parsed. What
/// is not a reference or a name is refused, as a `--ref` is.
#[test]
fn an_env_file_crosses_as_references_and_names_only() {
    use envcloak_ipc::proto::{EnvFileLine, EnvFileParams, RunRequest, RunRequestParams};
    use envcloak_policy::parse_env_file_refs;

    let cs = canaries(fresh_seed());
    let value = by_label(&cs, labels::DATABASE_URL)
        .as_str()
        .replace('\'', "");
    let file = format!(
        "OPENAI_API_KEY=envcloak://openai/acme-web\n\
         # a comment\n\
         export PLAIN='{value}'\n\
         STRIPE_SECRET_KEY=envcloak://stripe/acme-web#value\n"
    );
    let parsed = parse_env_file_refs(&SecretBytes::copy_from(file.as_bytes())).unwrap();
    let names = parsed.names();
    let sent = EnvFileParams::from(&names);
    let line = |line: u32, text: &str| EnvFileLine {
        line,
        text: text.into(),
    };
    assert_eq!(
        sent,
        EnvFileParams {
            refs: vec![
                line(1, "OPENAI_API_KEY=openai/acme-web"),
                line(4, "STRIPE_SECRET_KEY=stripe/acme-web#value"),
            ],
            plain: vec![line(3, "PLAIN")],
        }
    );
    let params = RunRequestParams {
        manifest: "/src/acme-web/envcloak.toml".into(),
        profile: None,
        refs: Vec::new(),
        env_file: Some(sent),
        argv: vec!["./emit".into()],
        claims: Vec::new(),
    };
    let f = proto::request_frame::<RunRequest>(7, &params).unwrap();
    let mut bytes = Vec::new();
    f.write_to(&mut bytes).unwrap();
    assert_no_canary(&bytes, &cs);
    let got: RunRequestParams = IncomingRequest::parse(&f).unwrap().params().unwrap();
    assert_eq!(got, params);
    assert_eq!(got.env_file.unwrap().names().unwrap(), names);

    // Without one, the field is left out.
    let none = RunRequestParams {
        env_file: None,
        ..params
    };
    let f = proto::request_frame::<RunRequest>(8, &none).unwrap();
    let mut bytes = Vec::new();
    f.write_to(&mut bytes).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("env_file"));

    for bad in [
        EnvFileParams {
            refs: vec![line(1, "OPENAI_API_KEY")],
            plain: Vec::new(),
        },
        EnvFileParams {
            refs: vec![line(1, "OPENAI_API_KEY=not a slug")],
            plain: Vec::new(),
        },
        EnvFileParams {
            refs: vec![line(1, "1X=openai/acme-web")],
            plain: Vec::new(),
        },
        EnvFileParams {
            refs: Vec::new(),
            plain: vec![line(1, "NOT A NAME")],
        },
        EnvFileParams {
            refs: Vec::new(),
            plain: vec![line(1, "A=b")],
        },
    ] {
        assert!(bad.names().is_err(), "{bad:?}");
    }
    // Unknown fields are refused: nothing else of the file can cross.
    let f = frame(&serde_json::json!({
        "jsonrpc": "2.0", "id": 9, "method": "run.request",
        "params": {
            "manifest": "/x/envcloak.toml", "argv": ["x"],
            "env_file": {"refs": [], "plain": [], "values": ["x"]}
        }
    }));
    let e = IncomingRequest::parse(&f)
        .unwrap()
        .params::<RunRequestParams>()
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidParams);
}

/// The item methods (T11): `items.add` carries its value to the daemon
/// intact and prints it nowhere; unknown fields are refused, so a client
/// cannot slip a value in under another name; and every view a client
/// prints is a `View`, which a type holding a `WireSecret` cannot be.
#[test]
fn item_requests_carry_values_only_where_a_value_goes() {
    use envcloak_ipc::proto::{AddParams, ItemsAdd, ItemsList, ListParams};
    use envcloak_ipc::view::{ItemsView, View};
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::GITHUB_TOKEN).value();
    let params = AddParams {
        slug: Some("github/work".into()),
        provider: Some("github".into()),
        field: None,
        account: None,
        env_hint: Some("GITHUB_TOKEN".into()),
        allow_short: false,
        value: WireSecret::new(SecretBytes::copy_from(key)),
        claims: Vec::new(),
    };
    let f = proto::request_frame::<ItemsAdd>(7, &params).unwrap();
    let req = IncomingRequest::parse(&f).unwrap();
    assert_eq!(req.method, "items.add");
    let got: AddParams = req.params().unwrap();
    assert!(got.value.as_secret().ct_eq(key));
    assert_eq!(got.slug.as_deref(), Some("github/work"));
    assert_no_canary(format!("{got:?} {req:?}").as_bytes(), &cs);

    // A field no method has is refused, whatever it holds.
    let f = frame(&serde_json::json!({
        "jsonrpc": "2.0", "id": 8, "method": "items.list",
        "params": {"long": true, "value": "aGk="}
    }));
    let req = IncomingRequest::parse(&f).unwrap();
    assert_eq!(
        req.params::<ListParams>().unwrap_err().kind,
        ErrorKind::InvalidParams
    );
    assert_eq!(ItemsList::NAME, "items.list");

    fn is_view<T: View>() {}
    is_view::<ItemsView>();
    is_view::<envcloak_ipc::view::ItemView>();
    is_view::<envcloak_ipc::view::CheckReport>();
    is_view::<envcloak_ipc::view::RefEditView>();
    is_view::<envcloak_ipc::view::RemovedView>();
}

/// `run.request`'s answer: a covered one carries the values through a
/// frame intact, and a client takes only an answer of the shape a daemon
/// sends. Values beside another decision, a variable or slug of the wrong
/// shape, a variable twice, and an empty value or one with a NUL byte are
/// refused; the frame and `Debug` output show no value.
#[test]
fn a_run_answer_carries_values_only_when_covered_and_well_formed() {
    use envcloak_ipc::proto::{ReleasedValue, RunAnswer, RunRequest};
    use envcloak_ipc::view::DecisionView;
    use envcloak_policy::Mode;

    let cs = canaries(fresh_seed());
    let v = |label: &str| WireSecret::new(SecretBytes::copy_from(by_label(&cs, label).value()));
    let released = |env: &str, slug: &str, value: WireSecret| ReleasedValue {
        env_name: env.to_owned(),
        slug: slug.to_owned(),
        allow_short: false,
        value,
    };
    let covered = || DecisionView::Covered {
        grant: "0".repeat(26),
        redact: true,
        mode: Mode::Inject,
        manifest_changed: false,
    };
    let good = RunAnswer {
        decision: covered(),
        values: vec![
            released(
                "OPENAI_API_KEY",
                "openai/acme-web",
                v(labels::OPENAI_API_KEY),
            ),
            released(
                "STRIPE_SECRET_KEY",
                "stripe/acme-web",
                v(labels::STRIPE_SECRET_KEY),
            ),
        ],
    };
    assert!(good.well_formed());
    let f = proto::result_frame(9, &good).unwrap();
    assert_no_canary(format!("{f:?}{good:?}").as_bytes(), &cs);
    let back: RunAnswer = proto::parse_response::<<RunRequest as Method>::Output>(&f, 9).unwrap();
    assert!(back.well_formed());
    assert!(
        back.values[0]
            .value
            .as_secret()
            .ct_eq(by_label(&cs, labels::OPENAI_API_KEY).value())
    );
    let pending = || DecisionView::Pending {
        request: "ABCDEFGH".into(),
    };
    assert!(RunAnswer::decided(pending()).well_formed());

    let one = |env: &str, slug: &str, value: WireSecret| vec![released(env, slug, value)];
    let bad = [
        RunAnswer {
            decision: pending(),
            values: one("A", "a/b", v(labels::OPENAI_API_KEY)),
        },
        RunAnswer {
            decision: DecisionView::Denied {
                reason: "repeated".into(),
            },
            values: one("A", "a/b", v(labels::OPENAI_API_KEY)),
        },
        RunAnswer {
            decision: covered(),
            values: one("NOT=A NAME", "a/b", v(labels::OPENAI_API_KEY)),
        },
        RunAnswer {
            decision: covered(),
            values: one("A", "Not A Slug", v(labels::OPENAI_API_KEY)),
        },
        RunAnswer {
            decision: covered(),
            values: vec![
                released("A", "a/b", v(labels::OPENAI_API_KEY)),
                released("A", "c/d", v(labels::STRIPE_SECRET_KEY)),
            ],
        },
        RunAnswer {
            decision: covered(),
            values: one("A", "a/b", WireSecret::new(SecretBytes::copy_from(b""))),
        },
        RunAnswer {
            decision: covered(),
            values: one(
                "A",
                "a/b",
                WireSecret::new(SecretBytes::copy_from(b"a value\0with a NUL")),
            ),
        },
    ];
    for (i, a) in bad.iter().enumerate() {
        assert!(!a.well_formed(), "case {i}");
    }
}
