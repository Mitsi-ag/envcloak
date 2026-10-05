//! Cycle435 independent config bytes and ranges, rendered as byte literals.
use envcloak_core::SecretBytes;
use envcloak_scan::{agent_config::parse_config, candidates::Disposition, source::ConfigFormat};
fn check(raw: &[u8], value: &[u8], format: ConfigFormat, range: Option<(u64, u64)>) {
    let r = parse_config(&SecretBytes::copy_from(raw), format);
    assert!(r.complete(), "valid config must be complete");
    assert_eq!(r.findings.len(), 1, "one binding expected");
    let f = &r.findings[0];
    assert!(
        f.disposition == Disposition::Literal,
        "literal disposition expected"
    );
    assert!(
        f.value.as_ref().is_some_and(|s| s.ct_eq(value)),
        "decoded value mismatch"
    );
    assert!(
        !f.single_complete_line,
        "config cannot claim shell-line removal"
    );
    if let Some((start, end)) = range {
        assert!(
            f.range.start == start && f.range.end == end,
            "raw byte range mismatch"
        );
    }
}
#[test]
fn json_decoding_and_raw_ranges() {
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((32, 32)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((32, 32)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((32, 44)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((32, 44)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((32, 46)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((32, 46)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((32, 43)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((32, 43)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((32, 39)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((32, 39)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"na\\u00e9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((32, 42)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"na\xc3\xa9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((32, 38)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"\\ud83d\\ude42-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((32, 49)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"\xf0\x9f\x99\x82-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((32, 41)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"prefix\\u2028end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((32, 47)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"prefix\xe2\x80\xa8end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((32, 44)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((36, 36)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((36, 36)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((36, 48)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((36, 48)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((36, 50)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((36, 50)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((36, 47)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((36, 47)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((36, 43)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((36, 43)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"na\\u00e9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((36, 46)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"na\xc3\xa9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((36, 42)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"\\ud83d\\ude42-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((36, 53)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"\xf0\x9f\x99\x82-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((36, 45)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"prefix\\u2028end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((36, 51)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"headers\":{\"N\":\"prefix\xe2\x80\xa8end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((36, 48)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((33, 33)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"\"}}}}",
        b"",
        ConfigFormat::Json,
        Some((33, 33)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((33, 45)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"sample-alpha\"}}}}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((33, 45)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((33, 47)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"quote\\\"slash\\\\\"}}}}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((33, 47)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((33, 44)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"line\\n\\tend\"}}}}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((33, 44)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((33, 40)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"a\\bb\\fc\"}}}}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((33, 40)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"na\\u00e9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((33, 43)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"na\xc3\xa9me\"}}}}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((33, 39)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"\\ud83d\\ude42-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((33, 50)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"\xf0\x9f\x99\x82-tail\"}}}}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((33, 42)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"prefix\\u2028end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((33, 48)),
    );
    check(
        b"{\"mcpServers\":{\"s\":{\"auth\":{\"N\":\"prefix\xe2\x80\xa8end\"}}}}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((33, 45)),
    );
    check(
        b"{\"apiKey\":\"\"}",
        b"",
        ConfigFormat::Json,
        Some((11, 11)),
    );
    check(
        b"{\"apiKey\":\"\"}",
        b"",
        ConfigFormat::Json,
        Some((11, 11)),
    );
    check(
        b"{\"apiKey\":\"sample-alpha\"}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((11, 23)),
    );
    check(
        b"{\"apiKey\":\"sample-alpha\"}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((11, 23)),
    );
    check(
        b"{\"apiKey\":\"quote\\\"slash\\\\\"}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((11, 25)),
    );
    check(
        b"{\"apiKey\":\"quote\\\"slash\\\\\"}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((11, 25)),
    );
    check(
        b"{\"apiKey\":\"line\\n\\tend\"}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((11, 22)),
    );
    check(
        b"{\"apiKey\":\"line\\n\\tend\"}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((11, 22)),
    );
    check(
        b"{\"apiKey\":\"a\\bb\\fc\"}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((11, 18)),
    );
    check(
        b"{\"apiKey\":\"a\\bb\\fc\"}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((11, 18)),
    );
    check(
        b"{\"apiKey\":\"na\\u00e9me\"}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((11, 21)),
    );
    check(
        b"{\"apiKey\":\"na\xc3\xa9me\"}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((11, 17)),
    );
    check(
        b"{\"apiKey\":\"\\ud83d\\ude42-tail\"}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((11, 28)),
    );
    check(
        b"{\"apiKey\":\"\xf0\x9f\x99\x82-tail\"}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((11, 20)),
    );
    check(
        b"{\"apiKey\":\"prefix\\u2028end\"}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((11, 26)),
    );
    check(
        b"{\"apiKey\":\"prefix\xe2\x80\xa8end\"}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((11, 23)),
    );
    check(b"{\"token\":\"\"}", b"", ConfigFormat::Json, Some((10, 10)));
    check(b"{\"token\":\"\"}", b"", ConfigFormat::Json, Some((10, 10)));
    check(
        b"{\"token\":\"sample-alpha\"}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((10, 22)),
    );
    check(
        b"{\"token\":\"sample-alpha\"}",
        b"sample-alpha",
        ConfigFormat::Json,
        Some((10, 22)),
    );
    check(
        b"{\"token\":\"quote\\\"slash\\\\\"}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((10, 24)),
    );
    check(
        b"{\"token\":\"quote\\\"slash\\\\\"}",
        b"quote\"slash\\",
        ConfigFormat::Json,
        Some((10, 24)),
    );
    check(
        b"{\"token\":\"line\\n\\tend\"}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((10, 21)),
    );
    check(
        b"{\"token\":\"line\\n\\tend\"}",
        b"line\n\tend",
        ConfigFormat::Json,
        Some((10, 21)),
    );
    check(
        b"{\"token\":\"a\\bb\\fc\"}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((10, 17)),
    );
    check(
        b"{\"token\":\"a\\bb\\fc\"}",
        b"a\x08b\x0cc",
        ConfigFormat::Json,
        Some((10, 17)),
    );
    check(
        b"{\"token\":\"na\\u00e9me\"}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((10, 20)),
    );
    check(
        b"{\"token\":\"na\xc3\xa9me\"}",
        b"na\xc3\xa9me",
        ConfigFormat::Json,
        Some((10, 16)),
    );
    check(
        b"{\"token\":\"\\ud83d\\ude42-tail\"}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((10, 27)),
    );
    check(
        b"{\"token\":\"\xf0\x9f\x99\x82-tail\"}",
        b"\xf0\x9f\x99\x82-tail",
        ConfigFormat::Json,
        Some((10, 19)),
    );
    check(
        b"{\"token\":\"prefix\\u2028end\"}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((10, 25)),
    );
    check(
        b"{\"token\":\"prefix\xe2\x80\xa8end\"}",
        b"prefix\xe2\x80\xa8end",
        ConfigFormat::Json,
        Some((10, 22)),
    );
}
#[test]
fn toml_literals() {
    check(
        b"[mcp_servers.s.env]\nN = \"sample-alpha\"\n",
        b"sample-alpha",
        ConfigFormat::Toml,
        None,
    );
    check(
        b"[mcp_servers.s.env]\nN = \"a\\\"b\\\\c\"\n",
        b"a\"b\\c",
        ConfigFormat::Toml,
        None,
    );
    check(
        b"[mcp_servers.s.env]\nN = \"line\\nend\"\n",
        b"line\nend",
        ConfigFormat::Toml,
        None,
    );
    check(
        b"[mcp_servers.s.env]\nN = \"na\xc3\xa9me\"\n",
        b"na\xc3\xa9me",
        ConfigFormat::Toml,
        None,
    );
}
#[test]
fn explicit_references_stay_names_only() {
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"${VAR}\"}}}}"),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"${VAR}\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(
                b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"${VAR:-default}\"}}}}",
            ),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"${VAR:-default}\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(
                b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"envcloak://fixture/item\"}}}}",
            ),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"envcloak://fixture/item\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        assert!(
            f.disposition == Disposition::Template && f.value.is_none(),
            "reference must stay names-only"
        );
    }
}
#[test]
fn literal_dollars_json() {
    let mut lost = 0usize;
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"cost$5\"}}}}"),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"cost$5"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"trailing$\"}}}}"),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"trailing$"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"two$$marks\"}}}}"),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"two$$marks"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(
                b"{\"mcpServers\":{\"s\":{\"env\":{\"N\":\"prefix$-suffix\"}}}}",
            ),
            ConfigFormat::Json,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"prefix$-suffix"))
        {
            lost += 1;
        }
    }
    assert_eq!(lost, 0, "literal punctuation values were withheld");
}
#[test]
fn literal_dollars_toml() {
    let mut lost = 0usize;
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"cost$5\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"cost$5"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"trailing$\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"trailing$"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"two$$marks\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"two$$marks"))
        {
            lost += 1;
        }
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"[mcp_servers.s.env]\nN = \"prefix$-suffix\"\n"),
            ConfigFormat::Toml,
        );
        assert!(r.complete());
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        if f.disposition != Disposition::Literal
            || !f.value.as_ref().is_some_and(|s| s.ct_eq(b"prefix$-suffix"))
        {
            lost += 1;
        }
    }
    assert_eq!(lost, 0, "literal punctuation values were withheld");
}
#[test]
fn syntax_and_ambiguity_refusals() {
    {
        let r = parse_config(&SecretBytes::copy_from(b"{"), ConfigFormat::Json);
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"x\",}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"x\"} trailing"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"\\q\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"\\uD800\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"\\uDC00\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"x\ny\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"x\",\"apiKey\":\"y\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"x\",\"api\\u004bey\":\"y\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(&SecretBytes::copy_from(b"{\"a\":01}"), ConfigFormat::Json);
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(&SecretBytes::copy_from(b"{\"a\":1.}"), ConfigFormat::Json);
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(&SecretBytes::copy_from(b"{\"a\":NaN}"), ConfigFormat::Json);
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
    {
        let r = parse_config(
            &SecretBytes::copy_from(b"{\"apiKey\":\"\xff\"}"),
            ConfigFormat::Json,
        );
        assert!(
            !r.complete() && r.findings.is_empty(),
            "invalid or ambiguous JSON must not produce bindings"
        );
    }
}
#[test]
fn config_size_limit() {
    let raw = vec![32u8; envcloak_scan::MAX_DOTENV + 1];
    let r = parse_config(&SecretBytes::copy_from(&raw), ConfigFormat::Json);
    assert!(!r.complete() && r.findings.is_empty());
    assert!(r.issues.iter().any(|i| i.reason == "too_large"));
}
