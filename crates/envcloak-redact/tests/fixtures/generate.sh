#!/usr/bin/env bash
# Regenerates serializer fixtures with the real runtimes, so the redactor is
# tested against their actual output rather than our own encoder.
#
# JSON value: ab/cd"ef\gh<BS>ij<U+00E9>kl<U+1F600>mn+op qr'st<uv
# URL value:  tok/en+val ue~!*'()&=x<U+00E9>
#
# Each file holds the runtime's exact output bytes with no trailing newline.
# Runtimes that are not installed are skipped; commit whatever was produced.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p json url
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if command -v python3 >/dev/null; then
  python3 - <<'EOF'
import json, urllib.parse
v = "ab/cd\"ef\\gh\bijékl\U0001F600mn+op qr'st<uv"
w = "tok/en+val ue~!*'()&=xé"
def put(p, s): open(p, "w", encoding="utf-8", newline="").write(s)
put("json/python_ensure_ascii.json", json.dumps(v))
put("json/python_utf8.json", json.dumps(v, ensure_ascii=False))
put("url/python_quote.txt", urllib.parse.quote(w))
put("url/python_quote_plus.txt", urllib.parse.quote_plus(w))
put("url/python_quote_safe_none.txt", urllib.parse.quote(w, safe=""))
EOF
fi

if command -v node >/dev/null; then
  node - <<'EOF'
const fs = require("fs");
const v = "ab/cd\"ef\\gh\bijékl\u{1F600}mn+op qr'st<uv";
const w = "tok/en+val ue~!*'()&=xé";
fs.writeFileSync("json/node_stringify.json", JSON.stringify(v));
fs.writeFileSync("url/node_encodeURIComponent.txt", encodeURIComponent(w));
fs.writeFileSync("url/node_URLSearchParams.txt", new URLSearchParams({ k: w }).toString().slice(2));
EOF
fi

if command -v go >/dev/null; then
  cat > "$tmp/main.go" <<'EOF'
package main

import (
	"encoding/json"
	"net/url"
	"os"
)

func main() {
	v := "ab/cd\"ef\\gh\bijékl\U0001F600mn+op qr'st<uv"
	w := "tok/en+val ue~!*'()&=xé"
	b, _ := json.Marshal(v)
	os.WriteFile("json/go_marshal.json", b, 0o644)
	os.WriteFile("url/go_QueryEscape.txt", []byte(url.QueryEscape(w)), 0o644)
	os.WriteFile("url/go_PathEscape.txt", []byte(url.PathEscape(w)), 0o644)
}
EOF
  go run "$tmp/main.go"
fi

if command -v dotnet >/dev/null; then
  cat > "$tmp/gen.cs" <<'EOF'
using System;
using System.IO;
using System.Text.Json;

var v = "ab/cd\"ef\\gh\bijékl\U0001F600mn+op qr'st<uv";
var w = "tok/en+val ue~!*'()&=xé";
var dir = Environment.GetEnvironmentVariable("FIXTURE_DIR")!;
// Utf8JsonWriter uses the same default encoder as JsonSerializer
// (reflection-based JsonSerializer is disabled in file-based apps).
using (var ms = new MemoryStream())
{
    using (var jw = new Utf8JsonWriter(ms)) { jw.WriteStringValue(v); }
    File.WriteAllBytes(Path.Combine(dir, "json/dotnet_system_text_json.json"), ms.ToArray());
}
File.WriteAllText(Path.Combine(dir, "url/dotnet_EscapeDataString.txt"), Uri.EscapeDataString(w));
File.WriteAllText(Path.Combine(dir, "url/dotnet_WebUtility_UrlEncode.txt"), System.Net.WebUtility.UrlEncode(w));
File.WriteAllText(Path.Combine(dir, "url/dotnet_HttpUtility_UrlEncode.txt"), System.Web.HttpUtility.UrlEncode(w));
EOF
  FIXTURE_DIR="$PWD" dotnet run "$tmp/gen.cs" >/dev/null
fi

if command -v ruby >/dev/null; then
  ruby -rjson -rcgi -ruri -e '
    v = "ab/cd\"ef\\gh\bijékl\u{1F600}mn+op qr'"'"'st<uv"
    w = "tok/en+val ue~!*'"'"'()&=xé"
    File.binwrite("json/ruby_generate.json", JSON.generate(v))
    File.binwrite("url/ruby_CGI_escape.txt", CGI.escape(w))
    File.binwrite("url/ruby_encode_www_form_component.txt", URI.encode_www_form_component(w))
  '
fi

ls -1 json url
