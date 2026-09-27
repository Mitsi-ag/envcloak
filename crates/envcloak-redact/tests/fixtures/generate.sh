#!/usr/bin/env bash
# Regenerates serializer fixtures with the real runtimes, so the redactor is
# tested against their actual output rather than our own encoder.
#
# The two test values are written once, as exact UTF-8 bytes, to
# value-json.txt and value-url.txt (built from code points, so no escaping
# layer can alter them). Every runtime reads its input from those files.
#
# JSON value: every JSON escape class: quote, backslash, slash, a short
#   control (backspace), DEL, non-ASCII (BMP and astral), HTML-sensitive
#   characters, apostrophe, plus, backtick, U+2028 and U+2029.
# URL value: space, non-ASCII and every ASCII punctuation character.
#
# Each output file holds the runtime's exact bytes with no trailing newline.
# Runtimes that are not installed are skipped; commit whatever was produced.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p json url
rm -f json/* url/*
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

python3 - <<'EOF'
c = chr
json_value = (
    "ab/cd" + c(0x22) + "ef" + c(0x5C) + "gh" + c(0x08) + "ij" + c(0xE9)
    + "kl" + c(0x1F600) + "mn+op qr'st<uv>w&x`y" + c(0x7F) + "z"
    + c(0x2028) + c(0x2029)
)
url_value = (
    "tok/en+val ue~!*'()&=x" + c(0xE9)
    + ",;:@$?#[]%" + c(0x22) + "<>`{}|" + c(0x5C) + "^"
)
open("value-json.txt", "w", encoding="utf-8", newline="").write(json_value)
open("value-url.txt", "w", encoding="utf-8", newline="").write(url_value)
EOF

if command -v python3 >/dev/null; then
  python3 - <<'EOF'
import json, urllib.parse
v = open("value-json.txt", encoding="utf-8").read()
w = open("value-url.txt", encoding="utf-8").read()
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
const v = fs.readFileSync("value-json.txt", "utf8");
const w = fs.readFileSync("value-url.txt", "utf8");
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
	vb, _ := os.ReadFile("value-json.txt")
	wb, _ := os.ReadFile("value-url.txt")
	b, _ := json.Marshal(string(vb))
	os.WriteFile("json/go_marshal.json", b, 0o644)
	w := string(wb)
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

var dir = Environment.GetEnvironmentVariable("FIXTURE_DIR")!;
var v = File.ReadAllText(Path.Combine(dir, "value-json.txt"));
var w = File.ReadAllText(Path.Combine(dir, "value-url.txt"));
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
    v = File.read("value-json.txt", encoding: "UTF-8")
    w = File.read("value-url.txt", encoding: "UTF-8")
    File.binwrite("json/ruby_generate.json", JSON.generate(v))
    File.binwrite("url/ruby_CGI_escape.txt", CGI.escape(w))
    File.binwrite("url/ruby_encode_www_form_component.txt", URI.encode_www_form_component(w))
  '
fi

ls -1 json url
