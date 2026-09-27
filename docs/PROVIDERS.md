# EnvCloak: the provider registry

Status: M1. This file fixes the format of the provider files in `providers/` (SPEC §8), the rules the registry loader enforces (§8 "Registry safety", gate 18), and how a value's provider and test or live classification are detected (§6.3, §6.4). The code is in `crates/envcloak-providers/`.

A provider entry decides where a key may be sent. The daemon's balance polling (M4) and the proxy (M6) send a key only to its provider's allowed hosts, and only in a declared auth slot. An entry that names the wrong host would send the key there, so the loader refuses any entry that breaks a rule below, and one bad file fails the whole registry: a provider is never silently left out.

## Where the registry comes from

The registry ships inside the release. `providers/*.toml` and `providers/multi-tenant-suffixes.txt` are compiled in byte for byte, and nothing reads a registry from disk or the network at runtime. Local registry overrides are M2+ and need an approval proof.

The files are compiled in as Rust source, `crates/envcloak-providers/src/embedded.rs`, which `scripts/gen-providers.py` writes. They are not included with `include_str!`, and there is no build script: `scripts/check-sources.sh` accepts no compiled input other than the Rust files `scripts/check-unsafe.sh` reads, and `check-unsafe.sh` refuses build scripts. After editing `providers/`, run:

```sh
python3 scripts/gen-providers.py            # rewrites embedded.rs
python3 scripts/gen-providers.py --check    # exits 1 if embedded.rs is stale
```

The crate's `embedded` test compares the compiled copy with `providers/` and fails when they differ, so an edit that was not regenerated fails CI.

## Provider file format

One TOML file per provider, `providers/<id>.toml`, UTF-8, at most 64 KiB. Unknown tables and keys fail to load, as does a value of the wrong type. Lists hold at most 64 entries. Every top-level key, with DeepSeek's values (`providers/deepseek.toml` leaves out the empty lists):

```toml
id = "deepseek"                        # the file name without .toml
name = "DeepSeek"                      # display name

key_patterns = ['^sk-[a-f0-9]{32}$']   # whole values
live_patterns = ['^sk-']               # from the start, after a key pattern matched
test_patterns = []
env_hints = ["DEEPSEEK_API_KEY"]

allowed_hosts = ["api.deepseek.com"]
auth = [{ header = "authorization", scheme = "Bearer" }]
denied_paths = []

[links]
docs = "https://api-docs.deepseek.com"
billing = "https://platform.deepseek.com/usage"
keys = "https://platform.deepseek.com/api_keys"

[balance]
request = { method = "GET", url = "https://api.deepseek.com/user/balance", auth = "bearer" }
value = "$.balance_infos[0].total_balance"
currency = "$.balance_infos[0].currency"
```

`id`, `name`, `key_patterns` and `allowed_hosts` are required; `allowed_hosts` may be empty. Everything else is optional.

| Key | Rule |
|---|---|
| `id` | 1 to 32 lowercase letters, digits and `-`, starting with a letter or digit; equal to the file name without `.toml` |
| `name` | 1 to 64 bytes, without control or invisible characters (bidirectional controls, zero-width characters, the byte-order mark) |
| `key_patterns` | At least one. Each matches whole values: see "Patterns" |
| `live_patterns`, `test_patterns` | Anchored at the start. Tried only on a value that matched one of the provider's key patterns |
| `env_hints` | Uppercase variable names: an ASCII uppercase letter or `_`, then those or digits; at most 128 bytes |
| `allowed_hosts` | Hosts, see "Hosts", listed once each |
| `auth` | Auth slots, see "Auth slots", listed once each |
| `denied_paths` | See "Denied paths" |
| `[links]` | `docs`, `billing`, `keys` (the page where keys are made and revoked) and `dashboard`, each an `https://` URL. Links open in a browser and never carry the key, so their hosts need not be allowed hosts |
| `[balance]` | A balance adapter, see "Adapters" |

### Patterns

Patterns are regular expressions in the syntax of the Rust `regex` crate, compiled for bytes, without Unicode classes, and matched in linear time. A pattern is at most 256 printable ASCII bytes. The loader checks each one on its syntax tree, so the rules hold for what a pattern means rather than how it is spelled:

- No capturing groups. Use `(?:...)`. Detection never records where or what a pattern matched.
- A key pattern is anchored at both ends: every match starts at the start of the value and ends at its end. `^a|b$` is not anchored, and neither is `(?m)^...$`, whose `^` also matches after a newline.
- A key pattern matches no value shorter than 16 bytes, so a pattern cannot claim every short value. Doctor reports registry-pattern matches of any length (SPEC §6.5), which would otherwise make it a guess-confirmation oracle.
- A live or test pattern is anchored at the start, and may be short (`^sk_live_`).

A provider with no test mode lists its keys as live: they act on the real account.

### Hosts

An allowed host is an exact host, `api.openai.com`, or a wildcard, `*.example.com`, which covers every host under `example.com` but not `example.com` itself. A host is a lowercase DNS name of two or more labels, at most 253 bytes, whose labels are letters, digits and `-` (not first or last) and whose last label starts with a letter. That leaves out IP addresses, ports, user names, trailing dots, uppercase and non-ASCII spellings, so the host a reviewer reads is the host the key goes to.

A wildcard is refused (`WildcardTooBroad`):

- over a whole top-level domain (`*.com`);
- over a public suffix of two labels whose first label is a public second-level label (`ac`, `co`, `com`, `edu`, `gov`, `net`, `org` and the like): `*.co.kr` and `*.com.sg` cover domains anyone can register, whether or not the list names them.

A wildcard is also refused when it overlaps the multi-tenant zone of a domain on `providers/multi-tenant-suffixes.txt`:

- under a multi-tenant suffix (`WildcardUnderMultiTenantSuffix`): its domain is on the list, or is under a domain on it. `*.vercel.app` and `*.acme.vercel.app` are refused, while `*.vercel.app.example.com` and the exact host `acme.vercel.app` are not.
- over a multi-tenant suffix (`WildcardOverMultiTenantSuffix`): a domain on the list is under its domain. With `tenants.example.net` on the list, `*.example.net` would match `evil.tenants.example.net`, so it is refused, while its sibling `*.other.example.net` is not.

Under a multi-tenant suffix anyone can create a host, so a wildcard there would send the key to hosts anyone controls. A tenant's own host, such as `acme.supabase.co`, is stored on the item instead (SPEC §8).

`providers/multi-tenant-suffixes.txt` holds one domain per line, lowercase, two or more labels; `#` starts a comment. It lists application and function hosting (`vercel.app`, `workers.dev`, `supabase.co`, `amplifyapp.com`, ...), cloud platforms whose customers get subdomains (`amazonaws.com`, `azure.com`, `googleapis.com`, `aliyuncs.com`, ...), code and page hosting (`github.io`, `github.dev`, ...), and public suffixes of two labels under which anyone can register a domain (`co.uk`, `com.au`, ...). The list is kept by hand, so a wildcard over a platform it misses would load. No shipped provider has a wildcard host (the crate's `embedded` test checks this), and a change that adds one is checked against the Public Suffix List in review.

### Auth slots

Where a provider takes its key (SPEC §6.2 step 3). The proxy substitutes a placeholder only when it is the entire value of a declared slot.

| Slot | Meaning |
|---|---|
| `{ header = "<name>" }` | The whole value of that request header, such as `x-api-key` |
| `{ header = "<name>", scheme = "<scheme>" }` | The value after the scheme and a space, such as `Authorization: Bearer` |
| `{ basic = "user" }`, `{ basic = "password" }` | That part of `Authorization: Basic` |
| `{ query = "<name>" }` | A query parameter |

Header names are lowercase letters, digits and `-`, at most 64 bytes, and not a framing, routing or cookie header (`host`, `cookie`, `content-length`, `transfer-encoding`, `connection`, `proxy-authorization`, `forwarded` and the like). A scheme is a letter, then letters, digits, `.`, `_` or `-`, at most 32 bytes, and not `Basic`, which has its own slots. Two slots that differ only in the ASCII case of the header name or scheme are the same slot. `[[auth]]` tables are not the format; use the inline list.

### Denied paths

Key-management, admin and credential-minting endpoints (SPEC §6.2 step 4). A denied path is `/`, then segments of letters, digits and `._~-`, where a segment `*` stands for any one segment, at most 256 bytes, with no empty, `.` or `..` segment. It covers each request path it is a prefix of, segment by segment and without ASCII case: `/v1/organization` covers `/v1/organization/admin_api_keys` but not `/v1/organizations`, and `/repos/*/*/keys` covers `/repos/acme/web/keys/1`.

A request path that is not normalized counts as denied: an empty, `.` or `..` segment, a `%` escape or a backslash anywhere in it, since a server that normalizes it could reach a denied endpoint. The query and fragment are ignored. The proxy (M6) normalizes paths before it asks.

### Adapters

A balance adapter is one request and where its JSON response holds the value:

- `request`: `method` (`GET` only), `url` and `auth`, all required.
  - `url` is `https://`, with no fragment, and its host must be matched by one of the provider's allowed hosts.
  - `auth` names one of the provider's declared slots: `bearer` (the `authorization` header with scheme `Bearer`), `header:<name>` (the one header slot of that name), `basic:user`, `basic:password` or `query:<name>`. A request cannot put the key anywhere else.
- `value`, required, and `currency`, optional: JSON paths, `$` then up to 16 `.name` or `[index]` steps (`name` a letter or `_`, then letters, digits or `_`; `index` 0 to 9999, without leading zeros).

Adapters never follow redirects (M4 sends them).

### URLs

Every URL in a provider file, link or request, starts with exactly `https://`: `http://`, `HTTPS://`, other schemes and scheme-relative URLs fail with `NotHttps`. The host follows the host rules above, so a user name or a port fails, and so does a space or a backslash anywhere in the URL. That refuses `https://api.example.com@evil.test/`, where the real host is `evil.test`.

## Detection

`Registry::detect(value, env_name)` gives the provider and classification of a value, for import and `add` to pre-fill a new item (SPEC §6.3, §6.4):

1. Every provider with a key pattern that matches the whole value is a candidate. A value with anything around the key, even a newline, matches nothing.
2. One candidate is the provider. Several are a tie, broken by the variable the value was read from: the one candidate whose env hints name it is the provider. A variable names a hint when it equals the hint or contains it between `_` or the ends (`VITE_OPENAI_API_KEY`, `OPENAI_API_KEY_2`), ignoring ASCII case. Otherwise the tie stands: there is no provider, and the detection is marked ambiguous so the caller can ask.
3. The classification comes from the provider's live and test patterns: live if only a live pattern matches, test if only a test pattern matches, unknown otherwise. With no provider, it is the classification every candidate agrees on, or unknown.

The variable name only breaks ties; it never overrides a pattern. The one tie in the shipped registry is `sk-` and 32 lowercase hex digits, which both DeepSeek's pattern and OpenAI's older user-key pattern match.

The value is read in one place, `detect.rs`, and matched in place. A detection holds provider ids and a classification, never the value, a piece of it or where a pattern matched, and nothing logs. The crate's allocator probe checks that detection never copies a value into the heap.

`Registry::prefill(detection, item)` fills a new item's empty fields: the provider, its links, a snapshot of its allowed hosts (SPEC §5: widening them later needs approval), the classification, and a title and env hint. When the item already names another provider, nothing changes. An ambiguous detection fills the classification only.

`Registry::by_env_hint(name)` suggests the one provider whose env hints name a variable, for a value no pattern matched, such as an AWS secret access key. It is a suggestion for display, not a detection, and pre-fill does not use it.

## Errors

A registry error is a kind, the file and, where the parser recorded one, the line. Messages are fixed text: the TOML and regex libraries' own messages quote their input and are never passed on, so a value pasted into a provider file by mistake is not echoed.

## Gates

| Gate (SPEC §15.2) | Test |
|---|---|
| 18: a request host outside `allowed_hosts` fails to load, including hosts that only look allowed | `tests/loader.rs` |
| 18: an `http://` URL fails to load, in a request or any link | `tests/loader.rs` |
| 18: a wildcard under each multi-tenant suffix fails to load, and the list is what refuses it | `tests/loader.rs` |
| 18: a wildcard over a multi-tenant suffix, or over a public suffix of two labels, fails to load | `tests/loader.rs` |
| One bad provider fails the whole registry | `tests/loader.rs` |
| The compiled registry is `providers/` byte for byte, and loads | `tests/embedded.rs` |
| Detection over generated values, and the OpenAI and DeepSeek tie broken by the variable name | `tests/detect.rs` |
| 11, detection part: no fixture in freed memory, even with the allocator's wipe off | `tests/detect_probe.rs` |
| Errors carry no value | `tests/loader.rs` |
