# EnvCloak: project manifests and env files

Status: M1. This file fixes the formats of SPEC §5 "Project manifest" and of the files `envcloak run --env-file` reads (§6.1), how a run's bindings are resolved from them, and how a project is identified (§6.1 step 2, §10b "Match" rule 5). The code is in `crates/envcloak-policy/`.

The manifest is committed to the repo, and agents can edit it: it is untrusted input. Nothing in it can loosen how a request is handled, and no error about it repeats its text.

## Finding and opening a manifest

The CLI looks for `envcloak.toml` in the working directory and each directory above it, after `realpath` of the working directory, so the walk follows the directories the kernel sees. The first entry by that name wins, whatever it is: a symlink is found and then refused, rather than a manifest further up being used in its place. A directory the walk cannot search stops it with an error.

The daemon opens the project from the path the CLI sends, which must be absolute and end in `envcloak.toml`:

1. `realpath` of the manifest's directory gives the canonical path.
2. That path is opened with `O_DIRECTORY | O_NOFOLLOW`, and `fstat` of the descriptor gives the directory's device and inode.
3. `envcloak.toml` is opened through the directory descriptor: `openat` with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`. A symlink in its place, dangling or not, is refused (`ELOOP`), and a FIFO does not block.
4. `fstat` of the manifest must show a regular file owned by the effective uid.
5. The canonical path is looked up again and must still be the directory opened in step 2.
6. At most 64 KiB is read from the manifest's descriptor and parsed.

## Project identity

A project is identified by its canonical directory together with that directory's device and inode:

| Change | Identity |
|---|---|
| The same directory through a symlinked path, `.` or `..` | Kept: `realpath` resolves to the same path and inode |
| Another spelling on a case-insensitive filesystem (APFS) | Kept: macOS `realpath` returns the stored spelling |
| The repo copied | New: another inode |
| The repo moved or renamed | New: a rename keeps the inode but not the path |
| The directory replaced by a new one at the same path | New inode, so new, unless the filesystem reuses the inode number |

The device and inode say which directory it is; the path alone could alias. The path is what makes a moved repo a new project.

The vault's project index (VAULT.md, "Project" record) keys a project by 49 bytes: a format byte `1`, the device and the inode as big-endian u64s, and SHA-256 of the canonical path's bytes.

## Manifest format

TOML, UTF-8, at most 64 KiB. Unknown tables and keys fail to parse, and so does a value of the wrong type.

```toml
[project]
name = "acme-web"                      # display text only

[env]                                  # the default profile
OPENAI_API_KEY = "openai/work"         # <slug>[#field]
STRIPE_SECRET_KEY = "stripe/acme-live#secret_key"
DATABASE_URL = { ref = "neon/acme", field = "url" }

[env.production]                       # a profile: inherits [env]
STRIPE_SECRET_KEY = "stripe/acme-live"

[policy]                               # can only tighten
agents = "approve"                     # approve | deny
redact = true
mode = "proxy"                         # proxy | inject
```

- `[project]` holds `name` only: 1 to 128 bytes, with no control characters and none of the invisible ones (bidirectional controls, zero-width characters, the byte-order mark).
- Under `[env]`, each key is an environment variable and each value a reference: a string `"<slug>[#field]"`, or an inline table with `ref` (a slug, without `#`) and an optional `field`.
- A standard or dotted table under `env` (`[env.production]`, `production.KEY = ...`) is a profile. An inline table is always a binding, and an inline `env = { ... }` holds bindings only. A profile holds bindings only: profiles do not nest.
- TOML itself refuses a key defined twice, including two spellings of one key (`A` and `"A"`).
- `envcloak://` is not part of a manifest reference.

### Names

| Name | Grammar |
|---|---|
| Variable | An ASCII letter or `_`, then letters, digits or `_`; at most 128 bytes; case matters |
| Profile | A lowercase ASCII letter or digit, then those, `_` or `-`; at most 64 bytes |
| Slug | VAULT.md: parts separated by `/`, each a lowercase letter or digit, then those, `.`, `_` or `-`; at most 128 bytes |
| Field | VAULT.md: a lowercase letter, digit or `_`, then those, `.` or `-`; at most 64 bytes |

### Policy

`[policy]` combines with the vault's policy for the project, and every setting moves the result only toward the stricter side:

| Setting | Effect |
|---|---|
| `agents = "deny"` | Requests from agent subjects, and subjects of unknown kind, are refused without a pending request |
| `agents = "approve"` | The default; every request still needs a grant (SPEC §10b) |
| `agents = "allow"` (any case) | Fails to parse: a manifest cannot loosen policy |
| `redact = true` | Redaction on |
| `redact = false` | Ignored. Agent subjects and subjects of unknown kind are always redacted; a terminal subject goes unredacted only when the vault's policy says so and the manifest does not turn it on |
| `mode = "proxy"` | Proxy mode required. M1 has no proxy, so such a request is refused rather than injected |
| `mode = "inject"` | Ignored where the vault's policy is proxy |

Any other value of `agents` or `mode` fails to parse. The vault's policy for a project defaults to approve, redact and inject.

## Resolving a run's bindings

A run names a profile, `--ref NAME=<slug>[#field]` arguments and an `--env-file`. Later layers replace earlier ones, variable by variable:

1. the manifest's `[env]`;
2. the profile's `[env.<profile>]`, which must exist;
3. the explicit bindings: the env file's references and the `--ref` arguments. Between them they may name a variable once. An ordinary variable in the env file is set from the file, so it removes the manifest's binding of that name.

The result is sorted by variable name. A binding added or changed by any layer is a new binding to the grant check, which compares variable, item and field.

Each binding is then tied to the vault's items. A reference names a secret item by slug, and a field by name; without a field it names the item's only field (an item with several fields needs `#field`). A reference to a card, an issuer credential or an item of any other class is refused, and the manifest is reported invalid.

## Env files

A `--env-file` is a dotenv-style file of at most 1 MiB. It can hold real values, so the CLI reads it into `SecretBytes`, and the parser copies each value only into a `SecretBuf` sized for it. The CLI reads only a regular file, opened without blocking. It sends the daemon the file's references and the names of its ordinary variables, each with its line (`EnvFileNames`), never a value: the daemon resolves the run's bindings from those, and the runner sets the ordinary variables for the command.

- Blank lines and lines starting with `#` are skipped. A byte-order mark before the first line is skipped. Lines end in LF or CRLF.
- Each entry is `[export ]NAME=value`, with blanks allowed around `=`. A variable may appear once.
- An unquoted value ends at the line's end or at a `#` that follows a blank, and loses surrounding blanks.
- `'single'` quotes are literal. `"double"` quotes decode `\n`, `\r`, `\t`, `\\`, `\"` and `\'`, and keep any other backslash as written. Quoted values may span lines, and CRLF inside them becomes LF. After the closing quote only blanks and a comment may follow, so `'a''b'` is an error rather than a concatenation.
- There is no variable expansion: `$HOME` is five bytes.
- A value may not contain a NUL byte.
- A value that is exactly `envcloak://<slug>[#field]` after unquoting is a reference; one that starts with `envcloak://` and is anything else is an error. Every other value is an ordinary variable, passed to the command as written.

## Errors

Errors are value-free. A manifest error is a kind and a place (a manifest line, a `--ref` argument's position or an env-file line); an env-file error is a kind and a line. The TOML library's own messages quote the source, so they are never passed on: a syntax error reports `not valid TOML` and its line. A binding that cannot be tied to an item names its variable and the kind, not the reference.

`envcloak run` prints one token for each (SPEC §6.1 step 9): `manifest_invalid` for the manifest, its path, and references to cards and other classes; `binding_unresolved` for `--profile`, `--ref`, `--env-file` and references to missing items or fields.

## Gates

| Gate (SPEC §15.2) | Test |
|---|---|
| 17: `agents = "allow"` fails to parse | `tests/manifest.rs` |
| 17: `redact = false` and `mode = "inject"` do not loosen, over every combination of vault policy, manifest policy and subject | `tests/effective.rs` |
| 17: references to a card, an issuer credential or an unknown item class are rejected | `tests/bind.rs` |
| 28, identity part: a copy or a move is a new identity; a symlinked path, or a case alias on APFS, keeps it | `tests/project.rs` |
| 11, parsing part: no fixture in freed memory while parsing env files and manifests | `tests/parse_probe.rs` |
| Errors carry no value, for malformed env files, manifests and `--ref` arguments holding fixtures | `tests/envfile.rs` |
