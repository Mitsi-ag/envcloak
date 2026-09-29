# EnvCloak: import, init and deleting plaintext

This is how `envcloak init`, `envcloak import --scan` and `envcloak recovery confirm` move a project's `.env` files into the vault, and when they delete them (SPEC §6.4). The daemon's methods are in [IPC.md](IPC.md), and the file backups' format in [VAULT.md](VAULT.md) "File backups".

## Commands

```sh
envcloak init                              # envcloak.toml with the project's name, if there is none
envcloak init --import                     # dry run: what an import would do
envcloak init --import --yes               # import, write envcloak.toml and .gitignore, check the references
envcloak recovery confirm [--kit-fd N]     # you hold the Recovery Kit
envcloak init --delete-plaintext           # delete the imported .env files, after the four conditions
envcloak init --undo <ID> [--passphrase-fd N]   # write them back, byte for byte
envcloak import --scan ~/Dev [--yes]       # every project under a directory; a dry run without --yes
```

The project is the directory of the nearest `envcloak.toml` at or above the working directory, or the working directory when there is none. `init` reads that directory's env files; `import --scan` reads every directory below the one named, and each directory holding env files is a project. Every command takes `--json`.

## Scanning

The scan runs in the CLI, never in the daemon or the app, so a macOS privacy prompt names your terminal. It uses directory handles throughout (`crates/envcloak-scan`):

- A directory below the root is opened with `O_DIRECTORY | O_NOFOLLOW` from its parent's handle: a symlink is never followed, so a symlink loop ends nothing and nothing outside the root is reached. A directory reached twice is listed once. A mount point is not crossed, so a network or cloud volume mounted inside the tree is not entered; a root on one, named explicitly, is scanned.
- These directories are not entered: `.git`, `.hg`, `.svn`, `node_modules`, `target`, `.venv`, `venv`, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`, `.gradle`, `.cache`, `.npm`, `.cargo`, `.rustup`, `.Trash`, and on macOS `CloudStorage` and `Mobile Documents` (File Provider cloud storage and iCloud Drive). A walk goes 12 levels deep, stops after 10,000 files, and skips a directory of more than 100,000 entries.
- A file named `.env` or `.env.<suffix>` is opened with `O_NOFOLLOW | O_NONBLOCK`, so a FIFO opens without waiting. `fstat` must show a regular file owned by you, of at most 1 MiB: a FIFO, socket, device or directory is skipped, and so is a larger file, which is never read. A file with another hard link is read, reported, and never modified or deleted.
- A file is read whole into a wiped buffer sized from `fstat`, and refused if it changed while it was read. Its stamp (device, inode, size, modification and change times, mode, links and owner) is kept: every later change to the file checks it.

`.env` is the default profile, `[env]`; `.env.<name>` is the profile `<name>`, lowercased, with `.` read as `-` (`.env.development.local` is `development-local`). `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are templates: their names are reported, and their values never leave the CLI.

## Parsing

`envcloak_scan::parse_dotenv` reads the buffer in place; no dotenv library is used, since their errors print the offending line. Per line: blank lines and `#` comments are skipped; `[export ]NAME=value` with blanks around `=`; an unquoted value ends at the line's end or at a `#` after a blank, and loses the blanks around it; `'single'` and `` `backtick` `` quotes are literal; `"double"` quotes decode `\n`, `\r`, `\t`, `\\`, `\"` and `\'`; quoted values may span lines; LF or CRLF; a byte-order mark is skipped. Nothing is expanded: a value that is not single-quoted and holds `${` interpolates another variable, and is left where it is. A value starting with `envcloak://` must be a whole reference. A NUL byte, an unclosed quote, a name set twice or a line that is not `NAME=value` fails the file, with its line and a fixed message, never its text.

## What is imported

Each value goes to the daemon, which alone holds the key to compare values. An entry is left where it is, with a reason, when it is:

| Reason | When |
|---|---|
| `empty` | The value is empty |
| `too_short` | Under 8 bytes: never injected (SPEC §6.1), so a port or a flag |
| `looks_like_value` | The name is shaped like a key: a value pasted in its place. The name is never shown |
| `too_large` | Over the vault's 64 KiB field cap |
| `not_secret` | Configuration: no provider's key pattern matches, no word of the name says secret, and the value is neither a URL with a password nor shaped like a generated key |
| `interpolated` | It holds `${`, which is never expanded |
| `reference` | It is an `envcloak://` reference already |

The words of a name (split at `_`) that say secret are `KEY`, `KEYS`, `APIKEY`, `TOKEN`, `TOKENS`, `SECRET`, `SECRETS`, `PASSWORD`, `PASSWORDS`, `PASSWD`, `PASS`, `PWD`, `PASSPHRASE`, `CREDENTIAL`, `CREDENTIALS`, `CREDS`, `PRIVATE`, `SALT`, `SIGNATURE`, `SESSION` and `DSN`, in any case. A URL with a password is `scheme://user:password@...` up to the last `@`. A value is shaped like a generated key when it holds a run of 24 or more ASCII letters and digits mixing two of lowercase, uppercase and digits.

A value that is kept:

- is grouped with every equal value, by keyed hash under the vault's `index` subkey, across files and projects: one value in two repos becomes one item both manifests reference;
- binds to the item that holds it already, the first by slug when several do; every item that holds it is reported, since a value with duplicate owners should have one (gate 10);
- otherwise becomes a new item, named after its provider (from the value's shape, as `envcloak add` detects it) or its variable, and its project: `openai/acme-web`, `database-url/acme-web`, with the profile added for a profile's file (`short-token/acme-web-short`), and `-2` up to `-99` when a slug is taken. Its provider, classification, links and allowed hosts are filled in from the registry, as `add` fills them.

The daemon's plan has a digest over every entry's fate, every item and each value's keyed hash. `--yes` commits that plan only: the daemon works it out again under the lock it writes under, and refuses (`plan_changed`) when the vault or the files changed since it was shown. Importing needs no proof, as `add` needs none: nothing is bound to a new item yet.

The request carries every value, so one import is at most what fits in the protocol's 1 MiB frame (`import_too_large`); import fewer directories at a time beyond that.

## What is written

After the commit, each project gets:

- **`envcloak.toml`**: created where there is none (`O_EXCL`, linked into place whole), with each variable bound to its item's reference, `[env]` for `.env` and `[env.<profile>]` for a profile's file (a profile's binding equal to `[env]`'s is left out, since profiles inherit it). In an existing manifest, each missing binding is added as `envcloak ref` adds one, keeping comments and layout; a variable bound to another item already is left as it is and reported (`conflicts`).
- **`.gitignore`**: a line `/<file>` for each env file, unless a line there already names it (`<file>`, `/<file>`, `**/<file>`, `.env*`, or `.env.*` for a profile's file). A references-only file and a template get none. Written atomically, and only when something is missing, so a second run changes nothing.
- **the dry run**: the daemon checks every reference of the manifest, in `[env]` and each profile, resolves (`resolves`).

A symlinked or hard-linked `envcloak.toml` or `.gitignore`, or one another program changed meanwhile, is left alone and reported.

## Deleting plaintext

`envcloak init --delete-plaintext` deletes the project's imported env files only after all four conditions hold (SPEC §6.4, gate 16), in this order (`envcloak_scan::delete_plaintext`):

1. The daemon answers `import.verify` from the manifest it opens itself: every secret each file holds is committed in the item the manifest binds its variable to (committed means the vault's transaction is on disk: SQLite with `synchronous=FULL`, and `F_FULLFSYNC` on macOS), every reference resolves, and the Recovery Kit is confirmed. The refusals are `not_imported`, `unresolved_reference` and `recovery_kit_unconfirmed`, in that order.
2. Each file is read again, and must be the file checked (its stamp); its bytes go to the daemon, which writes an encrypted backup (`files.backup`, [VAULT.md](VAULT.md) "File backups") and answers once it is on disk. A failure is `files_backup_failed`.
3. The daemon answers `import.verify` again, now.
4. Each file is removed only when it is still the file read, has no other hard link, was not modified in the last two minutes (`recently_changed`), and is not open in another process as far as the system can tell (`open_elsewhere`: on Linux a write lease, refused while anyone else has the file open; on macOS `proc_listpidspath`, among your own processes). It is first renamed aside and checked to be the file checked, then unlinked, so a file an editor saved over the name meanwhile is put back, never removed. The directory is flushed.

A crash at any point leaves each file in place, or removed after its values were committed. Templates, references-only files, files with another hard link and files that do not parse are never deleted. Entries that are not secrets (a port, a flag) go with their file and stay in its backup; the report names them. Deletion removes the working copy only: a value that was committed to git, synced or copied elsewhere is still there, and the report says to rotate it.

`envcloak recovery confirm` reads the kit from `/dev/tty` with echo off, or one line from the descriptor `--kit-fd` names (as `vault create --kit-fd` wrote it), checks its shape (a typo costs no attempt), and sends it to the daemon, which checks it opens the vault's Recovery Kit envelope. It is a proof, like the passphrase: only from a terminal session with no agent in it, counted by the attempt limiter.

## Undo

The report ends with the backup's id. `envcloak init --undo <ID>` asks the daemon for the backup's files (`files.restore`), which is a proof: the passphrase, from `/dev/tty` or `--passphrase-fd`, in a terminal session with no agent in it, since it hands plaintext back. Each file is written where it was, with its mode, byte for byte, as a new file linked into place; a file that is there already is left alone (`unchanged` when it holds the same bytes, `exists` otherwise). The daemon removes file backups older than 7 days whenever it writes one, and at every unlock.

## Gates

| Gate | Where |
|---|---|
| 10: a value two items hold is reported for both, through the import's deduplication | `crates/envcloak-daemon/tests/import.rs` |
| 11, for import: reading and parsing a dotenv file leave no fixture in freed memory | `crates/envcloak-scan/tests/dotenv_probe.rs` |
| 15: a symlinked `.env` outside the root, a FIFO, a 2 GB file, a directory symlink loop, a hard link and an unreadable file: no hang, nothing followed or modified, no value in the report | `crates/envcloak-scan/tests/scan_safety.rs`, `crates/envcloak-cli/tests/import.rs` |
| 16: each condition refuses the deletion on its own; `kill -9` at every step leaves the plaintext file or the committed item | `crates/envcloak-scan/tests/delete.rs`, `crates/envcloak-cli/tests/import.rs` |
| Story S2 and S3: import, the kit confirmed, deletion, metadata-only `ls`, `show` and `check`, `init --undo` byte for byte | `crates/envcloak-cli/tests/import.rs` |
