# EnvCloak: import, init and deleting plaintext

This is how `envcloak init`, `envcloak import --scan` and `envcloak recovery confirm` move a project's `.env` files into the vault, and when they delete them (SPEC §6.4). The daemon's methods are in [IPC.md](IPC.md), and the file backups' format in [VAULT.md](VAULT.md) "File backups".

## Commands

```sh
envcloak init                              # envcloak.toml with the project's name, if there is none
envcloak init --import                     # dry run: what an import would do
envcloak init --import --yes               # import, write envcloak.toml and .gitignore, check the references
envcloak recovery confirm [--kit-fd N]     # you hold the Recovery Kit
envcloak init --delete-plaintext           # take the imported entries out of the .env files, after the four conditions
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
- A file an interrupted change of an env file left under a temporary name (`..env.envcloak-del-<hex>.tmp`, `..env.envcloak-new-<hex>.tmp`, see "Deleting plaintext") is reported as `leftover` and never read: it may hold plaintext. Look at it, then delete it.

`.env` is the default profile, `[env]`; `.env.<name>` is the profile `<name>`, lowercased, with `.` read as `-` (`.env.development.local` is `development-local`). `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are templates, and so is a name with one of those words as any of its dot-separated parts (`.env.local.example`, `.env.example.local`): their names are reported, their values never leave the CLI, and they are never changed. A file whose profile is shaped like a key (`.env.<hash>`, a value pasted into the name) is skipped whole (`not_a_profile_name`): its profile would be kept in `envcloak.toml` and its name in `.gitignore`, both committed.

## Parsing

`envcloak_scan::parse_dotenv` reads the buffer in place; no dotenv library is used, since their errors print the offending line. Per line: blank lines and `#` comments are skipped; `[export ]NAME=value` with blanks around `=`; an unquoted value ends at the line's end or at a `#` after a blank, and loses the blanks around it; `'single'` and `` `backtick` `` quotes are literal; `"double"` quotes decode `\n`, `\r`, `\t`, `\\`, `\"` and `\'`; quoted values may span lines; LF or CRLF; a byte-order mark is skipped. Nothing is expanded: a value that is not single-quoted and holds a `$` followed by a letter, a digit, `_`, `{` or `(` interpolates another variable or runs a command in the tools that read it (dotenv-expand, docker compose, godotenv and Ruby's dotenv expand `$NAME` as well as `${NAME}`), so its text is not the value a program sees, and it is left where it is. A value starting with `envcloak://` must be a whole reference. A NUL byte, an unclosed quote, a name set twice or a line that is not `NAME=value` fails the file, with its line and a fixed message, never its text.

## What is imported

Each value goes to the daemon, which alone holds the key to compare values. An entry is left where it is, with a reason, when it is:

| Reason | When |
|---|---|
| `empty` | The value is empty |
| `too_short` | Under 8 bytes: never injected (SPEC §6.1), so a port or a flag |
| `looks_like_value` | The name is shaped like a key: a value pasted in its place. The name is never shown |
| `too_large` | Over the vault's 64 KiB field cap |
| `not_secret` | Configuration: no provider's key pattern matches, no word of the name says secret, and the value is neither a URL with a password nor shaped like a generated key |
| `interpolated` | It holds `$NAME`, `${NAME}` or `$(...)`, which is never expanded |
| `guessable` | Under 16 characters with no provider's key shape, or a URL whose password is under 16 characters, from a caller that is not a person (see "Who may compare values") |
| `reference` | It is an `envcloak://` reference already |

The words of a name (split at `_`) that say secret are `KEY`, `KEYS`, `APIKEY`, `TOKEN`, `TOKENS`, `SECRET`, `SECRETS`, `PASSWORD`, `PASSWORDS`, `PASSWD`, `PASS`, `PWD`, `PASSPHRASE`, `CREDENTIAL`, `CREDENTIALS`, `CREDS`, `PRIVATE`, `SALT`, `SIGNATURE`, `SESSION` and `DSN`, in any case. A URL with a password is `scheme://user:password@...` up to the last `@`. A value is shaped like a generated key when it holds a run of 24 or more ASCII letters and digits mixing two of lowercase, uppercase and digits.

A value that is kept:

- is grouped with every equal value, by keyed hash under the vault's `index` subkey, across files and projects: one value in two repos becomes one item both manifests reference;
- binds to the item that holds it already, the first by slug when several do; every item that holds it is reported, since a value with duplicate owners should have one (gate 10);
- otherwise becomes a new item, named after its provider (from the value's shape, as `envcloak add` detects it) or its variable, and its project: `openai/acme-web`, `database-url/acme-web`, with the profile added for a profile's file (`short-token/acme-web-short`), and `-2` up to `-99` when a slug is taken. A project or profile name shaped like a key (a directory named by a hash, as worktrees and CI checkouts are) is never kept, in a slug or in `envcloak.toml`, which is committed: the project is `project` instead; the CLI skips a file with such a profile (see "Scanning"), and the daemon leaves one another client sends out of the slug. Its provider, classification, links and allowed hosts are filled in from the registry, as `add` fills them.

### Who may compare values

Comparing a value with the vault tells the caller whether the vault holds it, so the daemon guards it as it guards doctor's matching (SPEC §6.5):

- A value short enough to guess, under 16 characters with no provider's key pattern (a database password, a short token), is imported and compared with the vault only for a person: a terminal subject with no agent by any evidence, as a proof requires. For any other caller, an agent included, the plan and `import.verify` leave it where it is (`guessable`) whether the vault holds it or not; run `envcloak init --import --yes` yourself to import it. A value of 16 characters or more, or with a provider's key shape, cannot be guessed, and is compared for anyone. Characters, not bytes: an eight-letter password of two-byte letters is 16 bytes, and still short. A value that is not UTF-8 is counted as short as any encoding could make it, four bytes a character, so under 64 bytes it is short. In a URL with a password only the password counts, since the scheme, user, host and database are no secret: `postgres://app:<8 characters>@db.internal:5432/app` is short however long the URL is, and a `%XX` escape in the password counts as the byte it stands for. A URL whose password has 16 characters or more is compared for anyone.
- Each subject root may have 100,000 values compared per hour of awake time, by `import.plan`, `import.commit` and `import.verify` together (three runs of the largest `import --scan`); beyond that the call is refused (`too_many_checks`). A call that compares no value is not counted. The daemon counts 4,096 roots at once; a new one beyond that takes the place of the root whose hour started first, so no caller, however many roots it makes, can have another refused.
- Each of those calls is audited with the count of values it compared (kind `import`, outcome `checked`), and a refusal too; never a value.

The daemon's plan has a digest over every entry's fate, every item and each value's keyed hash. `--yes` commits that plan only: the daemon works it out again under the lock it writes under, and refuses (`plan_changed`) when the vault or the files changed since it was shown. Importing needs no proof, as `add` needs none: nothing is bound to a new item yet.

The request carries every value, so one import is at most what fits in the protocol's 1 MiB frame (`import_too_large`); import fewer directories at a time beyond that.

## What is written

After the commit, each project gets:

- **`envcloak.toml`**: created where there is none (`O_EXCL`, linked into place whole), with each variable bound to its item's reference, `[env]` for `.env` and `[env.<profile>]` for a profile's file (a profile's binding equal to `[env]`'s is left out, since profiles inherit it). In an existing manifest, each missing binding is added as `envcloak ref` adds one, keeping comments and layout; a variable bound to another item already is left as it is and reported (`conflicts`).
- **`.gitignore`**: a line `/<file>` for each env file git would not ignore by it, and `.*.envcloak-*.tmp` unless git would ignore the temporary names a crash can leave plaintext under while a file changes (`..env.envcloak-del-<hex>.tmp`), whether or not the env files needed a line. The `.gitignore` is read as git reads it: the last line that matches a file decides, so `.env*` followed by `!.env.local` leaves `.env.local` to git, and it gets its line after them; `#` comments, trailing blanks, `/` anchors, `**/`, directory-only patterns and the wildcards `*`, `?`, `[...]` and `\` count as in gitignore(5). A doubt adds a line, which only makes a duplicate: a `!` line is read without regard to case (git on macOS reads it so), and a pattern it does not understand (`[[:alpha:]]`) counts as keeping the file in git. The lines are added after every existing one, so they win over the file's own lines and those of the directories above. A references-only file and a template get none. The file's own bytes are kept as they are, UTF-8 or not; lines are only added after them. Written atomically, and only when something is missing, so a second run changes nothing.
- **the dry run**: the daemon checks every reference of the manifest, in `[env]` and each profile, resolves (`resolves`).

A symlinked or hard-linked `envcloak.toml` or `.gitignore`, or one another program changed meanwhile, is left alone and reported.

## Deleting plaintext

`envcloak init --delete-plaintext` takes the imported entries out of the project's env files only after all four conditions hold (SPEC §6.4, gate 16), in this order (`envcloak_scan::delete_plaintext`):

1. The daemon answers `import.verify` from the manifest it opens itself: every secret each file holds is committed in the item the manifest binds its variable to (committed means the vault's transaction is on disk: SQLite with `synchronous=FULL`, and `F_FULLFSYNC` on macOS), every reference resolves, and the Recovery Kit is confirmed. The refusals are `not_imported`, `unresolved_reference` and `recovery_kit_unconfirmed`, in that order. The answer says, entry by entry, which values the vault holds there (`stored`), and why the others are left out.
2. Each file with an entry the vault holds is read again, and must be the file checked (its stamp); its bytes go to the daemon, which writes an encrypted backup (`files.backup`, [VAULT.md](VAULT.md) "File backups") and answers once it is on disk. A failure is `files_backup_failed`.
3. The daemon answers `import.verify` again, now, and must hold the same entries as the first time (`changed` otherwise).
4. Each file is changed only when it is still the file read, has no other hard link, was not modified in the last two minutes (`recently_changed`), and is not open in another process as far as the system can tell (`open_elsewhere`). The question is about the open file itself: on Linux a write lease on its descriptor, refused while anyone else has the file open; on macOS `proc_listpidspath`, among your own processes, asked about the descriptor's current path (`F_GETPATH`), which must name the file before and after (`unchecked` otherwise). A file found open is kept at once, never waited for, and the whole stamp, change time included, is checked again right after the question.

Only the entries the vault holds leave a file; nothing that was never committed is deleted:

- A file whose every entry the vault holds is removed: renamed aside (`..env.envcloak-del-<hex>.tmp`), checked to be the file checked, then unlinked, so a file an editor saved over the name meanwhile is put back, never removed.
- A file that also holds entries that are not imported (configuration such as `PORT`, an interpolated value, which may hold a literal password, an `envcloak://` reference, a value the daemon takes for configuration, or a short value it compares only for a person, see "Who may compare values") is rewritten to hold those, byte for byte as they were, with its comments and blank lines: the new contents are written beside it (`..env.envcloak-new-<hex>.tmp`, the original's mode) and swapped with it in one step (Linux `RENAME_EXCHANGE`, macOS `RENAME_SWAP`); what comes out must be the file checked, or an editor saved over the name meanwhile, and the two are swapped back (`changed`), so its save is kept. On a file system that cannot swap names (macOS HFS+, some network and FUSE ones), the new contents are renamed over the file right after the last check instead. The report names every entry that stays, and why.
- A file with no entry the vault holds is left as it is, and not backed up.

The directory is flushed after each change. A crash at any point leaves each entry in its file or committed in the vault: nothing changes before step 3 has passed, and a crash inside a change leaves the file as it was, or its new contents, or the removed or replaced file under its temporary name, which the next scan reports (`leftover`) and the project's `.gitignore` keeps out of git (see "What is written"). Templates, references-only files, files with another hard link and files that do not parse are never changed. Deletion removes the working copy only: a value that was committed to git, synced or copied elsewhere is still there, and the report says to rotate it.

`envcloak recovery confirm` reads the kit from `/dev/tty` with echo off, or one line from the descriptor `--kit-fd` names (as `vault create --kit-fd` wrote it), checks its shape (a typo costs no attempt), and sends it to the daemon, which checks it opens the vault's Recovery Kit envelope. It is a proof, like the passphrase: only from a terminal session with no agent in it, counted by the attempt limiter.

## Undo

The report ends with the backup's id. `envcloak init --undo <ID>` asks the daemon for the backup's files (`files.restore`), which is a proof: the passphrase, from `/dev/tty` or `--passphrase-fd`, in a terminal session with no agent in it, since it hands plaintext back. Run it in the project: the statement before the passphrase names the project directory, and only env files directly in it are written back. A backup names its own paths, and any client may store one, so the daemon takes only env files' paths (`.env`, `.env.<suffix>`) in `files.backup`, and the undo reports a file of another name (`not_env_file`) or in another directory (`elsewhere`) without writing it. Each file is written where it was, with its mode, byte for byte, as a new file linked into place. A file that is there already is `unchanged` when it holds the same bytes; one that is what the deletion left of it (the original with some entries taken out whole, nothing else changed) is replaced with the original, as `.gitignore` is replaced (`restored`); any other is left alone (`exists`). The daemon removes file backups older than 7 days whenever it writes one, and at every unlock.

## Gates

| Gate | Where |
|---|---|
| 10: a value two items hold is reported for both, through the import's deduplication | `crates/envcloak-daemon/tests/import.rs` |
| 11, for import: reading and parsing a dotenv file leave no fixture in freed memory | `crates/envcloak-scan/tests/dotenv_probe.rs` |
| 15: a symlinked `.env` outside the root, a FIFO, a 2 GB file, a directory symlink loop, a hard link and an unreadable file: no hang, nothing followed or modified, no value in the report | `crates/envcloak-scan/tests/scan_safety.rs`, `crates/envcloak-cli/tests/import.rs` |
| 16: each condition refuses the deletion on its own; `kill -9` of `envcloak init --import --yes --delete-plaintext` at every step, inside each file's change too, leaves every entry in its file or committed where the manifest binds it, with configuration, interpolated values, a reference and a misread secret in the fixture | `crates/envcloak-scan/tests/delete.rs`, `crates/envcloak-cli/tests/import.rs` |
| Story S2 and S3: import, the kit confirmed, deletion, metadata-only `ls`, `show` and `check`, `init --undo` byte for byte | `crates/envcloak-cli/tests/import.rs` |
