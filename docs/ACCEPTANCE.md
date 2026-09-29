# EnvCloak: M1 acceptance

Status: M1. This file says how the M1 acceptance story (SPEC §15.1) and every M1 gate (SPEC §15.2, gates 1 to 33) are tested, and where. M1 is done when the story and every gate pass on `macos-latest` and `ubuntu-latest` in CI (`.github/workflows/ci.yml`). The story's code is in `crates/envcloak-e2e/`.

## The story

`crates/envcloak-e2e/tests/fixture_story.rs` runs the story as one ordered test, on the built `envcloak` and `envcloakd`, in one isolated user: `HOME` and every `XDG_*` directory under a short `/tmp/ecXXXXXX` (so the socket path stays under macOS's 104-byte `sun_path`), a cleared environment for every process, and `envcloakd --foreground` started by absolute path.

- **The person** runs each command leading a session on a pseudo-terminal of its own, as in a terminal window, with no agent in its ancestry. What a command asks for on the terminal is typed when its prompt shows, waiting for the prompt's text, never for a time. Secrets on descriptors (`--passphrase-fd`, `--kit-fd`) come from files outside the home.
- **The agent** is `fixture-agent` (crates/envcloak-testkit), which the builtin catalog knows, running one shell for the whole story, with no terminal. A grant is scoped to that process instance, so it covers the agent's later commands.
- **The fixture repo** `acme-web` is generated at run time from `envcloak-testkit`'s canaries: `OPENAI_API_KEY` (an `sk-proj-` prefix, 64 bytes), `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `DATABASE_URL` (a password with `/`, `"`, `+`, a space and a non-ASCII character), `SHORT_TOKEN` (10 bytes, in `.env.short`, so in the `short` profile only), `PORT=8080`, and a `.env.example`. No key-shaped literal is in the source.
- **Its command** `./emit` (`crates/envcloak-e2e/tests/fixtures/emitters/emit.py`) puts each value through every serializer gate 8 names: Python's `json.dumps` (`ensure_ascii` true and false), `quote` and `quote_plus` in upper and lower hex, form encoding, standard and URL-safe base64, padded and unpadded, at offsets 0, 1 and 2 of a larger payload, and lower and upper hex; Node's `JSON.stringify` (`emit.js`), Go's `encoding/json` (`emit.go`), .NET's `System.Text.Json` (`Emit.cs`), PHP's `json_encode` (`emit.php`) and serde_json (`ec-emit-serde`). Each result is written whole and in pieces, on standard output and standard error at once: every byte boundary of `DATABASE_URL`'s results, three boundaries of the others', with a 45 ms pause after each piece (the runner flushes after 40 ms idle), then bytes that are not UTF-8 around halves of a value. Last, each serializer prints the SHA-256 of each value it was given.
- **The sweep** runs after every step: everything any process printed, every daemon's log (the one S11 stops too), and the whole home with the fixture repo in it, for every canary (the values, the passphrases, a wrong passphrase typed once, the Recovery Kit) in every encoding `envcloak-testkit` knows, and for what each serializer made of each value, run outside EnvCloak before the story starts and loaded as bytes. Only the fixture repo's `.env` files are skipped, until S2 takes their secrets out.

| Step | What the test checks |
|---|---|
| S1 | `vault create --passphrase-fd 3 --kit-fd 4 --kdf-memory 64MiB`: created and unlocked; the kit went only to descriptor 4 |
| S2 | `init --import` (dry run, nothing written), then `init --import --yes`: every entry mapped to its item, providers detected, `envcloak.toml` and `.gitignore` created, every reference resolves. `init --delete-plaintext` is refused with `recovery_kit_unconfirmed` and changes nothing; after `recovery confirm --kit-fd 4` it deletes `.env.short`, rewrites `.env` to what was not imported (`PORT=8080` and a comment), and the encrypted file backup exists |
| S3 | `ls`, `show openai/acme-web` and `check` by the agent: metadata only. `status` says "daemon identity: unverified", and "hardened" or "unhardened" as `codesign` (macOS) or `/proc` (Linux) says |
| S4 | The agent's `run -- ./emit`: exit 125, `approval_required request=<ID>`, no output from the command, and the daemon's audit line `decision=pending id=<ID>` |
| S5 | `approve <ID> --for 1h` on the person's terminal: the statement shows the escaped command line, every binding, the agent and "new project"; a wrong passphrase is refused and counted (`status`: one failed proof); the right one makes the grant |
| S6 | The agent's run: exit 0; every serializer ran, every result's frames went through, markers stand where the values were, and every serializer's digest of every value matches. `run --profile short` needs its own approval, then exits 125 with `value_too_short`, naming the item, and starts nothing |
| S7 | `rotate openai/acme-web --stdin`, the new value on standard input and the passphrase typed on the terminal: one prior value kept; both grants stay |
| S8 | The agent's rerun: the digests of `OPENAI_API_KEY` are the new value's; neither value, nor any serializer's form of either, appears |
| S9 | The agent's `lock`, then its run: exit 125, `vault_locked`; `grants list` is empty |
| S10 | `unlock` on the person's terminal; the agent's run is `approval_required` again |
| S11 | `backup create`; the daemon stops (SIGTERM); `vault/` is deleted; a new daemon starts; `recover --backup <file> --kit-fd 4 --new-passphrase-fd 3`: restored and unlocked with 5 items; `ls` equals the listing before the backup (and S3's, apart from the rotation's date); after an approval with the new passphrase, the run's digests are the rotated value's |
| S12 | `audit verify`: no problem, the anchor matched, and the unanchored tail reported when there is one |
| S13 | The last sweep: nothing anywhere; `vault/`, `audit/` and `backups/` hold ciphertext only |

## Gate 12

`crates/envcloak-e2e/tests/gate12.rs`, with `RUST_LOG=trace` and `RUST_BACKTRACE=full` in every process:

- **Injected panics.** Both binaries print a panic's place in the source and never its message (`envcloak_sys::install_panic_hook`), and no backtrace. `envcloak internal panic` and `envcloakd internal panic` panic with what standard input holds, in every build. The test build also panics on request at places on a value path (`envcloak_sys::panic_point`, feature `testing`, which no release build has): the CLI holding a run's released values (`cli.run.released`), the CLI holding an env file's parsed values (`cli.import.parsed`), and the daemon about to send a run's values (`daemon.release`). Each message holds a fixture; none shows anywhere.
- **Malformed inputs holding fixtures.** Values on the command line wherever a name or an id goes, and in an argument that is not UTF-8; a manifest with a value where a reference goes, one that is not TOML, and one with a value as a variable name; env files whose broken lines hold values, for `init`, `import --scan`, `check` and `run --env-file`; a value where the Recovery Kit or a passphrase goes, and a value with a NUL byte on standard input; frames sent straight to the daemon's socket with a value as the method, as an unknown field, JSON-escaped where base64 goes, as a slug, in a request's paths and names, as the whole body, and after an oversized header.

CI also runs the whole workspace's suite at `RUST_LOG=trace` and `RUST_BACKTRACE=full`, and `TestHome` passes both settings on to every process the tests start (they choose what a program logs and hold no secret). No EnvCloak program reads `RUST_LOG` yet: M1 has no logger, and the daemon's log is the fixed lines it writes to standard error. The setting is kept so that logging added later runs at its most verbose under the same sweeps. Gate 12 rests on `gate12.rs`, the fixture story (swept after every step), and the sweeps of the tests that start processes with fixtures, each of which sweeps the streams and logs it captures, among them the service-managed daemon's log in `crates/envcloak-cli/tests/service.rs`.

## The release artifacts

CI's `release` job builds the binaries as shipped (`cargo build --release`: `panic = "abort"`, LTO, stripped) and runs `crates/envcloak-e2e` against them (`ENVCLOAK_E2E_BIN_DIR`, `ENVCLOAK_TEST_RELEASE_DIR`):

- `tests/release.rs`: a panic aborts (SIGABRT, where the test build, the control, exits 101), with the handler's one line and no message; started with the core limit raised, and on macOS signed with `get-task-allow`, an aborting release binary leaves no core file, while the positive control does dump core into `ENVCLOAK_TEST_CORE_DIR`; the names of the test-only hooks are in the test build and in neither release binary; `internal hardening` and `status` say what `codesign` or `/proc` says, and "daemon identity: unverified";
- the fixture story and gate 12, on the release binaries (the panic points exist only in the test build, and are skipped there).

## Every M1 gate

| Gate | Where |
|---|---|
| 1, 2 (crypto), 3 | `crates/envcloak-core/tests/seal_tamper.rs`, `crypto_kat.rs`; CRYPTO.md |
| 2 (storage), 5, 6, 7 | VAULT.md "Gates" |
| 3 (re-wrap), 4 | VAULT.md "Gates"; 4 through the daemon and the CLI (S11): IPC.md "Gates", and the story |
| 8, 9, 13, 14, 33 (release order) | RUN.md "Gates"; 8 through the whole of `run`, and 9's `--profile short`: the story (S6, S8) |
| 10, 15, 16 | IMPORT.md "Gates"; the story (S2) |
| 11 | `crates/envcloak-sys/tests/alloc_probe.rs` and the probes each doc's "Gates" names (IPC frames, dotenv, TOML and JSON parsing, seal and open, the child's environment, the redactor) |
| 12 | `crates/envcloak-e2e/tests/gate12.rs`, `release.rs`, the fixture story, and every test's sweep of what it captures (the suite runs at `RUST_LOG=trace` for logging to come) |
| 17 | MANIFEST.md "Gates" |
| 18 | PROVIDERS.md "Gates" |
| 19 | `crates/envcloak-cli/tests/hardening.rs`, `crates/envcloak-daemon/tests/hardening.rs`, `crates/envcloak-sys/tests/{harden,tracer,codesign}.rs`; for the release artifacts, `crates/envcloak-e2e/tests/release.rs` |
| 20, 21, 22, 32 (frames) | IPC.md "Gates" |
| 23, 24, 27 to 32 | GRANTS.md "Gates"; 23's wrong passphrase and 29's lock: the story (S5, S9, S10) |
| 25, 26 | AGENTS.md; GRANTS.md "Gates" |
| 33 | IPC.md and VAULT.md "Gates"; the story (S4, S12) |

## Running it

`cargo test --workspace` runs everything. The story needs `python3` (it drives the terminals), and uses whichever of `node`, `go`, `dotnet` and `php` are on `PATH`, building the Go and .NET emitters under the target directory; set `ENVCLOAK_TEST_REQUIRE_EMITTERS` (a comma list of `python`, `node`, `go`, `dotnet`, `php` and `serde`) to make a missing one a failure, as CI does. The daemon takes a proof only from a terminal session with no agent in its ancestry (SPEC §10b), so run the tests outside an AI coding agent's process tree: under one, every approval is refused, as it must be. Tests that start daemons run one at a time within each test binary, since Argon2id's memory times parallel vaults can exhaust a runner.
