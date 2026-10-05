# Dev sign-in

The pure enrollment parser and TOTP engine are implemented in
`envcloak-signin` (M2b-03a). They perform no I/O and grant no authority.
Login commands, credential readers, account serialization, attempt leases,
submitted-step tracking and daemon integration remain M2b-03b's work.
No sign-in behavior ships from this library change alone.

## TOTP enrollment

`otpauth::parse` takes a `SecretBytes`, never a command-line argument.
It accepts this subset of the [Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

- Exact lowercase `otpauth://totp/`, one nonempty label, then `?` and
  ampersand-separated `name=value` parameters. No userinfo, port, fragment,
  additional path component, raw whitespace, control byte or backslash.
- Required `secret`: nonempty unpadded RFC 4648 base32. Uppercase and
  lowercase letters are accepted; spaces, padding, nonalphabet bytes,
  impossible lengths and nonzero unused tail bits are refused.
- Optional `algorithm`: exactly `SHA1`, `SHA256` or `SHA512`, default `SHA1`.
- Optional `digits`: exactly `6` or `8`, default `6`.
- Optional `period`: canonical positive decimal seconds, at most `u64::MAX`,
  default `30`. No sign, leading zeroes, fraction or overflow.
- Optional `issuer` and the label are display-only, never an account,
  origin or authority input. Both are stored as `SecretBytes`. A label may
  contain one colon separating a nonempty issuer prefix and account. An
  issuer parameter need not equal that prefix; neither is trusted identity.
- Values and labels may use `%HH` escapes, decoded exactly once. Text must
  be valid UTF-8 without control or bidi-format characters. Raw non-ASCII
  bytes and `+` are refused: spaces must be `%20`. Parameter names are
  literal lowercase ASCII, never percent-decoded. Unknown and duplicate
  parameters, empty fields and malformed escapes fail.

Caps: 4096 input bytes, 512 decoded seed bytes, 256 decoded bytes per label
or issuer. Caps refuse the whole enrollment; nothing is truncated. Secret
strength and account policy are the daemon's responsibility. Every parser
failure has the same value-free `invalid_otpauth` message. Formatting a
specification or a generated code prints only a fixed type marker.

## Calculation and time

`totp::code` implements [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)
with an explicit `u64` step, SHA-1/SHA-256/SHA-512 and fixed-width six or
eight decimal digits. `TotpParams::new` checks the width and period. `Code`
exposes only a reference to its wiping `SecretBytes`; opening those bytes
still requires the repository's reviewed exposure boundary.

The clock helpers take Unix seconds and a validated `Period`:

- `step_at` uses integer floor division from Unix epoch zero.
- `seconds_left` includes the current second; at a boundary it is the full
  period. `too_late_in_step` is true when three seconds or fewer remain.
  Periods of one to three seconds therefore never have an eligible instant.
- `refused_after_start` returns the start's current and previous steps. At
  epoch step zero it returns `[0, 0]`, since no previous step exists.

The daemon must retain that pair from its own start, serialize attempts by
account, remember submitted steps, refuse reuse and validate the lease and
clock again immediately before submission. These helpers do not enforce
that stateful policy. Codes generated earlier are not evidence of current
eligibility. The primitive accepts arbitrary HMAC seed bytes; enrollment
validation belongs to the parser and future login boundary.

## Independent checks

`tests/oracles/totp_oracle.py` adapts the independent Cycle206 oracle. Its
calculation, RFC hash references, mutant controls and separate Node
composition are preserved; deterministic synthetic input generation and
local fixture I/O replace its review-workspace adapter. The published
vectors use the algorithm-specific seed lengths in verified RFC erratum
2866 (20, 32 and 64 bytes). Six-digit expectations are independently
computed reductions, also checked against the published eight-digit
results' six-digit suffix hashes. Expected values are checked in as byte
arrays and loaded from disk, never printed in assertion diagnostics.

Run the generator with isolated HOME/TMPDIR and a PATH containing Python
and Node; `python3 -I -B crates/envcloak-signin/tests/oracles/totp_oracle.py`
checks fixture freshness, both implementations, all offset witnesses and
positive/mutation controls. `--write` regenerates the fixture.

The parser uses Python's independent base32 encoding in those same
fixtures. `tests/otpauth.rs` also provides bounded arbitrary-byte and
mutated-valid-input fuzzing. This checkout has no `fuzz/` workspace;
M2-25 owns its libFuzzer infrastructure because its entry macro conflicts
with the workspace's unsafe-code boundary. No libFuzzer run is claimed.
