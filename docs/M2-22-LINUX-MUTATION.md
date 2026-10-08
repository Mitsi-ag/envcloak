# M2-22 Linux tracer mutation handoff

The Linux baseline passes at `ab26e52f` in driver-reported CI runs
37716095057 and 37716104417. L-01 still needs the negative control below.
The macOS engineer cannot qualify Linux tracing and is instructed not to
push or dispatch workflows. The driver owns these steps.

Use a disposable checkout and branch from the final M2-22 repair commit.
Change only the initial refusal in `crates/envcloak-cli/src/cmd/scrub.rs`:

```python
from pathlib import Path

path = Path("crates/envcloak-cli/src/cmd/scrub.rs")
source = path.read_text()
before = "let result = refuse_if_traced().and_then(|()| {"
after = "let result = (if false { refuse_if_traced() } else { Ok(()) }).and_then(|()| {"
assert source.count(before) == 1
path.write_text(source.replace(before, after))
```

Mutation name: `skip_initial_scrub_tracer_refusal`. Keeping the unreachable
call keeps the import used, so strict warning checks do not turn this into
a compilation failure. Format the source, commit to the disposable branch,
and dispatch the existing `ci.yml` workflow on that branch. Its Linux gates
step already runs the full CLI scrub target. The target must compile and
`gate37_traced_scrub_refuses_before_reading_plaintext` must fail at a runtime
assertion. A compiler error, timeout or a different test failure is not a
qualifying receipt.

Record the failing run URL, SHA and assertion in M2-22-VALIDATION.md. Restore
the source in the disposable checkout and run the same gate again; attach
the restored passing receipt too. Do not merge the mutation. This handoff
is executable instructions, not a claim that the mutation has run.
