#!/usr/bin/env bash
# M3-21 QA fixture builder: generates runtime synthetic keys and two project
# repositories (`acme-web` and `billing`), plus an executable `emit` helper and
# a fixture agent wrapper, inside a private directory. Never contains committed
# key literals.
set -euo pipefail

dest=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      dest="$2"
      shift 2
      ;;
    -h|--help)
      echo "usage: scripts/macos/qa-fixture.sh [--dir DIR | DIR]" >&2
      exit 0
      ;;
    *)
      dest="$1"
      shift
      ;;
  esac
done
if [[ -z "$dest" ]]; then
  dest="$(mktemp -d /tmp/ecqa.XXXXXXXX)"
fi
mkdir -p "$dest"
chmod 700 "$dest"

python3 - "$dest" <<'PY'
import base64
import hashlib
import os
import pathlib
import stat
import sys
import time

root = pathlib.Path(sys.argv[1]).resolve()
acme = root / "acme-web"
billing = root / "billing"
bin_dir = root / "bin"
acme.mkdir(mode=0o700, exist_ok=True)
billing.mkdir(mode=0o700, exist_ok=True)
bin_dir.mkdir(mode=0o700, exist_ok=True)

def token_hex(nbytes):
    return os.urandom(nbytes).hex()

# Build runtime synthetic values without any literal provider prefix in source.
openai_prefix = "".join(["s", "k", "-", "proj", "-"])
openai_val = openai_prefix + token_hex(24)
gh_prefix = "".join(["g", "h", "p", "_"])
gh_val = gh_prefix + token_hex(20)
db_val = "postgres://app:" + token_hex(16) + "@db.acme.internal:5432/acme"
short_val = "short-" + token_hex(6)
stripe_prefix = "".join(["s", "k", "_", "live", "_"])
stripe_val = stripe_prefix + token_hex(20)
stripe_test_prefix = "".join(["s", "k", "_", "test", "_"])
stripe_test_val = stripe_test_prefix + token_hex(20)
webhook_val = "whsec_" + token_hex(20)

backdated = time.time() - 600.0

acme_env = acme / ".env"
acme_env.write_text(
    f"OPENAI_API_KEY={openai_val}\n"
    f"GITHUB_TOKEN={gh_val}\n"
    f"DATABASE_URL={db_val}\n"
    f"SHORT_TOKEN={short_val}\n"
    "PORT=3000\n",
    encoding="utf-8",
)
os.chmod(acme_env, 0o600)
os.utime(acme_env, (backdated, backdated))

billing_env = billing / ".env"
billing_env.write_text(
    f"STRIPE_SECRET_KEY={stripe_val}\n"
    f"STRIPE_TEST_KEY={stripe_test_val}\n"
    f"BILLING_WEBHOOK_SECRET={webhook_val}\n",
    encoding="utf-8",
)
os.chmod(billing_env, 0o600)
os.utime(billing_env, (backdated, backdated))

emit_script = acme / "emit"
emit_script.write_text(
    "#!/usr/bin/env python3\n"
    "import hashlib, os\n"
    "val = os.environ.get('OPENAI_API_KEY', '')\n"
    "digest = hashlib.sha256(val.encode('utf-8')).hexdigest()\n"
    "print(f'sha256:{digest}')\n"
    "print(f'raw:{val}')\n",
    encoding="utf-8",
)
os.chmod(emit_script, stat.S_IRWXU)

agent_wrapper = bin_dir / "fixture-agent"
agent_wrapper.write_text(
    "#!/usr/bin/env bash\n"
    "export CLAUDECODE=1\n"
    "exec \"$@\"\n",
    encoding="utf-8",
)
os.chmod(agent_wrapper, stat.S_IRWXU)

summary = {
    "root": str(root),
    "acme_web": str(acme),
    "billing": str(billing),
    "fixture_agent": str(agent_wrapper),
    "openai_sha256": hashlib.sha256(openai_val.encode("utf-8")).hexdigest(),
}
import json
(root / "fixture-meta.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
os.chmod(root / "fixture-meta.json", 0o600)
print(str(root))
PY
