#!/usr/bin/env bash
# M3-21 manual QA runner (`docs/APP.md` "Manual QA script").
# Records the macOS build, commit, and result of each step A1..A20.
# Interactive Touch ID steps are never reported as passed unless run interactively
# on the clean QA account and confirmed by the operator.
set -euo pipefail

cd "$(dirname "$0")/../.."

non_interactive=0
output_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive)
      non_interactive=1
      shift
      ;;
    --output)
      output_file="$2"
      shift 2
      ;;
    *)
      echo "usage: scripts/macos/qa-run.sh [--non-interactive] [--output <path>]" >&2
      exit 2
      ;;
  esac
done

macos_version="$(sw_vers -productVersion)"
macos_build="$(sw_vers -buildVersion)"
commit_sha="$(git rev-parse --short HEAD)"

steps=(
  "A1|first launch, background item|R-M3-08|interactive"
  "A2|vault, projects, unlock in Terminal|M1 S1|scripted"
  "A3|add Touch ID, approved once in Terminal|R-M3-21|interactive"
  "A4|unlock with Touch ID, twice|g2, g3|interactive"
  "A5|paste sheet, bindings, undo|R-M3-05, R-M3-F1|scripted"
  "A6|an agent's request, the notification||scripted"
  "A7|approve with Touch ID, twice|g3, gate 8|interactive"
  "A8|cancel, deny, auto-deny|gate 32|interactive"
  "A9|replace and remove with Touch ID|SPEC 10b|interactive"
  "A10|reveal and copy, the 30-second clear|g6|interactive"
  "A11|Activity, verify log|gate 33|scripted"
  "A12|screen lock|g7|interactive"
  "A13|rollback|g5|scripted"
  "A14|forged app peers, and the genuine app run by the fixture agent|g4, gates 22 and 23|scripted"
  "A15|a forged daemon|g1, gate 21|scripted"
  "A16|envcloak reveal from a person and an agent|R-M3-30|scripted"
  "A17|envcloak add --ask from an agent|R-M3-26|scripted"
  "A18|first-run scan screen|R-M3-38|scripted"
  "A19|menu bar search, revoke, lock||scripted"
  "A20|the canary sweep|gate 12|scripted"
)

report_lines=()
report_lines+=("# EnvCloak M3 Manual QA Report")
report_lines+=("- macOS: ${macos_version} (${macos_build})")
report_lines+=("- Commit: ${commit_sha}")
report_lines+=("")
report_lines+=("| Step | Description | Gates | Result |")
report_lines+=("|---|---|---|---|")

for entry in "${steps[@]}"; do
  IFS='|' read -r step_id desc gates mode <<< "$entry"
  if [[ "$non_interactive" -eq 1 ]]; then
    status="not run (requires clean QA account + Touch ID)"
  else
    printf "== %s: %s (%s) ==\n" "$step_id" "$desc" "$gates"
    read -r -p "Result for ${step_id} [pass/fail/skip] (default: skip): " ans
    case "${ans:-skip}" in
      pass) status="passed (${macos_build}, ${commit_sha})" ;;
      fail) status="failed (${macos_build}, ${commit_sha})" ;;
      *) status="not run" ;;
    esac
  fi
  report_lines+=("| ${step_id} | ${desc} | ${gates} | ${status} |")
done

if [[ -n "$output_file" ]]; then
  printf "%s\n" "${report_lines[@]}" > "$output_file"
else
  printf "%s\n" "${report_lines[@]}"
fi
