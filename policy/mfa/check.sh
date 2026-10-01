#!/usr/bin/env bash
# One-command MFA check: runs the platform's collector, evaluates it
# against policy/mfa, and exits non-zero if any privileged account
# lacks MFA. Intended for both manual terminal use and CI pipelines.
#
# Usage:
#   ./check.sh aws
#   ./check.sh azure
#   ./check.sh gcp
#   ./check.sh onprem_ad   # after editing collectors/onprem_ad_collect.ps1
#   ./check.sh ics_ot      # after editing collectors/ics_ot_collect.sh
#
# Optional: pass a config.json to override privileged-role defaults:
#   ./check.sh aws config.json
set -euo pipefail

command -v opa >/dev/null || { echo "opa not found in PATH - https://www.openpolicyagent.org/docs/#running-opa" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }

platform="${1:-}"
config="${2:-}"

if [ -z "$platform" ]; then
	echo "Usage: $0 <aws|azure|gcp|onprem_ad|ics_ot> [config.json]" >&2
	exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sh_collector="$script_dir/collectors/${platform}_collect.sh"
ps1_collector="$script_dir/collectors/${platform}_collect.ps1"

if [ -f "$sh_collector" ]; then
	collector_cmd=("$sh_collector")
elif [ -f "$ps1_collector" ]; then
	if command -v pwsh >/dev/null; then
		collector_cmd=(pwsh -NoProfile -File "$ps1_collector")
	elif command -v powershell.exe >/dev/null; then
		collector_cmd=(powershell.exe -NoProfile -File "$ps1_collector")
	else
		echo "Found $ps1_collector but neither pwsh nor powershell.exe is in PATH" >&2
		exit 1
	fi
else
	echo "Unknown platform '$platform' (expected aws, azure, gcp, onprem_ad, or ics_ot)" >&2
	exit 2
fi

eval_args=(-I -d "$script_dir" "data.policy.mfa.${platform}.deny" --format json)
[ -n "$config" ] && eval_args=(-d "$config" "${eval_args[@]}")

violations=$("${collector_cmd[@]}" | opa eval "${eval_args[@]}" | jq -r '.result[0].expressions[0].value[]?')

if [ -n "$violations" ]; then
	echo "FAIL: privileged accounts without MFA:" >&2
	echo "$violations" | sed 's/^/  - /' >&2
	exit 1
fi

echo "PASS: no privileged accounts without MFA ($platform)"
