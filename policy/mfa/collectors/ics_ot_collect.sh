#!/usr/bin/env bash
# TEMPLATE - not a drop-in script. There is no vendor-neutral API
# across PAM/VPN/jump-host tools for OT remote-access profiles
# (CyberArk, Claroty, Dragos, a plain VPN concentrator's config all
# differ). Replace fetch_profiles() below with a call into whichever
# tool brokers remote access into your OT network, returning the
# fields shown.
#
# Usage once wired up:
#   ./ics_ot_collect.sh > input.json
set -euo pipefail

command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }

fetch_profiles() {
	# EDIT ME: replace this with a real call into your PAM/VPN tool's
	# API or export, returning a JSON array of objects shaped like:
	#   {"profile_name": "...", "grants_ot_network_access": true, "mfa_required": false}
	echo "fetch_profiles() is not implemented - wire this up to your PAM/VPN tool's API." >&2
	exit 1
}

jq -n --argjson profiles "$(fetch_profiles)" '{remote_access_profiles: $profiles}'
