#!/usr/bin/env bash
# Collects Google Workspace user records and prints them in the shape
# policy/mfa/gcp.rego expects. Prints JSON to stdout; writes nothing
# to disk.
#
# Prerequisites:
#   - A GOOGLE_ACCESS_TOKEN environment variable holding an OAuth 2.0
#     access token for a principal with the
#     https://www.googleapis.com/auth/admin.directory.user.readonly
#     scope. The Admin SDK Directory API requires either a Workspace
#     super-admin user token, or a service account with domain-wide
#     delegation impersonating one - there is no `gcloud auth
#     print-access-token` shortcut for this API. See:
#     https://developers.google.com/admin-sdk/directory/v1/guides/delegation
#   - curl, jq
#
# Usage:
#   GOOGLE_ACCESS_TOKEN=$(your-token-retrieval-command) ./gcp_collect.sh > input.json
#   ./gcp_collect.sh | opa eval -I -d .. "data.policy.mfa.gcp.deny"
set -euo pipefail

command -v curl >/dev/null || { echo "curl not found in PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }
: "${GOOGLE_ACCESS_TOKEN:?Set GOOGLE_ACCESS_TOKEN - see prerequisites comment at the top of this script}"

all_records="[]"
page_token=""

while :; do
	url="https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500"
	[ -n "$page_token" ] && url="${url}&pageToken=${page_token}"

	response=$(curl -sS -H "Authorization: Bearer ${GOOGLE_ACCESS_TOKEN}" "$url")
	page=$(jq '[.users[]? | {primaryEmail, isAdmin, isDelegatedAdmin, isEnrolledIn2Sv}]' <<<"$response")
	all_records=$(jq -n --argjson acc "$all_records" --argjson page "$page" '$acc + $page')

	page_token=$(jq -r '.nextPageToken // empty' <<<"$response")
	[ -z "$page_token" ] && break
done

jq -n --argjson users "$all_records" '{users: $users}'
