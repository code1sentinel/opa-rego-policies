#!/usr/bin/env bash
# Collects Entra ID (Azure AD) user registration details and prints
# them in the shape policy/mfa/azure.rego expects. Prints JSON to
# stdout; writes nothing to disk.
#
# Prerequisites:
#   - Azure CLI, authenticated (`az login`) as a principal with Graph
#     API permission to read authenticationMethods report data
#     (e.g. the Reports Reader or Global Reader directory role, or an
#     app registration granted AuditLog.Read.All + User.Read.All).
#   - Azure AD Premium P1/P2 licensing is required for the tenant for
#     this report to return data.
#   - jq
#
# Usage:
#   ./azure_collect.sh > input.json
#   ./azure_collect.sh | opa eval -I -d .. "data.policy.mfa.azure.deny"
set -euo pipefail

command -v az >/dev/null || { echo "az CLI not found in PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }

url="https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
all_records="[]"

while [ -n "$url" ] && [ "$url" != "null" ]; do
	response=$(az rest --method GET --url "$url" --output json)
	page=$(jq '[.value[] | {userPrincipalName, isAdmin, isMfaRegistered}]' <<<"$response")
	all_records=$(jq -n --argjson acc "$all_records" --argjson page "$page" '$acc + $page')
	url=$(jq -r '."@odata.nextLink" // empty' <<<"$response")
done

jq -n --argjson records "$all_records" '{registration_details: $records}'
