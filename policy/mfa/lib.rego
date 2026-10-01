# METADATA
# title: MFA Enforcement - Core Logic
# description: >
#   Platform-agnostic decision logic for "every privileged account
#   must have MFA enabled". This package has no knowledge of AWS,
#   Azure, GCP, on-prem AD, or ICS/OT - it only understands a
#   normalized account record:
#
#     {"id": <string>, "privileged": <boolean>, "mfa_enabled": <boolean>}
#
#   Contract: adapters MUST always supply real booleans for
#   `privileged` and `mfa_enabled` (never missing or null) - do the
#   normalization in the adapter via `object.get(x, "field", false)`,
#   not here. That keeps this file platform-agnostic and keeps the
#   undefined/null handling in exactly one place per adapter.
#
#   Each platform adapter (aws.rego, azure.rego, gcp.rego,
#   onprem_ad.rego, ics_ot.rego) translates its own input into a list
#   of these records and calls `deny_messages` from its own `deny`
#   rule. To support a new platform, add a new adapter - this file
#   should never need to change.
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.mfa.lib

import rego.v1

# unprotected is the subset of accounts that are privileged and do
# not have MFA enabled.
unprotected(accounts) := {account |
	some account in accounts
	account.privileged
	account.mfa_enabled != true
}

# deny_messages renders one human-readable message per unprotected
# account. Adapters call this from their own `deny` rule so the
# messages surface under the adapter's own package.
deny_messages(accounts) := {msg |
	some account in unprotected(accounts)
	msg := sprintf("Privileged account '%s' does not have MFA enabled.", [account.id])
}
