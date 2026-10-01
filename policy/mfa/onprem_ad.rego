# METADATA
# title: MFA Enforcement Adapter - On-Premises Active Directory
# description: >
#   Vanilla AD has no native MFA concept, so this adapter expects a
#   pre-joined document: AD group membership joined against your MFA
#   provider's (Duo/RSA/RADIUS/etc.) enrollment export. Producing that
#   join is outside Rego's scope - do it once in whatever script pulls
#   both sources (e.g. `Get-ADGroupMember` plus your MFA vendor's API).
#
#   Expected input:
#
#     {
#       "accounts": [
#         {
#           "sam_account_name": "alice",
#           "member_of": ["Domain Admins"],
#           "mfa_enrolled": false
#         }
#       ]
#     }
#
#   Customize which groups count as privileged via config.json rather
#   than editing this file:
#
#     {"mfa": {"onprem_ad": {"privileged_groups": ["Domain Admins", "Enterprise Admins"]}}}
#
#   Note: a user in more than one privileged group produces one
#   `accounts` entry per group they're in (harmless - lib.deny_messages
#   renders the same message string for each, and messages are a set,
#   so the duplicates collapse). This only matters if you inspect
#   `accounts` directly rather than the final `deny` output.
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.mfa.onprem_ad

import data.policy.mfa.lib
import rego.v1

default privileged_groups := ["Domain Admins", "Enterprise Admins", "Schema Admins"]

privileged_groups := data.mfa.onprem_ad.privileged_groups

default is_privileged(_) := false

is_privileged(account) if {
	some group in object.get(account, "member_of", [])
	group in privileged_groups
}

accounts := [account |
	some raw in input.accounts
	account := {
		"id": raw.sam_account_name,
		"privileged": is_privileged(raw),
		"mfa_enabled": object.get(raw, "mfa_enrolled", false) == true,
	}
]

deny contains msg if {
	some msg in lib.deny_messages(accounts)
}
