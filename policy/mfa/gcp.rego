# METADATA
# title: MFA Enforcement Adapter - Google Cloud / Workspace
# description: >
#   Normalizes Admin SDK Directory API user records into
#   policy.mfa.lib's canonical account shape.
#
#   Expected input - the `users` array from the Directory API
#   `users.list` endpoint:
#
#     {
#       "users": [
#         {
#           "primaryEmail": "alice@example.com",
#           "isAdmin": true,
#           "isDelegatedAdmin": false,
#           "isEnrolledIn2Sv": false
#         }
#       ]
#     }
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.mfa.gcp

import data.policy.mfa.lib
import rego.v1

default is_privileged(_) := false

is_privileged(user) if object.get(user, "isAdmin", false) == true

is_privileged(user) if object.get(user, "isDelegatedAdmin", false) == true

accounts := [account |
	some user in input.users
	account := {
		"id": user.primaryEmail,
		"privileged": is_privileged(user),
		"mfa_enabled": object.get(user, "isEnrolledIn2Sv", false) == true,
	}
]

deny contains msg if {
	some msg in lib.deny_messages(accounts)
}
