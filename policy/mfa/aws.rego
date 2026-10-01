# METADATA
# title: MFA Enforcement Adapter - AWS IAM
# description: >
#   Normalizes AWS IAM data into policy.mfa.lib's canonical account
#   shape and flags privileged IAM users without MFA.
#
#   Expected input - merge the output of
#   `aws iam generate-credential-report` (for mfa_active) with
#   `aws iam list-attached-user-policies` (for attached_policy_arns)
#   per user:
#
#     {
#       "users": [
#         {
#           "username": "alice",
#           "mfa_active": false,
#           "attached_policy_arns": [
#             "arn:aws:iam::aws:policy/AdministratorAccess"
#           ]
#         }
#       ]
#     }
#
#   To customize which managed policies count as "privileged" for
#   your org, don't edit this file - add an override to your own
#   config.json and load it alongside this policy (e.g.
#   `opa eval -d config.json -d policy/mfa ...`):
#
#     {"mfa": {"aws": {"privileged_policy_arns": ["arn:aws:iam::aws:policy/YourCustomAdminPolicy"]}}}
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.mfa.aws

import data.policy.mfa.lib
import rego.v1

default privileged_policy_arns := [
	"arn:aws:iam::aws:policy/AdministratorAccess",
	"arn:aws:iam::aws:policy/PowerUserAccess",
	"arn:aws:iam::aws:policy/IAMFullAccess",
]

privileged_policy_arns := data.config.mfa.aws.privileged_policy_arns

default is_privileged(_) := false

is_privileged(user) if {
	some arn in object.get(user, "attached_policy_arns", [])
	arn in privileged_policy_arns
}

accounts := [account |
	some user in input.users
	account := {
		"id": user.username,
		"privileged": is_privileged(user),
		"mfa_enabled": object.get(user, "mfa_active", false) == true,
	}
]

deny contains msg if {
	some msg in lib.deny_messages(accounts)
}
