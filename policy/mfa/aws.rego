# METADATA
# title: MFA Enforcement Adapter - AWS IAM
# description: >
#   Normalizes AWS IAM data into policy.mfa.lib's canonical account
#   shape and flags privileged IAM users without MFA.
#
#   A user counts as privileged if ANY of the following is true -
#   admin access is most commonly granted via group membership, not a
#   direct attachment, so all three have to be checked:
#     - a managed policy in `privileged_policy_arns` is attached
#       directly to the user (attached_policy_arns)
#     - a managed policy in `privileged_policy_arns` is attached to a
#       group the user belongs to (group_attached_policy_arns)
#     - an inline policy document on the user has an Allow statement
#       with Action "*" and Resource "*" (inline_policy_documents).
#       This is a heuristic for "equivalent to AdministratorAccess,"
#       not a full IAM policy evaluator - it does not handle
#       NotAction, Condition keys, or Deny-statement overrides. Use
#       `aws iam simulate-principal-policy` if you need more
#       precision than this.
#
#   Expected input - merge the output of `aws iam list-mfa-devices`,
#   `aws iam list-attached-user-policies`, `aws iam
#   list-attached-group-policies` (for each of the user's groups via
#   `aws iam list-groups-for-user`), and `aws iam get-user-policy`
#   (for each name from `aws iam list-user-policies`) per user - see
#   collectors/aws_collect.sh, which does this for you:
#
#     {
#       "users": [
#         {
#           "username": "alice",
#           "mfa_active": false,
#           "attached_policy_arns": [
#             "arn:aws:iam::aws:policy/AdministratorAccess"
#           ],
#           "group_attached_policy_arns": [],
#           "inline_policy_documents": []
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

privileged_policy_arns := data.mfa.aws.privileged_policy_arns

default is_privileged(_) := false

is_privileged(user) if {
	some arn in object.get(user, "attached_policy_arns", [])
	arn in privileged_policy_arns
}

is_privileged(user) if {
	some arn in object.get(user, "group_attached_policy_arns", [])
	arn in privileged_policy_arns
}

is_privileged(user) if {
	some doc in object.get(user, "inline_policy_documents", [])
	has_admin_equivalent_statement(doc)
}

# has_admin_equivalent_statement is a heuristic (see METADATA above):
# it flags an Allow statement granting Action "*" on Resource "*".
has_admin_equivalent_statement(doc) if {
	some statement in as_array(doc.Statement)
	statement.Effect == "Allow"
	"*" in as_array(statement.Action)
	"*" in as_array(statement.Resource)
}

# as_array normalizes an AWS policy field that may legally be either
# a single string or an array of strings into always an array.
as_array(x) := x if is_array(x)

as_array(x) := [x] if is_string(x)

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
