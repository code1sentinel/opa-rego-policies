# METADATA
# title: MFA Enforcement Adapter - Azure AD / Entra ID
# description: >
#   Normalizes Microsoft Graph user-registration-detail records into
#   policy.mfa.lib's canonical account shape.
#
#   Expected input - the `value` array from
#   `GET /reports/authenticationMethods/userRegistrationDetails`:
#
#     {
#       "registration_details": [
#         {
#           "userPrincipalName": "alice@contoso.com",
#           "isAdmin": true,
#           "isMfaRegistered": false
#         }
#       ]
#     }
#
#   To flag accounts that are privileged without holding an Entra ID
#   admin role (e.g. a break-glass or automation account), add an
#   override to your own config.json rather than editing this file:
#
#     {"mfa": {"azure": {"extra_privileged_upns": ["svc-deploy@contoso.com"]}}}
#
#   Known gap: `isAdmin` reflects currently-activated directory roles
#   only. A user with an eligible-but-not-yet-activated Privileged
#   Identity Management (PIM) admin role will not show as privileged
#   here. Covering that requires a separate call to the PIM API
#   (roleEligibilityScheduleInstances) and is not implemented.
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.mfa.azure

import data.policy.mfa.lib
import rego.v1

default extra_privileged_upns := []

extra_privileged_upns := data.mfa.azure.extra_privileged_upns

default is_privileged(_) := false

is_privileged(user) if object.get(user, "isAdmin", false) == true

is_privileged(user) if user.userPrincipalName in extra_privileged_upns

accounts := [account |
	some user in input.registration_details
	account := {
		"id": user.userPrincipalName,
		"privileged": is_privileged(user),
		"mfa_enabled": object.get(user, "isMfaRegistered", false) == true,
	}
]

deny contains msg if {
	some msg in lib.deny_messages(accounts)
}
