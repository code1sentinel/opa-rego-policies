# METADATA
# title: Enforce MFA for Privileged Accounts
# description: >
#   Denies any user with the Administrator role that does not have
#   multi-factor authentication enabled.
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-53 Rev. 5
package policy.require_mfa

import rego.v1

deny contains msg if {
	some user in unprotected_admins
	msg := sprintf("Admin user '%s' does not have MFA enabled.", [user.username])
}

# unprotected_admins is the set of Administrator accounts without MFA
# enabled. has_mfa is a rule, not a raw field read, so negating it
# treats an explicit false, a null, and a missing field all the same
# way: as "not enabled". (Negating input.mfa_enabled directly would
# miss the null case: `not null` is undefined, not true.)
unprotected_admins contains user if {
	some user in input.users
	user.role == "Administrator"
	not has_mfa(user)
}

has_mfa(user) if user.mfa_enabled == true
