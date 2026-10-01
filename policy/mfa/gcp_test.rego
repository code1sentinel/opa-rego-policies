package policy.mfa.gcp

import rego.v1

test_deny_admin_without_2sv if {
	mock_input := {"users": [
		{"primaryEmail": "alice@example.com", "isAdmin": true, "isEnrolledIn2Sv": false},
		{"primaryEmail": "bob@example.com", "isAdmin": false, "isEnrolledIn2Sv": false},
	]}

	deny == {"Privileged account 'alice@example.com' does not have MFA enabled."} with input as mock_input
}

test_delegated_admin_counts_as_privileged if {
	mock_input := {"users": [
		{"primaryEmail": "carol@example.com", "isAdmin": false, "isDelegatedAdmin": true, "isEnrolledIn2Sv": false},
	]}

	deny == {"Privileged account 'carol@example.com' does not have MFA enabled."} with input as mock_input
}
