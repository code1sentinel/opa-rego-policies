package policy.mfa.azure

import rego.v1

test_deny_admin_without_mfa if {
	mock_input := {"registration_details": [
		{"userPrincipalName": "alice@contoso.com", "isAdmin": true, "isMfaRegistered": false},
		{"userPrincipalName": "bob@contoso.com", "isAdmin": false, "isMfaRegistered": false},
	]}

	deny == {"Privileged account 'alice@contoso.com' does not have MFA enabled."} with input as mock_input
}

test_extra_privileged_upn_via_config if {
	mock_input := {"registration_details": [
		{"userPrincipalName": "svc-deploy@contoso.com", "isAdmin": false, "isMfaRegistered": false},
	]}
	config := {"azure": {"extra_privileged_upns": ["svc-deploy@contoso.com"]}}

	deny == {"Privileged account 'svc-deploy@contoso.com' does not have MFA enabled."} with input as mock_input with data.mfa as config
}
