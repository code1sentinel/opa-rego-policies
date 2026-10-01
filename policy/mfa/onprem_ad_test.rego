package policy.mfa.onprem_ad

import rego.v1

test_deny_domain_admin_without_mfa if {
	mock_input := {"accounts": [
		{"sam_account_name": "alice", "member_of": ["Domain Admins"], "mfa_enrolled": false},
		{"sam_account_name": "bob", "member_of": ["Sales"], "mfa_enrolled": false},
	]}

	deny == {"Privileged account 'alice' does not have MFA enabled."} with input as mock_input
}

test_custom_privileged_group_via_config if {
	mock_input := {"accounts": [
		{"sam_account_name": "carol", "member_of": ["Backup Operators"], "mfa_enrolled": false},
	]}
	config := {"onprem_ad": {"privileged_groups": ["Backup Operators"]}}

	deny == {"Privileged account 'carol' does not have MFA enabled."} with input as mock_input with data.mfa as config
}
