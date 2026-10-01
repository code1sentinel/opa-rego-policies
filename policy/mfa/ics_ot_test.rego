package policy.mfa.ics_ot

import rego.v1

test_deny_ot_access_profile_without_mfa if {
	mock_input := {"remote_access_profiles": [
		{"profile_name": "vendor-remote-support", "grants_ot_network_access": true, "mfa_required": false},
		{"profile_name": "internal-reporting-view", "grants_ot_network_access": false, "mfa_required": false},
	]}

	deny == {"Privileged account 'vendor-remote-support' does not have MFA enabled."} with input as mock_input
}

test_allow_when_mfa_required if {
	mock_input := {"remote_access_profiles": [
		{"profile_name": "vendor-remote-support", "grants_ot_network_access": true, "mfa_required": true},
	]}

	count(deny) == 0 with input as mock_input
}
