package policy.mfa.lib

import rego.v1

test_unprotected_flags_privileged_without_mfa if {
	accounts := [
		{"id": "alice", "privileged": true, "mfa_enabled": false},
		{"id": "bob", "privileged": true, "mfa_enabled": true},
		{"id": "carol", "privileged": false, "mfa_enabled": false},
	]

	unprotected(accounts) == {{"id": "alice", "privileged": true, "mfa_enabled": false}}
}

test_deny_messages_empty_when_all_protected if {
	accounts := [{"id": "bob", "privileged": true, "mfa_enabled": true}]
	deny_messages(accounts) == set()
}

test_deny_messages_message_format if {
	accounts := [{"id": "alice", "privileged": true, "mfa_enabled": false}]
	deny_messages(accounts) == {"Privileged account 'alice' does not have MFA enabled."}
}
