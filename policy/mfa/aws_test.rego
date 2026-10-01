package policy.mfa.aws

import rego.v1

mock_input := {"users": [
	{
		"username": "alice",
		"mfa_active": false,
		"attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
	},
	{
		"username": "bob",
		"mfa_active": true,
		"attached_policy_arns": [],
	},
]}

test_deny_admin_without_mfa if {
	deny == {"Privileged account 'alice' does not have MFA enabled."} with input as mock_input
}

test_allow_when_admin_has_mfa if {
	fixed_input := json.patch(mock_input, [{"op": "replace", "path": "/users/0/mfa_active", "value": true}])
	count(deny) == 0 with input as fixed_input
}

test_custom_privileged_policy_arn_via_config if {
	custom_input := {"users": [{
		"username": "carol",
		"mfa_active": false,
		"attached_policy_arns": ["arn:aws:iam::aws:policy/CustomBillingAdmin"],
	}]}
	config := {"aws": {"privileged_policy_arns": ["arn:aws:iam::aws:policy/CustomBillingAdmin"]}}

	deny == {"Privileged account 'carol' does not have MFA enabled."} with input as custom_input with data.mfa as config
}

test_deny_admin_via_group_attached_policy if {
	mock := {"users": [{
		"username": "dave",
		"mfa_active": false,
		"attached_policy_arns": [],
		"group_attached_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
	}]}

	deny == {"Privileged account 'dave' does not have MFA enabled."} with input as mock
}

test_deny_admin_via_inline_wildcard_policy if {
	mock := {"users": [{
		"username": "erin",
		"mfa_active": false,
		"attached_policy_arns": [],
		"inline_policy_documents": [{
			"Version": "2012-10-17",
			"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
		}],
	}]}

	deny == {"Privileged account 'erin' does not have MFA enabled."} with input as mock
}

test_scoped_inline_policy_not_flagged_as_privileged if {
	mock := {"users": [{
		"username": "frank",
		"mfa_active": false,
		"attached_policy_arns": [],
		"inline_policy_documents": [{
			"Version": "2012-10-17",
			"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
		}],
	}]}

	count(deny) == 0 with input as mock
}
