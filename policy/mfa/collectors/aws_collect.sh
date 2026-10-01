#!/usr/bin/env bash
# Collects IAM user MFA + effective-policy data and prints it in the
# shape policy/mfa/aws.rego expects. Prints JSON to stdout; writes
# nothing to disk.
#
# Checks policy attached directly to the user AND policy attached via
# group membership (the more common way admin access is actually
# granted), plus inline policy documents. See aws.rego's METADATA
# block for exactly how "privileged" is derived from these.
#
# Scale note: this makes several sequential IAM API calls per user
# (list-mfa-devices, list-attached-user-policies, one
# list-attached-group-policies per group, one get-user-policy per
# inline policy). Fine for dozens of users; for an account with
# hundreds+ of IAM users, expect this to take minutes and consider
# IAM API throttling - there's no parallelism or backoff here.
#
# Prerequisites:
#   - AWS CLI v2, authenticated (via `aws configure`, SSO, or an
#     assumed role) with at least these read-only permissions:
#     iam:ListUsers, iam:ListMFADevices, iam:ListAttachedUserPolicies,
#     iam:ListGroupsForUser, iam:ListAttachedGroupPolicies,
#     iam:ListUserPolicies, iam:GetUserPolicy
#   - jq
#
# Usage:
#   ./aws_collect.sh > input.json
#   ./aws_collect.sh | opa eval -I -d .. "data.policy.mfa.aws.deny"
set -euo pipefail

command -v aws >/dev/null || { echo "aws CLI not found in PATH" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }

usernames=$(aws iam list-users --query 'Users[].UserName' --output json | jq -r '.[]')

records="[]"
while IFS= read -r user; do
	[ -z "$user" ] && continue

	mfa_devices=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output json)
	attached_arns=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output json)

	group_names=$(aws iam list-groups-for-user --user-name "$user" --query 'Groups[].GroupName' --output json | jq -r '.[]')
	group_attached_arns="[]"
	while IFS= read -r group; do
		[ -z "$group" ] && continue
		group_arns=$(aws iam list-attached-group-policies --group-name "$group" --query 'AttachedPolicies[].PolicyArn' --output json)
		group_attached_arns=$(jq -n --argjson acc "$group_attached_arns" --argjson new "$group_arns" '($acc + $new) | unique')
	done <<<"$group_names"

	inline_policy_names=$(aws iam list-user-policies --user-name "$user" --query 'PolicyNames' --output json | jq -r '.[]')
	inline_docs="[]"
	while IFS= read -r policy_name; do
		[ -z "$policy_name" ] && continue
		doc=$(aws iam get-user-policy --user-name "$user" --policy-name "$policy_name" --query 'PolicyDocument' --output json)
		inline_docs=$(jq -n --argjson acc "$inline_docs" --argjson d "$doc" '$acc + [$d]')
	done <<<"$inline_policy_names"

	record=$(jq -n \
		--arg username "$user" \
		--argjson mfa_devices "$mfa_devices" \
		--argjson attached_policy_arns "$attached_arns" \
		--argjson group_attached_policy_arns "$group_attached_arns" \
		--argjson inline_policy_documents "$inline_docs" \
		'{
			username: $username,
			mfa_active: (($mfa_devices | length) > 0),
			attached_policy_arns: $attached_policy_arns,
			group_attached_policy_arns: $group_attached_policy_arns,
			inline_policy_documents: $inline_policy_documents
		}')

	records=$(jq -n --argjson acc "$records" --argjson rec "$record" '$acc + [$rec]')
done <<<"$usernames"

jq -n --argjson users "$records" '{users: $users}'
