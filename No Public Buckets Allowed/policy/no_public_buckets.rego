# METADATA
# title: No Public Buckets Allowed
# description: >
#   Denies S3 bucket resources whose ACL grants public read access.
package policy.no_public_buckets

import rego.v1

deny contains msg if {
	is_public_bucket
	msg := "S3 buckets cannot be publicly readable (acl: public-read)"
}

is_public_bucket if {
	input.resource_type == "aws_s3_bucket"
	input.acl == "public-read"
}
