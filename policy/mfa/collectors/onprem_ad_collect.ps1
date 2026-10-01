<#
.SYNOPSIS
  TEMPLATE - not a drop-in script. Produces the shape
  policy/mfa/onprem_ad.rego expects, but the MFA half of the join has
  no universal API: you must wire Get-MfaEnrollment below to your own
  MFA provider (Duo, RSA, a RADIUS server's admin API, Okta, etc).
  The Active Directory half (group membership) works as-is given the
  ActiveDirectory PowerShell module and read access to your domain.

.USAGE
  .\onprem_ad_collect.ps1 | Out-File input.json -Encoding utf8
#>

param(
	[string[]]$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
)

Import-Module ActiveDirectory

function Get-MfaEnrollment {
	param([string]$SamAccountName)
	# EDIT ME: call your MFA provider's API or enrollment export here
	# and return $true or $false for this account. There is no
	# vendor-neutral way to do this - vanilla AD has no MFA concept.
	throw "Get-MfaEnrollment is not implemented - wire this up to your MFA provider before running this script."
}

$accounts = foreach ($group in $PrivilegedGroups) {
	Get-ADGroupMember -Identity $group -Recursive |
		Where-Object { $_.objectClass -eq "user" } |
		ForEach-Object {
			[PSCustomObject]@{
				sam_account_name = $_.SamAccountName
				member_of        = @($group)
				mfa_enrolled     = Get-MfaEnrollment -SamAccountName $_.SamAccountName
			}
		}
}

@{ accounts = $accounts } | ConvertTo-Json -Depth 5
