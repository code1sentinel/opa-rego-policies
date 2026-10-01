# METADATA
# title: MFA Enforcement Adapter - ICS/OT Remote Access Boundary
# description: >
#   Most ICS/OT field protocols (Modbus, DNP3, many PLC/HMI
#   management interfaces) have no authentication layer at all, so
#   "MFA on the device" is not an achievable or meaningful control.
#   The enforceable equivalent is MFA at the IT/OT boundary: every
#   remote-access path into the OT network (jump host, PAM broker,
#   VPN concentrator, vendor remote-support tunnel) must require MFA.
#
#   Expected input - access-profile config exported from your
#   jump-host/PAM/VPN tooling (e.g. CyberArk, Claroty, a VPN
#   concentrator's auth profiles):
#
#     {
#       "remote_access_profiles": [
#         {
#           "profile_name": "vendor-remote-support",
#           "grants_ot_network_access": true,
#           "mfa_required": false
#         }
#       ]
#     }
# custom:
#   controls: ["IA-2(1)"]
#   framework: NIST SP 800-82 Rev. 3 Section 6.2 / IEC 62443-3-3 SR 1.1-1.2
package policy.mfa.ics_ot

import data.policy.mfa.lib
import rego.v1

accounts := [account |
	some profile in input.remote_access_profiles
	object.get(profile, "grants_ot_network_access", false) == true
	account := {
		"id": profile.profile_name,
		"privileged": true,
		"mfa_enabled": object.get(profile, "mfa_required", false) == true,
	}
]

deny contains msg if {
	some msg in lib.deny_messages(accounts)
}
