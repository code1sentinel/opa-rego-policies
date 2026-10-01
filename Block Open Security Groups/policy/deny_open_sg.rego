# METADATA
# title: Block Open Security Groups
# description: >
#   Denies Terraform plans that create a security group allowing
#   unrestricted inbound SSH (22) or RDP (3389) access from the public
#   internet (0.0.0.0/0).
# custom:
#   severity: high
package policy.deny_open_sg

import input as tfplan
import rego.v1

public_cidr := "0.0.0.0/0"

# port_names maps a restricted port to the human-readable name used in
# deny messages.
port_names := {22: "SSH", 3389: "RDP"}

deny contains msg if {
	some rule in open_ingress_rules
	some port, name in port_names
	rule.from_port == port
	msg := sprintf("Open %s access (port %d) to the internet is not allowed.", [name, port])
}

# open_ingress_rules is the set of ingress rules, across all resource
# changes, that permit traffic from the public internet.
open_ingress_rules contains rule if {
	some resource_change in tfplan.resource_changes
	raw_triggers := resource_change.change.after.triggers.open_sg
	raw_triggers != ""
	sg := json.unmarshal(raw_triggers)
	some rule in sg.ingress
	public_cidr in rule.cidr_blocks
}
