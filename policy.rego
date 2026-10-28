# Supervisor policy (Phases 1, 2 and 4). OPA is the final decision maker.
#
# Input sent by the Supervisor:
#   { did, role, action, resource, capabilities: [{action, resource}], recent_action_count }
# Result: allow (true/false) and deny_reasons (why a request was refused).
package authz

import rego.v1

# Fail closed: anything not explicitly allowed is denied.
default allow := false

# What each role may do (the role comes from the verified credential).
role_permissions := {
	"log_analyst": {"read_logs"},
	"threat_detector": {"read_logs", "report_threat"},
	"incident_responder": {"block_ip", "isolate_host"},
}

# Critical assets. These OVERRIDE every allow rule.
protected_resources := {"ip:192.168.1.1", "host:db-01"}

# Maximum number of the same action by the same agent in the last 60 seconds.
action_limits := {
	"block_ip": 5,
	"isolate_host": 5,
	"read_logs": 60,
	"report_threat": 60,
}

role_allows if input.action in role_permissions[input.role]

# A capability must name this action AND cover this resource.
capability_matches if {
	some cap in input.capabilities
	cap.action == input.action
	resource_matches(cap.resource, input.resource)
}

# Only the two wildcards "ip:*" and "host:*" exist; everything else must match exactly.
resource_matches(pattern, resource) if pattern == resource

resource_matches("ip:*", resource) if startswith(resource, "ip:")

resource_matches("host:*", resource) if startswith(resource, "host:")

within_limit if input.recent_action_count < action_limits[input.action]

allow if {
	role_allows
	capability_matches
	not input.resource in protected_resources
	within_limit
}

# Human-readable reasons, stored in the audit log.
deny_reasons contains "role is not permitted to perform this action" if not role_allows

deny_reasons contains "token has no matching capability" if not capability_matches

deny_reasons contains "resource is protected" if input.resource in protected_resources

deny_reasons contains "rate limit exceeded" if not within_limit
