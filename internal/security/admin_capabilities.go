package security

// Capability matrix mirrors AdminController::hasCapability() in the PHP source.
// Each role lists the named operations it can perform; HasCapability is the
// authorisation gate every admin handler runs before doing real work.
//
// Capabilities ending in "_direct" mean the role is allowed to apply a change
// without going through the approval workflow. AdminMutationPolicy uses these
// to decide whether to mutate immediately or enqueue an approval request.

const (
	RoleSuperAdmin = "super_admin"
	RoleOperator   = "operator"
	RoleAuditor    = "auditor"
)

var capabilityMatrix = map[string][]string{
	RoleSuperAdmin: {
		"view_dashboard", "view_users", "manage_users", "view_projects", "manage_projects",
		"view_clients", "manage_clients", "view_assignments", "manage_assignments",
		"view_privileges", "manage_privileges", "view_audit", "view_maintenance",
		"manage_roles", "decode_error_trace", "view_scope_debug", "view_docs",
		"view_organizations", "manage_organizations", "switch_organization_admin",
		"delete_credentials_direct", "change_user_status_direct", "delete_privilege_direct",
		"change_project_status_direct", "change_client_status_direct",
		"update_project_settings_direct", "update_client_settings_direct",
		"assignment_mutations_direct",
		"view_cryptbin", "manage_cryptbin",
		"view_approvals", "decide_approvals",
	},
	RoleOperator: {
		"view_dashboard", "view_users", "manage_users", "view_projects", "manage_projects",
		"view_clients", "manage_clients", "view_assignments", "manage_assignments",
		"view_privileges", "manage_privileges", "view_audit", "view_docs",
		"view_approvals", "view_scope_debug", "view_organizations",
	},
	RoleAuditor: {
		"view_dashboard", "view_audit", "view_maintenance", "decode_error_trace",
		"view_approvals", "view_scope_debug", "view_docs",
	},
}

// HasCapability returns true if the role grants the given capability.
// Roles outside the known set get no capabilities.
func HasCapability(role, capability string) bool {
	caps, ok := capabilityMatrix[role]
	if !ok {
		return false
	}
	for _, c := range caps {
		if c == capability {
			return true
		}
	}
	return false
}

// CapabilitiesFor returns the capability list for a role, or nil for unknown roles.
func CapabilitiesFor(role string) []string {
	caps, ok := capabilityMatrix[role]
	if !ok {
		return nil
	}
	out := make([]string, len(caps))
	copy(out, caps)
	return out
}
