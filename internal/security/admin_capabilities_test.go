package security

import "testing"

func TestLicenceCapabilitiesAreLeastPrivilege(t *testing.T) {
	if !HasCapability(RoleSuperAdmin, "view_licences") || !HasCapability(RoleSuperAdmin, "manage_licences") {
		t.Fatal("super-administrator must be able to view and manage licences")
	}
	if !HasCapability(RoleOperator, "view_licences") {
		t.Fatal("operator must be able to inspect project licences")
	}
	if HasCapability(RoleOperator, "manage_licences") || HasCapability(RoleAuditor, "manage_licences") {
		t.Fatal("licence issuance and revocation must remain super-administrator-only")
	}
}
