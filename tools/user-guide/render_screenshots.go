// Command render_screenshots renders Blackwall's real templates with synthetic,
// non-sensitive example data. The resulting HTML is consumed by the companion
// capture_screenshots.sh script to produce reproducible user-guide images
// without creating an authentication bypass or exposing production tenants.
package main

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"blackwall/internal/service"
	"blackwall/internal/templates"
)

const (
	exampleProjectUUID = "aa88643b-889d-4ce7-a96d-4a562065c880"
	exampleLicenceUUID = "38a46ec2-7f4d-4a77-99dc-2298b16acb08"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run ./tools/user-guide/render_screenshots.go OUTPUT_DIRECTORY")
	}
	outputDirectory, err := filepath.Abs(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		panic(err)
	}

	now := time.Date(2026, time.August, 16, 9, 30, 0, 0, time.UTC)
	writeAdmin(outputDirectory, "dashboard", "dashboard.html", dashboardData(now))
	writeAdmin(outputDirectory, "organisations", "organizations/list.html", organisationsData())
	writeAdmin(outputDirectory, "projects", "projects/list.html", projectsData())
	writeAdmin(outputDirectory, "users", "users/list.html", usersData(now))
	writeAdmin(outputDirectory, "oauth-clients", "clients/list.html", clientsData(now))
	writeAdmin(outputDirectory, "licences", "projects/licences.html", licencesData(now))
	writeAdmin(outputDirectory, "audit-log", "audit/log.html", auditData(now))
	writeDocs(outputDirectory)
	writeStandalone(outputDirectory, "portal", "portal/dashboard.html", map[string]interface{}{
		"CSRFToken": "guide-example", "User": map[string]interface{}{"display_label": "alex@example.com"},
		"Projects":    []map[string]interface{}{{"name": "Customer Portal", "privilege_label": "Administrator"}, {"name": "Reporting", "privilege_label": "Viewer"}},
		"Credentials": []map[string]interface{}{{"label": "Laptop passkey", "created_at": now.AddDate(0, -3, 0), "credential_id": "example-laptop"}, {"label": "YubiKey 5 NFC", "created_at": now.AddDate(0, -1, 0), "credential_id": "example-yubikey"}},
	})
	writeStandalone(outputDirectory, "oauth-consent", "oauth/consent.html", map[string]interface{}{
		"CSRFToken": "guide-example", "FaviconURL": "https://blackwall.cx/assets/blackwall.svg",
		"Client":         map[string]interface{}{"Name": "Example Customer Portal"},
		"Project":        map[string]interface{}{"Name": "Customer Portal", "UUID": exampleProjectUUID},
		"PrivilegeLabel": "Administrator", "PrivilegeLevelNumber": 1,
		"Params": map[string]string{"client_id": "example-client", "scope": "openid profile email"},
	})
	writeStandalone(outputDirectory, "cryptbin-create", "cryptbin/create.html", map[string]interface{}{
		"CSRFToken": "guide-example", "MaxUploadBytes": int64(5 * 1024 * 1024), "MaxTextBytes": int64(256 * 1024),
	})
}

func baseData(title string) map[string]interface{} {
	return map[string]interface{}{
		"Title": title, "CurrentAdminRole": "super_admin", "CurrentUserID": 1,
		"CSRFToken": "guide-example", "Version": "1.0.1-b6d19bb", "BuildDate": "2026-08-16T09:24:53Z",
		"Capabilities": map[string]bool{"manage_users": true, "manage_projects": true, "view_maintenance": true, "view_licences": true},
	}
}

func dashboardData(now time.Time) map[string]interface{} {
	data := baseData("Dashboard")
	period := func(today, week, month int) map[string]int {
		return map[string]int{"Today": today, "Week": week, "Month": month}
	}
	data["Stats"] = map[string]int{"Users": 42, "Projects": 8, "Clients": 12, "AuditCount": 1847}
	data["OutcomeStats"] = map[string]interface{}{"Success": period(128, 794, 3120), "Fail": period(3, 19, 71)}
	data["CSRFSecurityStats"] = period(1, 4, 9)
	data["SuccessBreakdown"] = []map[string]interface{}{{"EventType": "oauth.token.issue", "Today": 84, "Week": 522, "Month": 2102}, {"EventType": "webauthn.authentication.success", "Today": 31, "Week": 192, "Month": 802}}
	data["FailBreakdown"] = []map[string]interface{}{{"EventType": "oauth.authorize.fail", "Today": 2, "Week": 11, "Month": 38}, {"EventType": "security.csrf.fail", "Today": 1, "Week": 4, "Month": 9}}
	data["RecentAudit"] = []map[string]interface{}{{"EventType": "admin.licence.issue", "Outcome": "success", "ActorUUID": "5fd8ee95-f524-46df-8c02-1f92bb26a619", "CreatedAt": "2026-08-16 09:18"}, {"EventType": "oauth.authorize.approve", "Outcome": "success", "ActorUUID": "57d0378d-4879-433a-b060-84c36f30bc58", "CreatedAt": "2026-08-16 09:12"}, {"EventType": "security.csrf.fail", "Outcome": "fail", "ActorUUID": "", "CreatedAt": "2026-08-16 08:54"}}
	data["BuildStatus"] = map[string]interface{}{"Version": "1.0.1-b6d19bb", "Commit": "b6d19bb", "BuildTime": "2026-08-16 09:24 UTC", "VulnerabilityScanRecorded": true, "VulnerabilityScanTime": "2026-08-16 09:24 UTC", "VulnerabilityScanReference": "release/20260816-licence-reminders"}
	data["CanViewApprovals"] = true
	data["ApprovalSummary"] = map[string]interface{}{"Pending": period(2, 4, 11), "Approved": period(7, 31, 118), "Rejected": period(1, 3, 8), "Cancelled": period(0, 1, 4)}
	data["ApprovalSLA"] = map[string]int{"MedianSeconds": 840, "P95Seconds": 7200, "PendingOlderThanThreshold": 1, "PendingWarningDays": 3}
	data["MyPendingApprovals"] = []map[string]interface{}{{"ActionType": "admin.project.update", "CreatedAt": now.Add(-2 * time.Hour)}}
	data["CanViewCryptbin"] = true
	data["IsSuperAdmin"] = true
	data["CryptbinStats"] = map[string]int{"Created24h": 6, "Failed24h": 0}
	return data
}

func organisationsData() map[string]interface{} {
	data := baseData("Organisations")
	data["CanManage"] = true
	data["Organizations"] = []map[string]interface{}{
		{"Name": "Example Organisation", "Slug": "example", "UUID": "68193fdf-e869-42c1-9855-97e343e43b65", "AdminUUID": "5fd8ee95-f524-46df-8c02-1f92bb26a619", "AdminLabel": "admin@example.com", "UserCount": 24, "ProjectCount": 5, "Status": "active"},
		{"Name": "Northwind Services", "Slug": "northwind", "UUID": "6b20469e-a722-4c1d-873f-c608d19ef9cc", "AdminUUID": "57d0378d-4879-433a-b060-84c36f30bc58", "AdminLabel": "owner@northwind.example", "UserCount": 18, "ProjectCount": 3, "Status": "active"},
	}
	return data
}

func projectsData() map[string]interface{} {
	data := baseData("Projects")
	data["CanManage"] = true
	data["Projects"] = []map[string]interface{}{
		{"Name": "Customer Portal", "UUID": exampleProjectUUID, "OrgName": "Example Organisation", "Status": "active"},
		{"Name": "Reporting", "UUID": "323b805c-e001-4407-b3c5-6a1607a6b2ac", "OrgName": "Example Organisation", "Status": "active"},
		{"Name": "Legacy SAML", "UUID": "a06e83bd-cb63-4aa9-890e-885366660b38", "OrgName": "Northwind Services", "Status": "disabled"},
	}
	return data
}

func usersData(now time.Time) map[string]interface{} {
	data := baseData("Users")
	data["CanManage"] = true
	data["Users"] = []map[string]interface{}{
		{"DisplayLabel": "admin@example.com", "UUID": "5fd8ee95-f524-46df-8c02-1f92bb26a619", "OrganizationName": "Example Organisation", "Status": "active", "CreatedAt": now.AddDate(-1, -2, 0)},
		{"DisplayLabel": "alex@example.com", "UUID": "57d0378d-4879-433a-b060-84c36f30bc58", "OrganizationName": "Example Organisation", "Status": "active", "CreatedAt": now.AddDate(0, -7, 0)},
		{"DisplayLabel": "former.user@example.com", "UUID": "e60afdb2-a6b0-4e1b-9f00-c42f1002e7d6", "OrganizationName": "Northwind Services", "Status": "disabled", "CreatedAt": now.AddDate(-2, 0, 0)},
	}
	return data
}

func clientsData(now time.Time) map[string]interface{} {
	data := baseData("OAuth clients")
	data["CanManage"] = true
	data["Project"] = map[string]interface{}{"Name": "Customer Portal", "UUID": exampleProjectUUID}
	data["Clients"] = []map[string]interface{}{
		{"Name": "Example Customer Portal", "PublicID": "bw_client_portal_7f9a", "Confidential": true, "OIDCEnabled": true, "Status": "active", "CreatedAt": now.AddDate(0, -5, 0)},
		{"Name": "Mobile Application", "PublicID": "bw_client_mobile_11c2", "Confidential": false, "OIDCEnabled": true, "Status": "active", "CreatedAt": now.AddDate(0, -3, 0)},
	}
	return data
}

func licencesData(now time.Time) map[string]interface{} {
	data := baseData("Project licences")
	data["Project"] = map[string]interface{}{"ID": 7, "Name": "Customer Portal", "UUID": exampleProjectUUID}
	data["CanManage"] = true
	data["IssuanceEnabled"] = true
	data["ActiveKeyID"] = "bwlic_YfM4qg8Q2WfJ9c1sHdA8D4pK"
	data["MaxValidityDays"] = 365
	data["Now"] = now
	data["Licences"] = []service.ProjectLicence{{
		PublicID: exampleLicenceUUID, EntityType: "business", EntityName: "Example Customer Limited",
		EntityReference: sql.NullString{String: "CUS-42", Valid: true}, Hostnames: []string{"app.example.com", "api.example.com"},
		Features: []string{"api", "reporting"}, MaxInstances: 2, IssuedAt: now.AddDate(0, -11, 0), ExpiresAt: now.AddDate(0, 1, 14),
	}, {
		PublicID: "8942cc8e-b4fc-45d7-b856-6955797f97e1", EntityType: "person", EntityName: "Alex Example",
		Hostnames: []string{"desktop.example.com"}, MaxInstances: 1, IssuedAt: now.AddDate(-1, 0, 0), ExpiresAt: now.AddDate(0, 0, 7),
	}}
	data["ReminderStatus"] = service.LicenceReminderProjectStatus{Enabled: true, RecipientAvailable: true, OrganisationName: "Example Organisation", RecipientLabel: "admin@example.com"}
	data["ReminderHistory"] = []service.LicenceReminderHistory{{LicencePublicID: exampleLicenceUUID, ThresholdDays: 30, Status: "succeeded", Attempts: 1, SentAt: sql.NullTime{Time: now.Add(-24 * time.Hour), Valid: true}, CreatedAt: now.Add(-24 * time.Hour)}}
	return data
}

func auditData(now time.Time) map[string]interface{} {
	data := baseData("Audit log")
	data["TotalCount"], data["Page"], data["TotalPages"] = 1847, 1, 93
	data["Filters"] = map[string]string{}
	data["Entries"] = []map[string]interface{}{
		{"CreatedAt": now.Add(-4 * time.Minute), "EventType": "admin.licence.issue", "Outcome": "success", "ActorUUID": "5fd8ee95-f524-46df-8c02-1f92bb26a619", "ProjectUUID": exampleProjectUUID, "TargetType": "project_licence", "TargetID": exampleLicenceUUID, "IP": "203.0.113.24", "CorrelationID": "c6f8a5ad-0767-40ef-8550-27d01a69b06f"},
		{"CreatedAt": now.Add(-18 * time.Minute), "EventType": "oauth.authorize.approve", "Outcome": "success", "ActorUUID": "57d0378d-4879-433a-b060-84c36f30bc58", "ProjectUUID": exampleProjectUUID, "TargetType": "oauth_client", "TargetID": "bw_client_portal_7f9a", "IP": "198.51.100.18", "CorrelationID": "69454f92-e528-4022-a3df-75af18efeec1"},
		{"CreatedAt": now.Add(-36 * time.Minute), "EventType": "security.csrf.fail", "Outcome": "fail", "ActorUUID": "", "ProjectUUID": "", "TargetType": "", "TargetID": "", "IP": "192.0.2.44", "CorrelationID": "558f859f-d5c7-4312-8eb3-08432765a402"},
	}
	return data
}

func writeDocs(outputDirectory string) {
	data := baseData("Documentation: Overview")
	data["DocsPages"] = []map[string]string{
		{"Slug": "overview", "Title": "Overview", "Summary": "Platform purpose and documentation map."},
		{"Slug": "quick-start", "Title": "Administrator Quick Start", "Summary": "First-session safety checks."},
		{"Slug": "project-licences", "Title": "Project Licences", "Summary": "Issue, verify, revoke, and renew."},
		{"Slug": "oauth-clients", "Title": "OAuth Clients", "Summary": "Secure authorisation flows."},
		{"Slug": "audit-and-security", "Title": "Audit and Security", "Summary": "Search, export, and response."},
	}
	data["CurrentSlug"], data["CurrentTitle"], data["CurrentSummary"] = "overview", "Overview", "Platform purpose, capability model, and documentation map."
	recorder := httptest.NewRecorder()
	templates.AdminDocsPage(recorder, "docs/overview.html", data)
	writeHTML(outputDirectory, "documentation", recorder)
}

func writeAdmin(outputDirectory, name, page string, pageData map[string]interface{}) {
	data := baseData(fmt.Sprint(pageData["Title"]))
	for key, value := range pageData {
		data[key] = value
	}
	recorder := httptest.NewRecorder()
	templates.AdminPage(recorder, page, data)
	writeHTML(outputDirectory, name, recorder)
}

func writeStandalone(outputDirectory, name, page string, data map[string]interface{}) {
	recorder := httptest.NewRecorder()
	templates.Standalone(recorder, page, data)
	writeHTML(outputDirectory, name, recorder)
}

func writeHTML(outputDirectory, name string, recorder *httptest.ResponseRecorder) {
	if recorder.Code != 200 {
		panic(fmt.Sprintf("render %s returned HTTP %d: %s", name, recorder.Code, recorder.Body.String()))
	}
	staticDirectory, err := filepath.Abs("internal/templates/web/static")
	if err != nil {
		panic(err)
	}
	body := recorder.Body.String()
	assetPrefix := "file://" + filepath.ToSlash(staticDirectory) + "/"
	guideAssetPrefix := "file:///tmp/blackwall-user-guide-assets/"
	body = strings.ReplaceAll(body, `https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css`, guideAssetPrefix+`bootstrap.min.css`)
	body = strings.ReplaceAll(body, `https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js`, guideAssetPrefix+`bootstrap.bundle.min.js`)
	body = strings.ReplaceAll(body, `<link rel="preconnect" href="https://fonts.googleapis.com">`, ``)
	body = strings.ReplaceAll(body, `<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>`, ``)
	body = strings.ReplaceAll(body, `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">`, ``)
	body = strings.ReplaceAll(body, `href="/assets/`, `href="`+assetPrefix)
	body = strings.ReplaceAll(body, `src="/assets/`, `src="`+assetPrefix)
	if err := os.WriteFile(filepath.Join(outputDirectory, name+".html"), []byte(body), 0o644); err != nil {
		panic(err)
	}
}
