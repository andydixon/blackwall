package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"blackwall/internal/config"
	"blackwall/internal/db"
	"blackwall/internal/handler"
	"blackwall/internal/middleware"
	"blackwall/internal/security"
	"blackwall/internal/service"
	"blackwall/internal/templates"
)

func main() {
	configPath := flag.String("config", "", "Path to config YAML file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Derive WebAuthn RPID from AppURL if not set
	if cfg.WebAuthnRPID == "" {
		cfg.WebAuthnRPID = extractHostname(cfg.AppURL)
	}
	if cfg.ErrorTraceKey == "" {
		cfg.ErrorTraceKey = cfg.CSRFSecret
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()

	// Apply forward-only schema migrations (idempotent; tracked via
	// schema_migrations table). Fatal on failure — running with a partial
	// schema is worse than refusing to start.
	if err := db.Migrate(database); err != nil {
		log.Fatalf("db migrate: %v", err)
	}

	security.InitSession(cfg)

	rateLimiter := security.NewRateLimiter(database)

	jwtMgr := service.NewJWTManager(database)
	webAuthnSvc := service.NewWebAuthnService(database)
	oauthSvc := service.NewOAuthService(database)
	auditLogger := service.NewAuditLogger(database)
	adminAuthSvc := service.NewAdminAuthService(database)
	approvalSvc := service.NewApprovalService(database)
	scopeBuilder := service.NewAdminScopeBuilder(database, adminAuthSvc)
	claimsSvc := service.NewOIDCClaimsService(database)
	maintenanceSvc := service.NewMaintenanceService(database)
	featuresSvc := service.NewFeatureFlagService(database)
	webhookSvc := service.NewWebhookService(database)
	sessionStore := service.NewSessionStore(database)
	brandingSvc := service.NewBrandingService(database)
	auditChainSvc := service.NewAuditChainService(database, jwtMgr)
	adminTokensSvc := service.NewAdminTokenService(database)
	scimSvc := service.NewSCIMService(database)
	samlSvc := service.NewSAMLService(database, jwtMgr)
	licenceSvc, err := service.NewLicenceService(database, cfg)
	if err != nil {
		log.Fatalf("licence service init failed: %v", err)
	}
	// Wire custom-claims into the OAuth service so it can merge them into
	// every issued ID token + userinfo response.
	oauthSvc.SetClaimsProvider(claimsSvc)
	// Wire webhooks into the audit logger so committed events fan out to
	// registered receivers without blocking the request path.
	auditLogger.AttachWebhooks(webhookSvc)

	// Background dispatcher for the webhook delivery queue. The context
	// here is tied to process lifetime; the dispatcher exits cleanly when
	// the server shuts down via the same Shutdown call as the HTTP server.
	dispatchCtx, dispatchCancel := context.WithCancel(context.Background())
	defer dispatchCancel()
	webhookSvc.StartDispatcher(dispatchCtx, 5*time.Second)

	var cryptbinKEK *service.CryptbinKEK
	if cfg.CryptbinKEKBase64 != "" {
		cryptbinKEK, err = service.NewCryptbinKEK()
		if err != nil {
			log.Fatalf("cryptbin KEK init failed: %v", err)
		}
	}

	app := &handler.App{
		WebAuthn:    webAuthnSvc,
		OAuth:       oauthSvc,
		JWT:         jwtMgr,
		Audit:       auditLogger,
		AdminAuth:   adminAuthSvc,
		Approval:    approvalSvc,
		Scope:       scopeBuilder,
		Claims:      claimsSvc,
		Maintenance: maintenanceSvc,
		RateLimit:   rateLimiter,
		Features:    featuresSvc,
		Webhooks:    webhookSvc,
		Sessions:    sessionStore,
		Branding:    brandingSvc,
		AuditChain:  auditChainSvc,
		AdminTokens: adminTokensSvc,
		SCIM:        scimSvc,
		SAML:        samlSvc,
		Licences:    licenceSvc,
		Favicons:    service.NewFaviconService(),
	}

	oauthHandler := handler.NewOAuthHandler(app, database)

	portalHandler := &handler.PortalHandler{
		App:      app,
		WebAuthn: webAuthnSvc,
	}

	bootstrapHandler := &handler.BootstrapHandler{
		App:      app,
		WebAuthn: webAuthnSvc,
		DB:       database,
	}

	cryptbinStorage := service.NewCryptbinStorage()
	cryptbinHandler := &handler.CryptbinHandler{
		App:      app,
		Storage:  cryptbinStorage,
		KEK:      cryptbinKEK,
		WebAuthn: webAuthnSvc,
	}

	adminHandler := &handler.AdminHandler{
		App:      app,
		WebAuthn: webAuthnSvc,
		DB:       database,
	}

	metricsHandler := &handler.MetricsHandler{DB: database}

	r := chi.NewRouter()

	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.RequestBodyLimit(cfg.RequestBodyMaxBytes))
	r.Use(middleware.CorrelationID)
	r.Use(middleware.IPAddress)
	r.Use(middleware.AuditContext(database, auditLogger))
	r.Use(middleware.SecurityHeaders)

	// Static assets
	r.Handle("/assets/*", http.StripPrefix("/assets/", templates.StaticHandler()))

	// Public pages
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		templates.Standalone(w, "home.html", map[string]interface{}{"Title": "BlackWall"})
	})
	r.Get("/metrics", metricsHandler.Index)

	// OIDC / OAuth discovery
	r.Get("/.well-known/openid-configuration", oauthHandler.Discovery)
	r.Get("/oauth/jwks", oauthHandler.JWKS)
	r.Get("/.well-known/blackwall-licence-keys.json", adminHandler.LicenceKeys)
	r.Post("/licences/v1/verify", adminHandler.LicenceVerify)

	// OAuth endpoints
	r.Get("/oauth/authorize", oauthHandler.Authorize)
	r.Post("/oauth/authorize", oauthHandler.AuthorizePost)
	r.Get("/oauth/client-favicon", oauthHandler.ClientFavicon)
	r.Post("/oauth/login/challenge", oauthHandler.LoginChallenge)
	r.Post("/oauth/login/verify", oauthHandler.LoginVerify)
	r.Post("/oauth/token", oauthHandler.Token)
	r.Post("/oauth/revoke", oauthHandler.Revoke)
	r.Post("/oauth/introspect", oauthHandler.Introspect)
	r.Get("/oauth/userinfo", oauthHandler.UserInfo)
	r.Post("/oauth/userinfo", oauthHandler.UserInfo)

	// Portal
	r.Get("/portal/login", portalHandler.LoginForm)
	r.Post("/portal/login", portalHandler.LoginChallenge)
	r.Post("/portal/login/challenge", portalHandler.LoginChallenge)
	r.Post("/portal/login/verify", portalHandler.LoginVerify)
	r.Get("/portal", portalHandler.Dashboard)
	r.Post("/portal/keys/add/init", portalHandler.AddKeyInit)
	r.Post("/portal/keys/add/complete", portalHandler.AddKeyComplete)
	r.Post("/portal/keys/{credentialPublicId}/delete", portalHandler.DeleteKey)
	r.Post("/portal/logout", portalHandler.Logout)

	// Bootstrap & enrollment
	r.Get("/bootstrap", bootstrapHandler.BootstrapForm)
	r.Post("/bootstrap/enroll", bootstrapHandler.EnrollWebAuthn)
	r.Get("/enroll", bootstrapHandler.EnrollForm)
	r.Post("/enroll/complete", bootstrapHandler.EnrollKey)
	r.Get("/organisations/signup", bootstrapHandler.OrgSignupForm)
	r.Post("/organisations/signup", bootstrapHandler.OrgSignup)

	// Cryptbin
	r.Get("/cryptbin", cryptbinHandler.CreateForm)
	r.Post("/cryptbin/create", cryptbinHandler.Create)
	r.Get("/cryptbin/{id}", cryptbinHandler.View)
	r.Get("/cryptbin/{id}/share", cryptbinHandler.Share)
	r.Get("/cryptbin/{id}/meta", cryptbinHandler.Metadata)
	r.Get("/cryptbin/{id}/ciphertext", cryptbinHandler.Ciphertext)
	r.Post("/cryptbin/{id}/webauthn/challenge", cryptbinHandler.WebAuthnChallenge)
	r.Post("/cryptbin/{id}/wrap", cryptbinHandler.Wrap)
	r.Post("/cryptbin/{id}/unwrap", cryptbinHandler.Unwrap)
	r.Post("/cryptbin/{id}/update", cryptbinHandler.Update)
	r.Post("/cryptbin/{id}/delete", cryptbinHandler.Delete)

	// Admin
	r.Route("/admin", func(r chi.Router) {
		r.Get("/login", adminHandler.LoginForm)
		r.Post("/login/challenge", adminHandler.LoginChallenge)
		r.Post("/login/verify", adminHandler.LoginVerify)
		r.Post("/logout", adminHandler.Logout)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		})
		r.Get("/dashboard", adminHandler.Dashboard)
		r.Get("/maintenance", adminHandler.Maintenance)
		r.Post("/maintenance", adminHandler.Maintenance)
		r.Get("/docs", adminHandler.DocsHome)
		r.Get("/docs/", adminHandler.DocsHome)
		r.Get("/docs/{page}", adminHandler.DocsHome)
		r.Get("/scope", adminHandler.ScopeDebug)
		r.Get("/error-trace", adminHandler.ErrorTraceForm)
		r.Post("/error-trace", adminHandler.ErrorTraceDecode)
		r.Get("/roles", adminHandler.AdminRoles)
		r.Post("/roles", adminHandler.AdminRoleUpsert)
		r.Post("/roles/{userId}/revoke", adminHandler.AdminRoleRevoke)

		r.Get("/organisations", adminHandler.OrganizationsList)
		r.Post("/organisations/create", adminHandler.OrganizationStore)
		r.Get("/organisations/{organizationUuid}", adminHandler.OrganizationDetail)
		r.Post("/organisations/{organizationUuid}/update", adminHandler.OrganizationUpdate)
		r.Post("/organisations/{organizationUuid}/switch-admin", adminHandler.OrganizationSwitchAdmin)
		r.Post("/organisations/{organizationUuid}/users/import", adminHandler.OrganizationImportUsers)
		r.Post("/organisations/{organizationUuid}/enrollment-urls/export", adminHandler.OrganizationExportEnrollmentURLs)

		r.Post("/switch/restore", adminHandler.SwitchRestore)

		r.Get("/approvals", adminHandler.ApprovalsList)
		r.Post("/approvals/{id}/approve", adminHandler.ApprovalApprove)
		r.Post("/approvals/{id}/reject", adminHandler.ApprovalReject)
		r.Post("/approvals/{id}/cancel", adminHandler.ApprovalCancel)

		r.Get("/cryptbin", adminHandler.CryptbinList)
		r.Post("/cryptbin/{id}/delete", adminHandler.CryptbinDelete)

		// Users
		r.Get("/users", adminHandler.UsersList)
		r.Get("/users/create", adminHandler.UserCreate)
		r.Post("/users/create", adminHandler.UserStore)
		r.Get("/users/{userUuid}", adminHandler.UserDetail)
		r.Post("/users/{userUuid}/update", adminHandler.UserUpdate)
		r.Post("/users/{userUuid}/enrollment-link", adminHandler.GenerateEnrollmentLink)
		r.Post("/users/{userUuid}/credentials/{credentialPublicId}/delete", adminHandler.DeleteCredential)

		// Custom OIDC claims (user-level + project-scoped per user).
		r.Get("/users/{userUuid}/claims", adminHandler.UserClaims)
		r.Post("/users/{userUuid}/claims", adminHandler.UserClaimUpsert)
		r.Post("/users/{userUuid}/claims/delete", adminHandler.UserClaimDelete)
		r.Post("/users/{userUuid}/projects/{projectUuid}/claims", adminHandler.UserProjectClaimUpsert)
		r.Post("/users/{userUuid}/projects/{projectUuid}/claims/delete", adminHandler.UserProjectClaimDelete)

		// Default OIDC claim templates (org-wide and project-wide). Merged
		// into every user's tokens beneath the per-user layers above.
		r.Post("/organisations/{organizationUuid}/claim-defaults", adminHandler.OrgClaimDefaultUpsert)
		r.Post("/organisations/{organizationUuid}/claim-defaults/delete", adminHandler.OrgClaimDefaultDelete)
		r.Post("/projects/{projectUuid}/claim-defaults", adminHandler.ProjectClaimDefaultUpsert)
		r.Post("/projects/{projectUuid}/claim-defaults/delete", adminHandler.ProjectClaimDefaultDelete)

		// Project authentication sandbox: preview what /oauth/userinfo
		// would emit for any user in the project, with per-claim source.
		r.Get("/projects/{projectUuid}/test", adminHandler.ProjectAuthTest)

		// Projects
		r.Get("/projects", adminHandler.ProjectsList)
		r.Get("/projects/create", adminHandler.ProjectCreate)
		r.Post("/projects/create", adminHandler.ProjectStore)
		r.Get("/projects/{projectUuid}", adminHandler.ProjectDetail)
		r.Post("/projects/{projectUuid}/update", adminHandler.ProjectUpdate)
		r.Get("/projects/{projectUuid}/licences", adminHandler.ProjectLicences)
		r.Post("/projects/{projectUuid}/licences/issue", adminHandler.ProjectLicenceIssue)
		r.Get("/projects/{projectUuid}/licences/{licenceId}/download", adminHandler.ProjectLicenceDownload)
		r.Post("/projects/{projectUuid}/licences/{licenceId}/revoke", adminHandler.ProjectLicenceRevoke)

		// Privilege levels
		r.Get("/projects/{projectUuid}/privileges", adminHandler.PrivilegeLevels)
		r.Post("/projects/{projectUuid}/privileges/create", adminHandler.PrivilegeLevelCreate)
		r.Post("/privileges/{id}/update", adminHandler.PrivilegeLevelUpdate)
		r.Post("/privileges/{id}/delete", adminHandler.PrivilegeLevelDelete)

		// Assignments
		r.Get("/projects/{projectUuid}/assignments", adminHandler.ProjectAssignments)
		r.Post("/projects/{projectUuid}/assignments/create", adminHandler.AssignmentCreate)
		r.Post("/assignments/{id}/update", adminHandler.AssignmentUpdate)
		r.Post("/assignments/{id}/delete", adminHandler.AssignmentDelete)

		// OAuth clients
		r.Get("/projects/{projectUuid}/clients", adminHandler.ClientsList)
		r.Get("/projects/{projectUuid}/clients/create", adminHandler.ClientCreate)
		r.Post("/projects/{projectUuid}/clients/create", adminHandler.ClientStore)
		r.Get("/clients/{clientPublicId}", adminHandler.ClientDetail)
		r.Post("/clients/{clientPublicId}/update", adminHandler.ClientUpdate)

		// Audit
		r.Get("/audit", adminHandler.AuditLog)
		r.Get("/audit/export", adminHandler.AuditExport)

		// Audit chain checkpoints (tamper-evidence)
		r.Get("/audit/checkpoints", adminHandler.AuditCheckpoints)
		r.Post("/audit/checkpoints/create", adminHandler.AuditCheckpointCreate)
		r.Get("/audit/checkpoints/{id}/verify", adminHandler.AuditCheckpointVerify)

		// Webhooks (per-project)
		r.Get("/projects/{projectUuid}/webhooks", adminHandler.WebhookList)
		r.Post("/projects/{projectUuid}/webhooks/create", adminHandler.WebhookCreate)
		r.Post("/projects/{projectUuid}/webhooks/{endpointId}/update", adminHandler.WebhookUpdate)
		r.Post("/projects/{projectUuid}/webhooks/{endpointId}/delete", adminHandler.WebhookDelete)
		r.Get("/projects/{projectUuid}/webhooks/{endpointId}/deliveries", adminHandler.WebhookDeliveries)

		// Per-project feature flags
		r.Post("/projects/{projectUuid}/features", adminHandler.ProjectFeatureFlagsUpdate)

		// Session management (per user)
		r.Get("/users/{userUuid}/sessions", adminHandler.UserSessions)
		r.Post("/users/{userUuid}/sessions/revoke", adminHandler.UserSessionRevoke)
		r.Post("/users/{userUuid}/sessions/revoke-all", adminHandler.UserSessionRevokeAll)

		// Org branding + custom domains
		r.Post("/organisations/{organizationUuid}/branding", adminHandler.OrgBrandingUpdate)
		r.Post("/organisations/{organizationUuid}/domains/add", adminHandler.OrgDomainAdd)
		r.Post("/organisations/{organizationUuid}/domains/delete", adminHandler.OrgDomainDelete)

		// Admin API tokens (for JSON API / Terraform / SCIM consumers)
		r.Get("/api-tokens", adminHandler.AdminTokens)
		r.Post("/api-tokens/create", adminHandler.AdminTokenCreate)
		r.Post("/api-tokens/{publicId}/revoke", adminHandler.AdminTokenRevoke)

		// SAML SP registry (per project)
		r.Get("/projects/{projectUuid}/saml", adminHandler.SAMLSPList)
		r.Post("/projects/{projectUuid}/saml/create", adminHandler.SAMLSPCreate)
		r.Post("/projects/{projectUuid}/saml/{spId}/delete", adminHandler.SAMLSPDelete)
	})

	// JSON admin API — bearer-token authenticated. Separate route prefix
	// so the auth middleware doesn't have to discriminate between cookie
	// and bearer flows. Consumers: the Terraform provider, SCIM
	// receivers, and any operator's automation.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(adminHandler.AdminAPIBearerAuth)
		r.Get("/organizations", adminHandler.APIListOrganizations)
		r.Get("/projects", adminHandler.APIListProjects)
		r.Post("/projects", adminHandler.APICreateProject)
		r.Get("/projects/{projectUuid}", adminHandler.APIGetProject)
		r.Patch("/projects/{projectUuid}", adminHandler.APIPatchProject)
		r.Delete("/projects/{projectUuid}", adminHandler.APIDeleteProject)
		r.Get("/projects/{projectUuid}/oauth_clients", adminHandler.APIListOAuthClients)
		r.Post("/projects/{projectUuid}/oauth_clients", adminHandler.APICreateOAuthClient)
		r.Get("/oauth_clients/{clientId}", adminHandler.APIGetOAuthClient)
		r.Patch("/oauth_clients/{clientId}", adminHandler.APIPatchOAuthClient)
		r.Delete("/oauth_clients/{clientId}", adminHandler.APIDeleteOAuthClient)
		r.Get("/projects/{projectUuid}/claim_defaults", adminHandler.APIListClaimDefaults)
		r.Put("/projects/{projectUuid}/claim_defaults", adminHandler.APIUpsertClaimDefault)
		r.Delete("/projects/{projectUuid}/claim_defaults", adminHandler.APIDeleteClaimDefault)
		r.Get("/projects/{projectUuid}/webhooks", adminHandler.APIListWebhooks)
		r.Post("/projects/{projectUuid}/webhooks", adminHandler.APICreateWebhook)
		r.Patch("/projects/{projectUuid}/webhooks/{endpointId}", adminHandler.APIPatchWebhook)
		r.Delete("/projects/{projectUuid}/webhooks/{endpointId}", adminHandler.APIDeleteWebhook)
		r.Get("/projects/{projectUuid}/saml_service_providers", adminHandler.APIListSAMLSPs)
		r.Post("/projects/{projectUuid}/saml_service_providers", adminHandler.APICreateSAMLSP)
		r.Get("/saml_service_providers/{spId}", adminHandler.APIGetSAMLSP)
		r.Delete("/saml_service_providers/{spId}", adminHandler.APIDeleteSAMLSP)
		r.Get("/users", adminHandler.APIListUsers)
	})

	// SAML 2.0 IdP. Public endpoints (no auth middleware) — SAML handles
	// its own trust model via signed AuthnRequests / verified Responses.
	r.Get("/saml/projects/{projectUuid}/metadata", adminHandler.SAMLMetadata)
	r.Get("/saml/projects/{projectUuid}/sso", adminHandler.SAMLSSO)
	r.Post("/saml/projects/{projectUuid}/sso", adminHandler.SAMLSSO)
	r.Get("/saml/projects/{projectUuid}/sso/continue", adminHandler.SAMLSSOContinue)

	// SCIM 2.0 — same bearer-token middleware as /api/v1; the SCIM client
	// passes the target project via the X-BlackWall-Project header so the
	// IdP can be configured with one base URL per environment.
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(adminHandler.AdminAPIBearerAuth)
		r.Get("/ServiceProviderConfig", adminHandler.SCIMServiceProviderConfig)
		r.Get("/ResourceTypes", adminHandler.SCIMResourceTypes)
		r.Get("/Schemas", adminHandler.SCIMSchemas)
		r.Get("/Users", adminHandler.SCIMUsersList)
		r.Post("/Users", adminHandler.SCIMUserCreate)
		r.Get("/Users/{id}", adminHandler.SCIMUserGet)
		r.Put("/Users/{id}", adminHandler.SCIMUserReplace)
		r.Patch("/Users/{id}", adminHandler.SCIMUserPatch)
		r.Delete("/Users/{id}", adminHandler.SCIMUserDelete)
	})

	// 404 handler
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		templates.Standalone(w, "error.html", map[string]interface{}{
			"Title":   "Not Found",
			"Message": "Page not found",
			"Code":    404,
		})
	})

	addr := cfg.ServerAddr
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}

	log.Printf("BlackWall starting on %s", addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func extractHostname(appURL string) string {
	// strip scheme
	u := appURL
	for _, prefix := range []string{"https://", "http://"} {
		if len(u) > len(prefix) && u[:len(prefix)] == prefix {
			u = u[len(prefix):]
			break
		}
	}
	// strip path/port
	for i, c := range u {
		if c == '/' || c == ':' {
			return u[:i]
		}
	}
	return u
}
