package main

import (
	"log"
	"net/http"
	"time"

	"construct/accounts/internal/config"
	"construct/accounts/internal/database"
	"construct/accounts/internal/handlers"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/seed"
)

func main() {
	cfg := config.Load()
	handlers.Cfg = cfg
	middleware.SetCSRFSecret(cfg.CSRFSecret)
	handlers.InitWebAuthn()

	database.Init(cfg)
	seed.Run()

	mux := http.NewServeMux()

	// Auth API routes
	mux.HandleFunc("POST /api/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/auth/register", handlers.Register)
	// Top-level paths are kept for the legacy server-rendered HTML forms
	// (and any code that still posts to them). The /api/auth/* aliases
	// are what the my.lisaos.dev gateway proxies — clients on the
	// gateway side must use these or the gateway treats the request as
	// an SPA route and returns 405 on the CORS preflight.
	mux.HandleFunc("POST /forgot-password", handlers.ForgotPassword)
	mux.HandleFunc("POST /reset-password", handlers.ResetPassword)
	mux.HandleFunc("POST /verify-2fa", handlers.TwoFactorLogin)
	mux.HandleFunc("POST /api/auth/forgot-password", handlers.ForgotPassword)
	mux.HandleFunc("POST /api/auth/reset-password", handlers.ResetPassword)
	mux.HandleFunc("POST /api/auth/verify-2fa", handlers.TwoFactorLogin)
	mux.HandleFunc("GET /api/auth/me", handlers.Me)
	mux.HandleFunc("GET /api/auth/logout", handlers.Logout)
	mux.HandleFunc("PUT /api/auth/profile", handlers.UpdateProfile)
	mux.HandleFunc("PUT /api/auth/password", handlers.ChangePassword)
	mux.HandleFunc("GET /api/auth/sessions", handlers.ListSessions)
	mux.HandleFunc("DELETE /api/auth/sessions/{id}", handlers.DeleteSession)

	// Developer enrollment moved to developer service (POST /api/enroll/personal,
	// POST /api/enroll/org). Accounts no longer owns developer identity.

	// OAuth routes
	mux.HandleFunc("GET /oauth/authorize", handlers.Authorize)
	mux.HandleFunc("POST /oauth/token", handlers.Token)
	mux.HandleFunc("GET /api/me", handlers.UserInfo)
	mux.HandleFunc("GET /api/me/scope", handlers.MeScope)

	// Admin endpoints — gated by X-Internal-Secret header via AdminAuth middleware
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("POST /api/admin/users/{id}/suspend", handlers.AdminSuspendUser)
	adminMux.HandleFunc("POST /api/admin/users/{id}/unsuspend", handlers.AdminUnsuspendUser)
	adminMux.HandleFunc("POST /api/admin/users/{id}/force-logout", handlers.AdminForceLogout)
	adminMux.HandleFunc("POST /api/admin/users/{id}/reset-2fa", handlers.AdminReset2FA)
	adminMux.HandleFunc("POST /api/admin/users/{id}/force-password-reset", handlers.AdminForcePasswordReset)
	adminMux.HandleFunc("DELETE /api/admin/sessions/{id}", handlers.AdminRevokeSession)
	adminMux.HandleFunc("DELETE /api/admin/access-tokens/{id}", handlers.AdminRevokeAccessToken)
	adminMux.HandleFunc("DELETE /api/admin/refresh-tokens/{id}", handlers.AdminRevokeRefreshToken)
	adminMux.HandleFunc("DELETE /api/admin/passkeys/{id}", handlers.AdminRevokePasskey)
	adminMux.HandleFunc("DELETE /api/admin/oauth-clients/{client_id}/authorizations/{user_id}", handlers.AdminRevokeClientAuthorization)
	adminMux.HandleFunc("POST /api/admin/oauth-clients", handlers.AdminCreateOAuthClient)
	adminMux.HandleFunc("PATCH /api/admin/oauth-clients/{id}", handlers.AdminUpdateOAuthClient)
	adminMux.HandleFunc("DELETE /api/admin/oauth-clients/{id}", handlers.AdminDeleteOAuthClient)
	adminMux.HandleFunc("POST /api/admin/oauth-clients/{id}/regenerate-secret", handlers.AdminRegenerateOAuthClientSecret)
	mux.Handle("/api/admin/", middleware.AdminAuth(adminMux))

	// Gateway auth subrequest — the my.lisaos.dev nginx calls this before
	// proxying /api/* to any downstream service. See handlers.ValidateToken.
	mux.HandleFunc("GET /internal/validate-token", handlers.ValidateToken)

	// Delegated automation token — Conductor mints a short-lived token to run a
	// user's automations on a cloud executor when their desktop is offline.
	mux.HandleFunc("POST /internal/delegated-token", handlers.DelegatedToken)

	// Internal migration endpoints (X-Internal-Secret header)
	mux.HandleFunc("GET /internal/users/developer-candidates", handlers.InternalDeveloperCandidates)
	mux.HandleFunc("POST /internal/users/batch", handlers.InternalBatchUsers)
	mux.HandleFunc("POST /oauth/revoke", handlers.Revoke)
	mux.HandleFunc("GET /oauth/code-status", handlers.CodeStatus)

	// Preferences API
	mux.HandleFunc("GET /api/preferences", handlers.ListPreferences)
	mux.HandleFunc("PUT /api/preferences/{key}", handlers.SavePreference)
	mux.HandleFunc("GET /api/preferences/{key}", handlers.GetPreference)

	// Account data (GDPR)
	mux.HandleFunc("GET /api/account/export", handlers.ExportData)
	mux.HandleFunc("POST /api/account/delete", handlers.DeleteAccount)

	// 2FA (TOTP) routes
	mux.HandleFunc("POST /api/2fa/setup", handlers.TwoFactorSetup)
	mux.HandleFunc("POST /api/2fa/verify", handlers.TwoFactorVerify)
	mux.HandleFunc("POST /api/2fa/disable", handlers.TwoFactorDisable)

	// Passkey (WebAuthn) routes
	mux.HandleFunc("POST /api/passkey/register/begin", handlers.PasskeyRegisterBegin)
	mux.HandleFunc("POST /api/passkey/register/finish", handlers.PasskeyRegisterFinish)
	mux.HandleFunc("POST /api/passkey/login/begin", handlers.PasskeyLoginBegin)
	mux.HandleFunc("POST /api/passkey/login/finish", handlers.PasskeyLoginFinish)
	mux.HandleFunc("DELETE /api/passkey/{id}", handlers.PasskeyDelete)

	// Passkeys list API
	mux.HandleFunc("GET /api/passkeys", handlers.ListPasskeys)

	// Connected services
	mux.HandleFunc("GET /api/services", handlers.ListServices)
	mux.HandleFunc("DELETE /api/services/{client_id}", handlers.RevokeService)

	// Well-known
	mux.HandleFunc("GET /.well-known/openid-configuration", handlers.OpenIDConfiguration)

	// CSRF token endpoint for SPA
	mux.HandleFunc("GET /api/auth/csrf", func(w http.ResponseWriter, r *http.Request) {
		sessionToken := middleware.ParseCookie(r.Header.Get("Cookie"), "session")
		token := middleware.GenerateCSRFToken(sessionToken)
		handlers.WriteJSON(w, 200, map[string]any{"token": token})
	})

	// Health check
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		handlers.WriteJSON(w, 200, map[string]any{"status": "ok"})
	})

	// Apply middleware
	var handler http.Handler = mux
	handler = middleware.CSRFProtect(handler)
	handler = middleware.CORS(cfg)(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.RateLimit(handler)
	handler = middleware.Logger(handler)

	log.Printf("Construct Accounts running on :%s", cfg.Port)
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
