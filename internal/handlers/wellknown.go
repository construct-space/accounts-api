package handlers

import "net/http"

func OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, 200, map[string]any{
		"issuer":                            Cfg.AppURL,
		"authorization_endpoint":            Cfg.AppURL + "/oauth/authorize",
		"token_endpoint":                    Cfg.AppURL + "/oauth/token",
		"userinfo_endpoint":                 Cfg.AppURL + "/api/me",
		"revocation_endpoint":               Cfg.AppURL + "/oauth/revoke",
		"scopes_supported":                  []string{"profile", "email"},
		"response_types_supported":          []string{"code"},
		"grant_types_supported":             []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	})
}
