package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"construct/accounts/internal/config"
	"construct/accounts/internal/database"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"
)

// getCSRFToken generates a CSRF token for the current session
func getCSRFToken(r *http.Request) string {
	sessionToken := middleware.ParseCookie(r.Header.Get("Cookie"), "session")
	return middleware.GenerateCSRFToken(sessionToken)
}

// isValidReturnURL checks that a return_to URL is safe (same origin or allowed)
func isValidReturnURL(returnTo string, cfg *config.Config) bool {
	if returnTo == "" {
		return false
	}
	// Allow relative paths
	if strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") {
		return true
	}
	// Parse the URL and extract scheme+host for comparison
	parsed, err := url.Parse(returnTo)
	if err != nil || parsed.Host == "" {
		return false
	}
	returnOrigin := parsed.Scheme + "://" + parsed.Host
	// Allow same origin
	if returnOrigin == extractOrigin(cfg.AppURL) {
		return true
	}
	// Allow configured origins
	for _, origin := range cfg.AllowedOrigins {
		if returnOrigin == extractOrigin(origin) {
			return true
		}
	}
	return false
}

// extractOrigin parses a URL string and returns scheme://host
func extractOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return rawURL
	}
	return parsed.Scheme + "://" + parsed.Host
}

// safeRedirectURL returns a safe redirect URL, falling back to appURL
func safeRedirectURL(returnTo string, cfg *config.Config) string {
	if isValidReturnURL(returnTo, cfg) {
		return returnTo
	}
	return cfg.AppURL
}

var Cfg *config.Config

const maxRequestBodyBytes = 1 << 20

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func parseBody(r *http.Request) (map[string]string, error) {
	result := make(map[string]string)
	ct := r.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
	if err != nil {
		return result, err
	}
	defer r.Body.Close()
	if len(body) > maxRequestBodyBytes {
		return result, fmt.Errorf("request body too large")
	}

	if len(body) == 0 {
		return result, nil
	}

	if strings.Contains(ct, "application/json") {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return result, err
		}
		for k, v := range m {
			if s, ok := v.(string); ok {
				result[k] = s
			}
		}
		return result, nil
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return result, err
	}
	for k, v := range values {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result, nil
}

func getLoggedInUser(r *http.Request) *models.User {
	// Try Bearer token first (OAuth access tokens from desktop/API clients)
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
		if bearerToken != "" {
			var accessToken models.AccessToken
			if err := database.DB.Where("token = ?", bearerToken).First(&accessToken).Error; err == nil {
				if accessToken.IsValid() {
					var user models.User
					if err := database.DB.First(&user, accessToken.UserID).Error; err == nil {
						// Treat suspension as immediate token revocation —
						// without this check, a suspended user's still-live
						// OAuth tokens would keep every downstream service
						// accepting them until expiry (up to 30 days).
						if user.Suspended {
							return nil
						}
						return &user
					}
				}
			}
		}
	}

	// Fall back to session cookie (browser)
	cookie := r.Header.Get("Cookie")
	token := middleware.ParseCookie(cookie, "session")
	if token == "" {
		return nil
	}

	var session models.Session
	if err := database.DB.Where("token = ?", token).First(&session).Error; err != nil {
		return nil
	}
	if session.IsExpired() {
		return nil
	}

	var user models.User
	if err := database.DB.First(&user, session.UserID).Error; err != nil {
		return nil
	}
	if user.Suspended {
		return nil
	}
	return &user
}

func htmlError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(400)
	w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Error</title>
<style>body{font-family:system-ui;background:#1a1a2e;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
.box{text-align:center;max-width:400px;padding:2rem;}
h1{color:#3b82f6;font-size:1.5rem;}
p{color:#6b7280;font-size:0.875rem;}</style>
</head><body><div class="box"><h1>OAuth Error</h1><p>` + message + `</p></div></body></html>`))
}

func encodeParam(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "&", "%26")
}

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
