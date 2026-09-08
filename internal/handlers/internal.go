package handlers

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"construct/accounts/internal/database"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"
	"construct/accounts/internal/services"

	goauth "github.com/construct-space/go-auth"
)

// GET /internal/validate-token
//
// Used by the my.lisaos.dev gateway as an nginx auth_request target.
// The gateway sends this before proxying /api/* to any downstream service.
// On success we return 200 with X-Auth-* response headers the gateway then
// injects onto the upstream request. On failure we return 401; downstream
// never sees the request.
//
// Required request headers:
//
//	X-Internal-Secret: <INTERNAL_SHARED_SECRET>   proves the caller is the gateway
//	Authorization:     Bearer cat_...             identity token (optional if X-API-Key present)
//	X-API-Key:         csk_live_...               publisher ownership key (optional)
//
// On 200, response headers:
//
//	X-Auth-User-ID, X-Auth-User-Email, X-Auth-User-Name
//	X-Auth-Org-ID, X-Auth-Roles          (present when scope="org")
//	X-Auth-Scope                          "user" | "org"
//	X-Auth-Publisher-ID                   (present when X-API-Key validated)
//
// Scope resolution mirrors /api/me/scope so the gateway's identity is the
// same identity the SPA would see. Org membership wins over personal.
func ValidateToken(w http.ResponseWriter, r *http.Request) {
	// Gateway identity check — only the gateway has INTERNAL_SHARED_SECRET.
	if !goauth.Trusted(r, os.Getenv("INTERNAL_SHARED_SECRET")) {
		WriteJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}

	user := identityFromHeaders(r)
	if user == nil {
		// No valid identity — reject. Publisher key alone isn't enough;
		// every call at the gateway must have a user identity.
		WriteJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}

	w.Header().Set("X-Auth-User-ID", user.UUID)
	w.Header().Set("X-Auth-User-Row-ID", strconv.FormatUint(uint64(user.ID), 10))
	w.Header().Set("X-Auth-User-Email", user.Email)
	w.Header().Set("X-Auth-User-Name", user.Name())

	// Resolve org membership / personal scope — same logic as MeScope.
	// Errors here are swallowed: a scope lookup failure shouldn't block
	// the identity from reaching the downstream service.
	if membership, _ := services.GetMembership(Cfg, user.UUID); membership != nil {
		w.Header().Set("X-Auth-Scope", "org")
		w.Header().Set("X-Auth-Org-ID", membership.OrgID)
		w.Header().Set("X-Auth-Roles", strings.Join(membership.Roles, ","))
	} else {
		w.Header().Set("X-Auth-Scope", "user")
	}

	// Publisher key validation is out of accounts' remit — the developer
	// service owns csk_live_* keys. Phase 3: developer exposes its own
	// /internal/validate-publisher and the gateway chains both subrequests.
	// For now we pass X-API-Key through untouched; downstream services that
	// need it can still validate directly.

	w.WriteHeader(http.StatusOK)
}

// identityFromHeaders parses Authorization (or falls back to a session
// cookie, so curl-with-cookie works in dev) and returns the authenticated
// user. Returns nil if no valid identity.
func identityFromHeaders(r *http.Request) *models.User {
	// Gateway-side check too — every downstream service trusts the
	// X-Auth-* headers this function populates, so letting a suspended
	// user through here is equivalent to granting them platform-wide
	// access until their bearer expires.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != "" {
			var accessToken models.AccessToken
			if err := database.DB.Where("token = ?", token).First(&accessToken).Error; err == nil {
				if accessToken.IsValid() {
					var user models.User
					if err := database.DB.First(&user, accessToken.UserID).Error; err == nil {
						if user.Suspended {
							return nil
						}
						return &user
					}
				}
			}
		}
	}

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		token := middleware.ParseCookie(cookie, "session")
		if token != "" {
			var session models.Session
			if err := database.DB.Where("token = ?", token).First(&session).Error; err == nil {
				if !session.IsExpired() {
					var user models.User
					if err := database.DB.First(&user, session.UserID).Error; err == nil {
						if user.Suspended {
							return nil
						}
						return &user
					}
				}
			}
		}
	}

	return nil
}
