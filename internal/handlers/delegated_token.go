package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"

	goauth "github.com/construct-space/go-auth"
)

// automationClientID labels delegated tokens so they're distinguishable from
// real OAuth-client tokens in the access_tokens table. It is not a registered
// OAuth client — delegated tokens are minted directly, never via a client
// secret — and downstream validation only looks up the token row, not the
// client, so no oauth_clients row is required.
const automationClientID = "construct-automations"

const (
	defaultDelegatedTTL = 15 * time.Minute
	maxDelegatedTTL     = 60 * time.Minute
)

type delegatedTokenRequest struct {
	UserID  string `json:"user_id"`  // the user UUID to act as
	Scope   string `json:"scope"`    // optional; defaults to "automations"
	TTLSecs int    `json:"ttl_secs"` // optional; clamped to [60, 3600]
}

type delegatedTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	UserID    string `json:"user_id"`
	Scope     string `json:"scope"`
}

// POST /internal/delegated-token
//
// Mints a short-lived, automation-scoped access token for a user so a trusted
// first-party executor (the cloud automation runner) can act AS that user when
// their desktop is offline. Gated by INTERNAL_SHARED_SECRET — only callers that
// hold the shared secret (Conductor) may mint; there is no user credential in
// the flow, which is exactly why it must be internal-only.
//
// The result is an ordinary cat_ access token, so Graph/source validate it the
// same as any user token (org is still resolved from membership server-side).
// The short TTL + "automations" scope bound the blast radius: a leaked token
// expires in minutes and is labelled for audit.
//
// Request (X-Internal-Secret required):
//
//	{ "user_id": "<uuid>", "ttl_secs": 900, "scope": "automations" }
//
// Response 200:
//
//	{ "token": "cat_...", "expires_at": "RFC3339", "user_id": "<uuid>", "scope": "automations" }
func DelegatedToken(w http.ResponseWriter, r *http.Request) {
	if !goauth.Trusted(r, os.Getenv("INTERNAL_SHARED_SECRET")) {
		WriteJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}

	var body delegatedTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == "" {
		WriteJSON(w, 400, map[string]any{"error": "user_id required"})
		return
	}

	scope := body.Scope
	if scope == "" {
		scope = "automations"
	}
	ttl := time.Duration(body.TTLSecs) * time.Second
	if ttl <= 0 {
		ttl = defaultDelegatedTTL
	}
	if ttl > maxDelegatedTTL {
		ttl = maxDelegatedTTL
	}

	var user models.User
	if err := database.DB.Where("uuid = ?", body.UserID).First(&user).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	if user.Suspended {
		WriteJSON(w, 403, map[string]any{"error": "user suspended"})
		return
	}

	tok := models.AccessToken{
		Token:     models.GenerateAccessToken(),
		ClientID:  automationClientID,
		UserID:    user.ID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := database.DB.Create(&tok).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "could not mint token"})
		return
	}

	// Opportunistic cleanup of expired tokens (same as mintTokensForClient).
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.AccessToken{})

	WriteJSON(w, 200, delegatedTokenResponse{
		Token:     tok.Token,
		ExpiresAt: tok.ExpiresAt.UTC().Format(time.RFC3339),
		UserID:    user.UUID,
		Scope:     scope,
	})
}
