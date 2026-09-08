package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

// POST /api/admin/users/{id}/suspend
// Body (optional): {"reason": "..."}
func AdminSuspendUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}

	body, _ := parseBody(r)
	now := time.Now()
	updates := map[string]any{
		"suspended":        true,
		"suspended_at":     now,
		"suspended_reason": body["reason"],
	}
	if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to suspend user"})
		return
	}

	// Revoke every credential the user currently holds:
	//   - sessions (browser)
	//   - access tokens (OAuth / desktop app)
	//   - refresh tokens (prevent minting new access tokens)
	//
	// identityFromHeaders + getLoggedInUser also check user.Suspended, so
	// these revokes are belt-and-braces — but without them, a stolen
	// bearer could theoretically be used to re-authenticate via a system
	// that bypasses the suspension check (future bugs).
	database.DB.Where("user_id = ?", user.ID).Delete(&models.Session{})
	database.DB.Model(&models.AccessToken{}).Where("user_id = ?", user.ID).Update("revoked", true)
	database.DB.Model(&models.RefreshToken{}).Where("user_id = ?", user.ID).Update("revoked", true)

	WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/admin/users/{id}/unsuspend
func AdminUnsuspendUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}

	updates := map[string]any{
		"suspended":        false,
		"suspended_at":     nil,
		"suspended_reason": "",
	}
	if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to unsuspend user"})
		return
	}

	WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/admin/users/{id}/force-logout — revoke ALL sessions for this user
func AdminForceLogout(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	result := database.DB.Where("user_id = ?", user.ID).Delete(&models.Session{})
	if result.Error != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to revoke sessions"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true, "sessions_revoked": result.RowsAffected})
}

// POST /api/admin/users/{id}/reset-2fa — disable TOTP and clear the secret
func AdminReset2FA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	user.TOTPEnabled = false
	user.TOTPSecret = nil
	if err := database.DB.Save(&user).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to reset 2FA"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/admin/users/{id}/force-password-reset
// Sets MustChangePassword=true, issues a real reset token (24h), invalidates all sessions.
// Returns the reset token so the admin can share it or send it manually.
// Does NOT touch the user's Password field.
func AdminForcePasswordReset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "user not found"})
		return
	}
	token := models.GenerateResetToken()
	expiry := time.Now().Add(24 * time.Hour)
	updates := map[string]any{
		"must_change_password": true,
		"reset_token":          token,
		"reset_token_expiry":   expiry,
	}
	if err := database.DB.Model(&user).Updates(updates).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to force password reset"})
		return
	}

	// Invalidate all sessions
	database.DB.Where("user_id = ?", user.ID).Delete(&models.Session{})

	WriteJSON(w, 200, map[string]any{"ok": true, "reset_token": token})
}

// DELETE /api/admin/sessions/{id}
func AdminRevokeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	result := database.DB.Delete(&models.Session{}, id)
	if result.Error != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to revoke session"})
		return
	}
	if result.RowsAffected == 0 {
		WriteJSON(w, 404, map[string]any{"error": "session not found"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/admin/access-tokens/{id}
func AdminRevokeAccessToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var token models.AccessToken
	if err := database.DB.First(&token, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "token not found"})
		return
	}
	token.Revoked = true
	if err := database.DB.Save(&token).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to revoke token"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/admin/refresh-tokens/{id}
func AdminRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var token models.RefreshToken
	if err := database.DB.First(&token, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "refresh token not found"})
		return
	}
	token.Revoked = true
	if err := database.DB.Save(&token).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to revoke refresh token"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/admin/passkeys/{id}
func AdminRevokePasskey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	result := database.DB.Delete(&models.Passkey{}, id)
	if result.Error != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to revoke passkey"})
		return
	}
	if result.RowsAffected == 0 {
		WriteJSON(w, 404, map[string]any{"error": "passkey not found"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/admin/oauth-clients/{client_id}/authorizations/{user_id}
// Revokes all access tokens and refresh tokens issued to user_id via client_id.
func AdminRevokeClientAuthorization(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	userID := r.PathValue("user_id")
	if clientID == "" || userID == "" {
		WriteJSON(w, 400, map[string]any{"error": "client_id and user_id required"})
		return
	}

	database.DB.Model(&models.AccessToken{}).
		Where("client_id = ? AND user_id = ?", clientID, userID).
		Update("revoked", true)

	database.DB.Model(&models.RefreshToken{}).
		Where("client_id = ? AND user_id = ?", clientID, userID).
		Update("revoked", true)

	WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/admin/oauth-clients
// Body: {name, redirect_uri, description?, logo_url?}
// Creates a new client with generated client_id + client_secret.
// The secret is returned ONCE in plaintext — it's hex-encoded in the DB and
// can be regenerated later but never shown again.
func AdminCreateOAuthClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		RedirectURI string  `json:"redirect_uri"`
		Description *string `json:"description"`
		LogoURL     *string `json:"logo_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.RedirectURI = strings.TrimSpace(body.RedirectURI)
	if body.Name == "" || body.RedirectURI == "" {
		WriteJSON(w, 400, map[string]any{"error": "name and redirect_uri are required"})
		return
	}

	secret := models.GenerateClientSecret()
	client := models.OAuthClient{
		ClientID:     models.GenerateClientID(),
		ClientSecret: secret,
		Name:         body.Name,
		RedirectURI:  body.RedirectURI,
		Description:  body.Description,
		LogoURL:      body.LogoURL,
		Active:       true,
	}
	if err := database.DB.Create(&client).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to create client"})
		return
	}
	// Plaintext secret included in this response only. Callers must capture it
	// now — it isn't retrievable later without regenerate-secret.
	WriteJSON(w, 201, map[string]any{
		"data":          client,
		"client_secret": secret,
	})
}

// PATCH /api/admin/oauth-clients/{id}
// Body: any subset of {name, redirect_uri, description, logo_url, active}
func AdminUpdateOAuthClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var client models.OAuthClient
	if err := database.DB.First(&client, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "oauth client not found"})
		return
	}

	var body struct {
		Name        *string `json:"name"`
		RedirectURI *string `json:"redirect_uri"`
		Description *string `json:"description"`
		LogoURL     *string `json:"logo_url"`
		Active      *bool   `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}

	updates := map[string]any{}
	if body.Name != nil {
		name := strings.TrimSpace(*body.Name)
		if name == "" {
			WriteJSON(w, 400, map[string]any{"error": "name cannot be empty"})
			return
		}
		updates["name"] = name
	}
	if body.RedirectURI != nil {
		uri := strings.TrimSpace(*body.RedirectURI)
		if uri == "" {
			WriteJSON(w, 400, map[string]any{"error": "redirect_uri cannot be empty"})
			return
		}
		updates["redirect_uri"] = uri
	}
	if body.Description != nil { updates["description"] = body.Description }
	if body.LogoURL != nil { updates["logo_url"] = body.LogoURL }
	if body.Active != nil { updates["active"] = *body.Active }

	if len(updates) == 0 {
		WriteJSON(w, 400, map[string]any{"error": "no updatable fields provided"})
		return
	}
	if err := database.DB.Model(&client).Updates(updates).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to update client"})
		return
	}
	database.DB.First(&client, id) // refresh to return current row
	WriteJSON(w, 200, map[string]any{"data": client})
}

// DELETE /api/admin/oauth-clients/{id}
// Hard-deletes the client. Outstanding access/refresh tokens issued via this
// client are revoked first so no grant survives the row.
func AdminDeleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var client models.OAuthClient
	if err := database.DB.First(&client, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "oauth client not found"})
		return
	}
	database.DB.Model(&models.AccessToken{}).Where("client_id = ?", client.ClientID).Update("revoked", true)
	database.DB.Model(&models.RefreshToken{}).Where("client_id = ?", client.ClientID).Update("revoked", true)
	if err := database.DB.Delete(&client).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to delete client"})
		return
	}
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/admin/oauth-clients/{id}/regenerate-secret
// Returns the new secret once. All existing access/refresh tokens are revoked
// since the old secret is no longer valid — clients MUST re-authorize after a
// rotation.
func AdminRegenerateOAuthClientSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var client models.OAuthClient
	if err := database.DB.First(&client, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "oauth client not found"})
		return
	}
	secret := models.GenerateClientSecret()
	if err := database.DB.Model(&client).Update("client_secret", secret).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "failed to rotate secret"})
		return
	}
	database.DB.Model(&models.AccessToken{}).Where("client_id = ?", client.ClientID).Update("revoked", true)
	database.DB.Model(&models.RefreshToken{}).Where("client_id = ?", client.ClientID).Update("revoked", true)
	WriteJSON(w, 200, map[string]any{
		"client_secret": secret,
		"revoked_grants": true,
	})
}
