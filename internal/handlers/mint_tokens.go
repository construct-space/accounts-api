package handlers

import (
	"net/http"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

// Shape the desktop/CLI auth endpoints return when a client asks for bearer
// tokens instead of a session cookie. Matches /oauth/token's response so a
// single client code path can consume both.
type bearerTokenResponse struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	ExpiresIn    int            `json:"expires_in"`
	RefreshToken string         `json:"refresh_token"`
	Scope        string         `json:"scope"`
	User         map[string]any `json:"user,omitempty"`
}

// mintTokensForClient issues an access + refresh token pair for a validated
// user against a known OAuth client. Returns an http-writable error if the
// client id is unknown or inactive; callers should return immediately when
// err is non-nil. Writes no output — callers decide status + shape.
func mintTokensForClient(userID uint, clientID, scope string) (*models.AccessToken, *models.RefreshToken, error) {
	if scope == "" {
		scope = "openid profile email"
	}

	var client models.OAuthClient
	if err := database.DB.Where("client_id = ? AND active = ?", clientID, true).First(&client).Error; err != nil {
		return nil, nil, err
	}

	access := models.AccessToken{
		Token:     models.GenerateAccessToken(),
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := database.DB.Create(&access).Error; err != nil {
		return nil, nil, err
	}

	refresh := models.RefreshToken{
		Token:         models.GenerateRefreshToken(),
		AccessTokenID: &access.ID,
		UserID:        userID,
		ClientID:      clientID,
		Scope:         scope,
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
	}
	if err := database.DB.Create(&refresh).Error; err != nil {
		return nil, nil, err
	}

	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.AccessToken{})
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{})

	return &access, &refresh, nil
}

// writeBearerTokens sends the standard bearer-token JSON response and sets
// the same cache-control headers /oauth/token uses.
func writeBearerTokens(w http.ResponseWriter, access *models.AccessToken, refresh *models.RefreshToken, user *models.User) {
	resp := bearerTokenResponse{
		AccessToken:  access.Token,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(access.ExpiresAt).Seconds()),
		RefreshToken: refresh.Token,
		Scope:        access.Scope,
	}
	if user != nil {
		resp.User = user.ProfileJSON()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	WriteJSON(w, 200, resp)
}
