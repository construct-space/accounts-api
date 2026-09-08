package handlers

import (
	"net/http"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

// GET /api/services — list connected OAuth apps for the current user
func ListServices(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	// Find distinct client_ids with active (non-revoked, non-expired) access tokens
	type tokenRow struct {
		ClientID  string    `gorm:"column:client_id"`
		Scope     string    `gorm:"column:scope"`
		CreatedAt time.Time `gorm:"column:created_at"`
	}

	var rows []tokenRow
	database.DB.Model(&models.AccessToken{}).
		Select("client_id, scope, MAX(created_at) as created_at").
		Where("user_id = ? AND revoked = false AND expires_at > ?", user.ID, time.Now()).
		Group("client_id").
		Find(&rows)

	// Look up client details
	services := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		var client models.OAuthClient
		if err := database.DB.Where("client_id = ?", row.ClientID).First(&client).Error; err != nil {
			continue
		}

		// Count active tokens for this client
		var tokenCount int64
		database.DB.Model(&models.AccessToken{}).
			Where("user_id = ? AND client_id = ? AND revoked = false AND expires_at > ?", user.ID, row.ClientID, time.Now()).
			Count(&tokenCount)

		s := map[string]any{
			"client_id":    client.ClientID,
			"name":         client.Name,
			"scope":        row.Scope,
			"connected_at": row.CreatedAt,
			"token_count":  tokenCount,
		}
		if client.Description != nil {
			s["description"] = *client.Description
		}
		if client.LogoURL != nil {
			s["logo_url"] = *client.LogoURL
		}
		services = append(services, s)
	}

	WriteJSON(w, 200, map[string]any{"services": services})
}

// DELETE /api/services/{client_id} — revoke all tokens for a connected app
func RevokeService(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	clientID := r.PathValue("client_id")
	if clientID == "" {
		WriteJSON(w, 400, map[string]any{"error": "Missing client_id"})
		return
	}

	// Revoke all access tokens
	database.DB.Model(&models.AccessToken{}).
		Where("user_id = ? AND client_id = ?", user.ID, clientID).
		Update("revoked", true)

	// Revoke all refresh tokens
	database.DB.Model(&models.RefreshToken{}).
		Where("user_id = ? AND client_id = ?", user.ID, clientID).
		Update("revoked", true)

	WriteJSON(w, 200, map[string]any{"message": "Access revoked"})
}
