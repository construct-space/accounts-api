package handlers

import (
	"net/http"
	"os"

	"construct/accounts/internal/database"

	goauth "github.com/construct-space/go-auth"
)

// requireMigrationSecret gates one-shot migration endpoints with the shared
// internal secret. Distinct gate from the /api/* public surface.
func requireMigrationSecret(w http.ResponseWriter, r *http.Request) bool {
	if Cfg.InternalSecret == "" {
		WriteJSON(w, 503, map[string]any{"error": "internal endpoints disabled"})
		return false
	}
	if !goauth.Trusted(r, os.Getenv("INTERNAL_SHARED_SECRET")) {
		WriteJSON(w, 401, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

// GET /internal/users/developer-candidates
// Returns all users that had developer_status = 'enrolled' at the time of
// the identity-scopes cutover. Used once to backfill Publisher.user_id in
// the developer service for legacy rows that won't auto-link via the
// /api/enroll/personal existing-row flow.
//
// Queries the leftover developer_status column directly via raw SQL —
// the column was removed from the User model but remains in the DB.
func InternalDeveloperCandidates(w http.ResponseWriter, r *http.Request) {
	if !requireMigrationSecret(w, r) {
		return
	}
	var rows []struct {
		UUID  string
		Email string
	}
	err := database.DB.
		Raw("SELECT uuid, email FROM users WHERE developer_status = ?", "enrolled").
		Scan(&rows).Error
	if err != nil {
		WriteJSON(w, 200, map[string]any{
			"users": []map[string]string{},
			"note":  "developer_status column absent or query failed — nothing to backfill",
		})
		return
	}

	users := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		users = append(users, map[string]string{
			"user_id": r.UUID,
			"email":   r.Email,
		})
	}
	WriteJSON(w, 200, map[string]any{"users": users})
}
