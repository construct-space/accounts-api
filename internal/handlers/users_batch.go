package handlers

import (
	"encoding/json"
	"net/http"
	"os"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"

	goauth "github.com/construct-space/go-auth"
)

// POST /internal/users/batch
// Body: { "ids": ["uuid1", "uuid2", ...] }
// Returns minimal user info for each known UUID. Unknown IDs are silently
// dropped (caller renders a fallback). Used by the developer service to
// resolve org-publisher user IDs to display names — for org publishes the
// caller has no personal Publisher row, so the per-publisher join in
// enrichPublishes returns nothing and we fall back to this lookup.
//
// Response: { "users": [ { "id", "name", "email", "first_name", "last_name" }, ... ] }
//
// X-Internal-Secret gated. Cap at 200 ids per call to keep request size
// bounded; that's well above what one publish-history page would need.
func InternalBatchUsers(w http.ResponseWriter, r *http.Request) {
	if !goauth.Trusted(r, os.Getenv("INTERNAL_SHARED_SECRET")) {
		WriteJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid body"})
		return
	}
	if len(body.IDs) == 0 {
		WriteJSON(w, 200, map[string]any{"users": []any{}})
		return
	}
	if len(body.IDs) > 200 {
		body.IDs = body.IDs[:200]
	}

	var users []models.User
	if err := database.DB.
		Where("uuid IN ?", body.IDs).
		Find(&users).Error; err != nil {
		WriteJSON(w, 500, map[string]any{"error": "lookup failed"})
		return
	}

	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{
			"id":         u.UUID,
			"name":       u.Name(),
			"first_name": u.FirstName,
			"last_name":  u.LastName,
			"email":      u.Email,
			"avatar_url": u.AvatarURL,
		})
	}
	WriteJSON(w, 200, map[string]any{"users": out})
}
