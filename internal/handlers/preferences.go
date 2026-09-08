package handlers

import (
	"encoding/json"
	"net/http"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

// GET /notifications
func NotificationsPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	prefs := getUserPrefs(user.ID, "notifications")

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	renderTemplate(w, "notifications.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"Prefs":     prefs,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "notifications",
	})
}

// GET /privacy
func PrivacyPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	prefs := getUserPrefs(user.ID, "privacy")

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	renderTemplate(w, "privacy.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"Prefs":     prefs,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "privacy",
	})
}

// GET /services
func ServicesPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	renderTemplate(w, "services.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"CSRFToken": getCSRFToken(r),
		"Active":    "services",
	})
}

// POST /api/preferences/:key — save a preference (JSON API)
func SavePreference(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	key := r.PathValue("key")
	if key == "" {
		WriteJSON(w, 400, map[string]any{"error": "Key is required"})
		return
	}

	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "Invalid JSON"})
		return
	}

	var pref models.Preference
	result := database.DB.Where("user_id = ? AND `key` = ?", user.ID, key).First(&pref)
	if result.Error != nil {
		pref = models.Preference{
			UserID: user.ID,
			Key:    key,
			Value:  body,
		}
		database.DB.Create(&pref)
	} else {
		database.DB.Model(&pref).Update("value", body)
	}

	WriteJSON(w, 200, map[string]any{"message": "Saved"})
}

// GET /api/preferences/:key — get a preference (JSON API)
func GetPreference(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	key := r.PathValue("key")
	prefs := getUserPrefs(user.ID, key)
	WriteJSON(w, 200, prefs)
}

// GET /api/preferences — list every preference for the caller.
// Clients call this once on bootstrap to hydrate a local cache; singular
// get/put keeps covering reads/writes during a session. Shape matches
// source's old handler ({"data": {key: value}}) so the desktop store
// can point here without reshaping its response handling.
func ListPreferences(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	var prefs []models.Preference
	database.DB.Where("user_id = ?", user.ID).Find(&prefs)

	data := make(map[string]any, len(prefs))
	for _, p := range prefs {
		// Values stored as JSON round-trip back to their original type;
		// plain strings (legacy) pass through unchanged.
		var parsed any
		if err := json.Unmarshal([]byte(p.Value), &parsed); err == nil {
			data[p.Key] = parsed
		} else {
			data[p.Key] = p.Value
		}
	}

	WriteJSON(w, 200, map[string]any{"data": data})
}

// GET /api/account/export — download all user data as JSON
func ExportData(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	// Gather all user data
	var sessions []models.Session
	database.DB.Where("user_id = ?", user.ID).Find(&sessions)

	var passkeys []models.Passkey
	database.DB.Where("user_id = ?", user.ID).Find(&passkeys)

	var preferences []models.Preference
	database.DB.Where("user_id = ?", user.ID).Find(&preferences)

	type exportSession struct {
		ID        uint   `json:"id"`
		UserAgent string `json:"user_agent"`
		IPAddress string `json:"ip_address"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
	}
	var exportSessions []exportSession
	for _, s := range sessions {
		ua, ip := "", ""
		if s.UserAgent != nil {
			ua = *s.UserAgent
		}
		if s.IPAddress != nil {
			ip = *s.IPAddress
		}
		exportSessions = append(exportSessions, exportSession{
			ID:        s.ID,
			UserAgent: ua,
			IPAddress: ip,
			CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z"),
			ExpiresAt: s.ExpiresAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	type exportPasskey struct {
		ID        uint   `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	var exportPasskeys []exportPasskey
	for _, p := range passkeys {
		exportPasskeys = append(exportPasskeys, exportPasskey{
			ID:        p.ID,
			Name:      p.Name,
			CreatedAt: p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	type exportPref struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	var exportPrefs []exportPref
	for _, p := range preferences {
		exportPrefs = append(exportPrefs, exportPref{
			Key:   p.Key,
			Value: p.Value,
		})
	}

	phone := ""
	if user.Phone != nil {
		phone = *user.Phone
	}

	export := map[string]any{
		"account": map[string]any{
			"id":           user.UUID,
			"first_name":   user.FirstName,
			"last_name":    user.LastName,
			"username":     user.Username,
			"email":        user.Email,
			"phone":        phone,
			"totp_enabled": user.TOTPEnabled,
			"created_at":   user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			"updated_at":   user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		},
		"sessions":    exportSessions,
		"passkeys":    exportPasskeys,
		"preferences": exportPrefs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"construct-account-data.json\"")
	_ = json.NewEncoder(w).Encode(export)
}

// POST /api/account/delete — permanently delete account
func DeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteJSON(w, 400, map[string]any{"error": "Invalid request"})
		return
	}

	if !user.CheckPassword(body.Password) {
		WriteJSON(w, 403, map[string]any{"error": "Incorrect password"})
		return
	}

	// Delete all related data
	database.DB.Where("user_id = ?", user.ID).Delete(&models.Session{})
	database.DB.Where("user_id = ?", user.ID).Delete(&models.Passkey{})
	database.DB.Where("user_id = ?", user.ID).Delete(&models.Preference{})
	database.DB.Where("user_id = ?", user.ID).Delete(&models.RefreshToken{})
	database.DB.Where("user_id = ?", user.ID).Delete(&models.AccessToken{})
	database.DB.Where("user_id = ?", user.ID).Delete(&models.OAuthCode{})
	database.DB.Delete(user)

	// Clear session cookie
	w.Header().Set("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0")
	WriteJSON(w, 200, map[string]any{"message": "Account deleted"})
}

func getUserPrefs(userID uint, key string) map[string]bool {
	defaults := map[string]map[string]bool{
		"notifications": {
			"email_security":    true,
			"email_product":     false,
			"email_digest":      false,
			"desktop":           false,
			"important_updates": true,
		},
		"privacy": {
			"analytics":       true,
			"crash_reports":   true,
			"personalization": false,
			"third_party":     false,
		},
	}

	result := defaults[key]
	if result == nil {
		result = map[string]bool{}
	}

	var pref models.Preference
	if err := database.DB.Where("user_id = ? AND `key` = ?", userID, key).First(&pref).Error; err == nil {
		var saved map[string]bool
		if json.Unmarshal(pref.Value, &saved) == nil {
			for k, v := range saved {
				result[k] = v
			}
		}
	}

	return result
}
