package services

import (
	"encoding/json"
	"net/http"
	"net/url"

	"construct/accounts/internal/config"
)

// DeliveryTenantStatus reports whether the user has been enrolled as a
// delivery tenant. Pulls from delivery-api's /internal/tenant-status endpoint
// so accounts doesn't need its own delivery_enabled column — delivery is the
// source of truth (a user is "enrolled" iff they have at least one api_key
// row).
//
// Returns (false, nil) if delivery isn't reachable or misconfigured — the
// Services page degrades to "not enabled" rather than blowing up on a peer
// outage. Enrollment + unenrollment are user-facing actions on delivery-api
// itself (POST/DELETE /api/enroll through the gateway); accounts doesn't
// proxy those.
func DeliveryTenantStatus(cfg *config.Config, userID string) (bool, error) {
	if cfg.DeliveryURL == "" || cfg.InternalSecret == "" {
		return false, nil
	}
	u := cfg.DeliveryURL + "/internal/tenant-status?user_id=" + url.QueryEscape(userID)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Internal-Secret", cfg.InternalSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	return body.Enabled, nil
}
