// Package services provides thin HTTP clients for peer infra services
// (source, developer). All calls use the shared X-Internal-Secret header;
// accounts never speaks to a peer without it.
package services

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"construct/accounts/internal/config"
)

var client = &http.Client{Timeout: 3 * time.Second}

// Membership summarizes what source returns from /internal/membership.
// Nil/empty when the user is not in any org.
type Membership struct {
	OrgID    string   `json:"org_id"`
	OrgName  string   `json:"org_name"`
	OrgSlug  string   `json:"org_slug"`
	OrgIcon  string   `json:"org_icon"`
	MemberID string   `json:"member_id"`
	Roles    []string `json:"roles"`
}

// PublisherInfo summarizes what developer returns from /internal/publisher.
type PublisherInfo struct {
	PublisherID uint   `json:"publisher_id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	UserID      string `json:"user_id"`
	Verified    bool   `json:"verified"`
}

// GetMembership calls source. Returns (nil, nil) on 404.
func GetMembership(cfg *config.Config, userID string) (*Membership, error) {
	if cfg.SourceURL == "" || cfg.InternalSecret == "" {
		return nil, nil
	}
	u := cfg.SourceURL + "/internal/membership?user_id=" + url.QueryEscape(userID)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Internal-Secret", cfg.InternalSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var m Membership
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetPersonalPublisher calls developer. Returns (nil, nil) if user has no
// personal Publisher record.
func GetPersonalPublisher(cfg *config.Config, userID string) (*PublisherInfo, error) {
	if cfg.DeveloperURL == "" || cfg.InternalSecret == "" {
		return nil, nil
	}
	u := cfg.DeveloperURL + "/internal/publisher?user_id=" + url.QueryEscape(userID)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Internal-Secret", cfg.InternalSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var p PublisherInfo
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetOrgPublisher calls developer. Returns (nil, nil) if the org is not
// enrolled as a publisher.
func GetOrgPublisher(cfg *config.Config, orgID string) (*PublisherInfo, error) {
	if cfg.DeveloperURL == "" || cfg.InternalSecret == "" {
		return nil, nil
	}
	u := cfg.DeveloperURL + "/internal/publisher/org?org_id=" + url.QueryEscape(orgID)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Internal-Secret", cfg.InternalSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var p PublisherInfo
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}
