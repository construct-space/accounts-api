package handlers

import (
	"net/http"

	"construct/accounts/internal/services"
)

// GET /api/me/scope
// Returns the caller's resolved identity scope by asking source and developer.
// Single source of truth for "what can this user do right now". Designed to
// be called on app startup / settings open; role changes don't take effect
// until the user restarts the app (so they re-hit this endpoint).
//
// Response shape:
//   {
//     "authenticated": true,
//     "user": { ...User... },
//     "scope": "user" | "org",
//     "org": { "id", "name", "slug", "icon" } | null,
//     "roles": [...],           // present when scope="org"
//     "developer": bool         // present when scope="user" (personal Publisher exists)
//   }
func MeScope(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"authenticated": false})
		return
	}

	resp := map[string]any{
		"authenticated": true,
		"user":          user,
	}

	// `developer` always reflects whether the *personal* publisher exists.
	// It's surfaced on every response so the Account/Services page can
	// show personal-enrolled state independently of org scope.
	publisher, _ := services.GetPersonalPublisher(Cfg, user.UUID)
	resp["developer"] = publisher != nil

	// `delivery` reflects whether the user is enrolled as a delivery tenant
	// (at least one api_key row on delivery-api). Surfaced for the Services
	// page's Enable/Disable card + shell capability filter that hides the
	// Delivery space from unenrolled users.
	deliveryEnabled, _ := services.DeliveryTenantStatus(Cfg, user.UUID)
	resp["delivery"] = deliveryEnabled

	// Prefer org scope — org wins over personal per the isolation rule.
	// Within an org we also report whether the org itself is enrolled as
	// a publisher on org.developer, for the Org space's Services page.
	membership, _ := services.GetMembership(Cfg, user.UUID)
	if membership != nil {
		resp["scope"] = "org"
		orgPub, _ := services.GetOrgPublisher(Cfg, membership.OrgID)
		resp["org"] = map[string]any{
			"id":        membership.OrgID,
			"name":      membership.OrgName,
			"slug":      membership.OrgSlug,
			"icon":      membership.OrgIcon,
			"developer": orgPub != nil,
		}
		resp["member_id"] = membership.MemberID
		resp["roles"] = membership.Roles
		WriteJSON(w, 200, resp)
		return
	}

	resp["scope"] = "user"
	resp["org"] = nil
	WriteJSON(w, 200, resp)
}
