package handlers

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"sync"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/mailer"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"

	"github.com/pquerna/otp/totp"
)

// Per-account 2FA brute-force protection. A TOTP code is only 10^6 wide with
// a ±1 step window; the pending session lives ~10 min, so without a per-token
// attempt cap an attacker who has the password can spray codes (IP rate limits
// are evadable). We count failures against the pending token in memory and
// burn the pending session after maxTwoFAAttempts, forcing a fresh login.
// In-memory is sufficient: entries are bounded (cleared on success/lockout,
// and the pending session expires regardless), and a server restart only ever
// resets counters downward, never granting extra attempts on a live token.
const maxTwoFAAttempts = 5

var (
	twoFAAttemptsMu sync.Mutex
	twoFAAttempts   = map[string]int{}
)

func recordTwoFAFailure(token string) int {
	twoFAAttemptsMu.Lock()
	defer twoFAAttemptsMu.Unlock()
	twoFAAttempts[token]++
	return twoFAAttempts[token]
}

func clearTwoFAAttempts(token string) {
	twoFAAttemptsMu.Lock()
	delete(twoFAAttempts, token)
	twoFAAttemptsMu.Unlock()
}

// GET /security/2fa
func TwoFactorPage(w http.ResponseWriter, r *http.Request) {
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

	renderTemplate(w, "2fa.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"Enabled":   user.TOTPEnabled,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "2fa",
	})
}

// POST /api/2fa/setup — generate TOTP secret, return QR as base64
func TwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	if user.TOTPEnabled {
		WriteJSON(w, 400, map[string]any{"error": "2FA is already enabled"})
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Construct",
		AccountName: user.Email,
	})
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": "Failed to generate secret"})
		return
	}

	// Store secret (not yet enabled until verified)
	secret := key.Secret()
	database.DB.Model(user).Update("totp_secret", secret)

	// Generate QR code as base64 PNG
	img, err := key.Image(200, 200)
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": "Failed to generate QR code"})
		return
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	qr := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	WriteJSON(w, 200, map[string]any{
		"qr_code": qr,
		"secret":  secret,
		"uri":     key.URL(),
	})
}

// POST /api/2fa/verify — verify TOTP code and enable 2FA
func TwoFactorVerify(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	body, err := parseBody(r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": "Bad request"})
		return
	}

	code := body["code"]
	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		WriteJSON(w, 400, map[string]any{"error": "No 2FA setup in progress"})
		return
	}

	if !totp.Validate(code, *user.TOTPSecret) {
		WriteJSON(w, 400, map[string]any{"error": "Invalid code"})
		return
	}

	database.DB.Model(user).Update("totp_enabled", true)
	safeAsync("mailer.two_factor_enabled", func() { _ = mailer.SendTwoFactorEnabledEmail(Cfg, user.Email) })
	WriteJSON(w, 200, map[string]any{"message": "2FA enabled"})
}

// POST /api/2fa/disable — disable 2FA
func TwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	body, err := parseBody(r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": "Bad request"})
		return
	}

	if !user.CheckPassword(body["password"]) {
		WriteJSON(w, 403, map[string]any{"error": "Incorrect password"})
		return
	}

	database.DB.Model(user).Updates(map[string]any{
		"totp_enabled": false,
		"totp_secret":  nil,
	})
	safeAsync("mailer.two_factor_disabled", func() { _ = mailer.SendTwoFactorDisabledEmail(Cfg, user.Email) })
	WriteJSON(w, 200, map[string]any{"message": "2FA disabled"})
}

// POST /verify-2fa — verify TOTP during login
func TwoFactorLogin(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	json := isJSONRequest(r)
	pendingToken := body["pending_token"]
	code := body["code"]
	returnTo := body["return_to"]
	// Desktop/CLI 2FA — echoes the client_id it sent to /api/auth/login so
	// this handler knows to mint bearer tokens instead of converting the
	// pending session into a long-lived cookie session.
	clientID := body["client_id"]
	wantsTokens := json && clientID != ""

	jsonErr := func(status int, msg string) {
		if json {
			WriteJSON(w, status, map[string]any{"error": msg})
		} else {
			http.Redirect(w, r, "/login?error="+encodeParam(msg), http.StatusFound)
		}
	}

	if pendingToken == "" || code == "" {
		jsonErr(400, "Invalid request")
		return
	}

	var session models.Session
	if err := database.DB.Where("token = ? AND expires_at > ?", pendingToken, time.Now()).First(&session).Error; err != nil {
		jsonErr(400, "Session expired")
		return
	}

	if session.UserAgent == nil || *session.UserAgent != "__2fa_pending__" {
		jsonErr(400, "Invalid session")
		return
	}

	var user models.User
	if err := database.DB.First(&user, session.UserID).Error; err != nil {
		jsonErr(400, "User not found")
		return
	}

	if user.TOTPSecret == nil || !totp.Validate(code, *user.TOTPSecret) {
		// Brute-force guard: after too many wrong codes, destroy the pending
		// session so the attacker must re-authenticate with the password.
		if recordTwoFAFailure(pendingToken) >= maxTwoFAAttempts {
			database.DB.Delete(&session)
			clearTwoFAAttempts(pendingToken)
			jsonErr(429, "Too many incorrect codes — please log in again")
			return
		}
		if json {
			WriteJSON(w, 400, map[string]any{"error": "Invalid code"})
		} else {
			http.Redirect(w, r, "/verify-2fa?token="+pendingToken+"&return_to="+encodeParam(returnTo)+"&error=Invalid+code", http.StatusFound)
		}
		return
	}

	// Correct code — clear the failure counter for this pending token.
	clearTwoFAAttempts(pendingToken)

	if wantsTokens {
		// Drop the pending-2FA session — desktop clients don't need it and
		// we don't want stale entries lingering.
		database.DB.Delete(&session)
		access, refresh, err := mintTokensForClient(user.ID, clientID, "openid profile email")
		if err != nil {
			WriteJSON(w, 400, map[string]any{"error": "invalid_client"})
			return
		}
		writeBearerTokens(w, access, refresh, &user)
		return
	}

	ua := r.UserAgent()
	ip := getClientIP(r)
	database.DB.Model(&session).Updates(map[string]any{
		"user_agent": ua,
		"ip_address": ip,
	})

	redirectURL := safeRedirectURL(returnTo, Cfg)

	w.Header().Set("Set-Cookie", middleware.SessionCookie(Cfg, session.Token, false))
	w.Header().Set("Cache-Control", "no-store")
	if json {
		WriteJSON(w, 200, map[string]any{"redirect_to": redirectURL})
	} else {
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}
