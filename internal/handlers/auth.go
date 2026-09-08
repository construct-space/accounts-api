package handlers

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/mailer"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"
)

func isJSONRequest(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json")
}

func Login(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	json := isJSONRequest(r)
	email := strings.TrimSpace(strings.ToLower(body["email"]))
	password := body["password"]
	returnTo := body["return_to"]
	// Presence of client_id switches the response from a browser session
	// cookie to an OAuth bearer+refresh token pair. Desktop/CLI/API clients
	// pass their registered client_id (e.g. "construct_app") and consume
	// the same shape /oauth/token returns. Browsers omit it and the cookie
	// flow stays unchanged.
	clientID := body["client_id"]
	wantsTokens := json && clientID != ""

	redirectURL := safeRedirectURL(returnTo, Cfg)

	if email == "" || password == "" {
		if json {
			WriteJSON(w, 400, map[string]any{"error": "Email and password are required"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/login?error=Email+and+password+are+required&return_to="+encodeParam(returnTo), http.StatusFound)
		}
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil || !user.CheckPassword(password) {
		if json {
			WriteJSON(w, 401, map[string]any{"error": "Invalid email or password"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/login?error=Invalid+email+or+password&return_to="+encodeParam(returnTo), http.StatusFound)
		}
		return
	}

	if user.Suspended {
		if json {
			WriteJSON(w, 403, map[string]any{"error": "Account suspended"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/login?error=Account+suspended&return_to="+encodeParam(returnTo), http.StatusFound)
		}
		return
	}

	if user.MustChangePassword {
		token := models.GenerateResetToken()
		expiry := time.Now().Add(24 * time.Hour)
		database.DB.Model(&user).Updates(map[string]any{
			"reset_token":        token,
			"reset_token_expiry": expiry,
		})
		if json {
			WriteJSON(w, 200, map[string]any{"must_change_password": true, "reset_token": token})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/reset-password?token="+token+"&return_to="+encodeParam(returnTo), http.StatusFound)
		}
		return
	}

	now := time.Now()
	user.LastLogin = &now
	database.DB.Save(&user)

	// Clean expired sessions
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.Session{})

	// Check if 2FA is enabled
	if user.TOTPEnabled && user.TOTPSecret != nil {
		pending := "__2fa_pending__"
		session := models.Session{
			Token:     models.GenerateSessionToken(),
			UserID:    user.ID,
			UserAgent: &pending,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		database.DB.Create(&session)
		if json {
			WriteJSON(w, 200, map[string]any{"requires_2fa": true, "pending_token": session.Token, "return_to": returnTo})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/verify-2fa?token="+session.Token+"&return_to="+encodeParam(returnTo), http.StatusFound)
		}
		return
	}

	if wantsTokens {
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
	session := models.Session{
		Token:     models.GenerateSessionToken(),
		UserID:    user.ID,
		UserAgent: &ua,
		IPAddress: &ip,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	database.DB.Create(&session)

	w.Header().Set("Set-Cookie", middleware.SessionCookie(Cfg, session.Token, false))
	w.Header().Set("Cache-Control", "no-store")
	if json {
		WriteJSON(w, 200, map[string]any{"redirect_to": redirectURL})
	} else {
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	json := isJSONRequest(r)
	firstName := strings.TrimSpace(body["first_name"])
	lastName := strings.TrimSpace(body["last_name"])
	email := strings.TrimSpace(strings.ToLower(body["email"]))
	username := strings.TrimSpace(strings.ToLower(body["username"]))
	password := body["password"]
	returnTo := body["return_to"]
	phone := body["phone"]
	// Desktop/CLI registration — returns bearer tokens instead of a cookie.
	// Same contract as Login (see note there).
	clientID := body["client_id"]
	wantsTokens := json && clientID != ""

	regError := func(msg string) {
		if json {
			WriteJSON(w, 400, map[string]any{"error": msg})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/register?error="+encodeParam(msg)+"&return_to="+encodeParam(returnTo), http.StatusFound)
		}
	}

	if firstName == "" {
		regError("First name is required")
		return
	}
	if lastName == "" {
		regError("Last name is required")
		return
	}
	if email == "" {
		regError("Email is required")
		return
	}
	if username == "" {
		regError("Username is required")
		return
	}
	if len(password) < 8 {
		regError("Password must be at least 8 characters")
		return
	}
	if len([]byte(password)) > 72 {
		regError("Registration failed")
		return
	}

	var count int64
	database.DB.Model(&models.User{}).Where("email = ?", email).Count(&count)
	if count > 0 {
		regError("Registration failed")
		return
	}
	database.DB.Model(&models.User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		regError("Registration failed")
		return
	}

	var phonePtr *string
	if phone != "" {
		phonePtr = &phone
	}

	passwordHash, err := models.HashPassword(password)
	if err != nil {
		regError("Registration failed")
		return
	}

	user := models.User{
		FirstName: firstName,
		LastName:  lastName,
		Username:  username,
		Email:     email,
		Password:  passwordHash,
		Phone:     phonePtr,
	}
	database.DB.Create(&user)
	safeAsync("mailer.welcome", func() { _ = mailer.SendWelcomeEmail(Cfg, user.Email, user.FirstName) })

	if wantsTokens {
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
	session := models.Session{
		Token:     models.GenerateSessionToken(),
		UserID:    user.ID,
		UserAgent: &ua,
		IPAddress: &ip,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	database.DB.Create(&session)

	redirectURL := safeRedirectURL(returnTo, Cfg)

	w.Header().Set("Set-Cookie", middleware.SessionCookie(Cfg, session.Token, false))
	w.Header().Set("Cache-Control", "no-store")
	if json {
		WriteJSON(w, 200, map[string]any{"redirect_to": redirectURL})
	} else {
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

func Me(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"authenticated": false})
		return
	}
	WriteJSON(w, 200, map[string]any{
		"authenticated": true,
		"user":          user,
	})
}

func Logout(w http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Get("Cookie")
	token := middleware.ParseCookie(cookie, "session")
	if token != "" {
		database.DB.Where("token = ?", token).Delete(&models.Session{})
	}

	w.Header().Set("Set-Cookie", middleware.SessionCookie(Cfg, "", true))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, Cfg.AppURL+"/login", http.StatusFound)
}

func UpdateProfile(w http.ResponseWriter, r *http.Request) {
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

	updates := map[string]any{}
	if v, ok := body["first_name"]; ok {
		updates["first_name"] = strings.TrimSpace(v)
	}
	if v, ok := body["last_name"]; ok {
		updates["last_name"] = strings.TrimSpace(v)
	}
	if v, ok := body["phone"]; ok {
		updates["phone"] = strings.TrimSpace(v)
	}
	if v, ok := body["avatar_url"]; ok {
		avatarURL, err := normalizeAvatarURL(v)
		if err != nil {
			WriteJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		updates["avatar_url"] = avatarURL
	}
	if v, ok := body["username"]; ok {
		newUsername := strings.TrimSpace(strings.ToLower(v))
		if newUsername != "" {
			var count int64
			database.DB.Model(&models.User{}).Where("username = ? AND id != ?", newUsername, user.ID).Count(&count)
			if count > 0 {
				WriteJSON(w, 409, map[string]any{"error": "Username already taken"})
				return
			}
			updates["username"] = newUsername
		}
	}

	if len(updates) > 0 {
		if err := database.DB.Model(user).Updates(updates).Error; err != nil {
			log.Printf("[profile] update user %s failed: %v", user.UUID, err)
			WriteJSON(w, 500, map[string]any{"error": "Profile update failed"})
			return
		}
	}

	if err := database.DB.First(user, user.ID).Error; err != nil {
		log.Printf("[profile] reload user %s failed: %v", user.UUID, err)
		WriteJSON(w, 500, map[string]any{"error": "Profile reload failed"})
		return
	}
	WriteJSON(w, 200, user)
}

func normalizeAvatarURL(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	if len(v) > 2048 {
		return "", errors.New("avatar_url is too long")
	}

	u, err := url.Parse(v)
	if err != nil {
		return "", err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errInvalidAvatarURL()
	}
	return v, nil
}

func errInvalidAvatarURL() error {
	return &avatarURLError{}
}

type avatarURLError struct{}

func (*avatarURLError) Error() string {
	return "avatar_url must be an absolute http or https URL"
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
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

	if !user.CheckPassword(body["current_password"]) {
		WriteJSON(w, 403, map[string]any{"error": "Current password is incorrect"})
		return
	}

	newPassword := body["new_password"]
	if len(newPassword) < 8 {
		WriteJSON(w, 400, map[string]any{"error": "New password must be at least 8 characters"})
		return
	}
	if len([]byte(newPassword)) > 72 {
		WriteJSON(w, 400, map[string]any{"error": "New password is too long"})
		return
	}

	passwordHash, err := models.HashPassword(newPassword)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": "New password is invalid"})
		return
	}
	database.DB.Model(user).Update("password", passwordHash)
	safeAsync("mailer.password_changed", func() { _ = mailer.SendPasswordChangedEmail(Cfg, user.Email) })
	WriteJSON(w, 200, map[string]any{"message": "Password updated"})
}

func ListSessions(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	var sessions []models.Session
	database.DB.Where("user_id = ? AND expires_at > ?", user.ID, time.Now()).Find(&sessions)

	currentToken := middleware.ParseCookie(r.Header.Get("Cookie"), "session")

	data := make([]map[string]any, len(sessions))
	for i, s := range sessions {
		data[i] = map[string]any{
			"id":         s.ID,
			"user_agent": s.UserAgent,
			"ip_address": s.IPAddress,
			"expires_at": s.ExpiresAt,
			"created_at": s.CreatedAt,
			"is_current": s.Token == currentToken,
		}
	}

	WriteJSON(w, 200, map[string]any{"data": data})
}

// POST /forgot-password
func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	json := isJSONRequest(r)
	email := strings.TrimSpace(strings.ToLower(body["email"]))
	successMsg := "If an account exists with that email, we sent a reset link"

	if email == "" {
		if json {
			WriteJSON(w, 400, map[string]any{"error": "Email is required"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/forgot-password?error=Email+is+required", http.StatusFound)
		}
		return
	}

	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err == nil {
		token := models.GenerateResetToken()
		expiry := time.Now().Add(1 * time.Hour)
		database.DB.Model(&user).Updates(map[string]any{
			"reset_token":        token,
			"reset_token_expiry": expiry,
		})
		// Log the outcome — the caller still returns the generic success
		// message regardless, but without this log a misconfigured
		// DELIVERY_URL / DELIVERY_API_KEY (or downstream 5xx) is invisible.
		if err := mailer.SendResetEmail(Cfg, user.Email, token); err != nil {
			log.Printf("[forgot-password] SendResetEmail to %s failed: %v", user.Email, err)
		} else {
			log.Printf("[forgot-password] reset email queued for %s", user.Email)
		}
	} else {
		log.Printf("[forgot-password] no user for %s", email)
	}

	// Don't reveal if email exists
	if json {
		WriteJSON(w, 200, map[string]any{"message": successMsg})
	} else {
		http.Redirect(w, r, Cfg.AppURL+"/forgot-password?message="+encodeParam(successMsg), http.StatusFound)
	}
}

// POST /reset-password
func ResetPassword(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	json := isJSONRequest(r)
	token := body["token"]
	newPw := body["password"]
	confirm := body["confirm_password"]

	jsonErr := func(msg string) {
		if json {
			WriteJSON(w, 400, map[string]any{"error": msg})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/reset-password?token="+token+"&error="+encodeParam(msg), http.StatusFound)
		}
	}

	if token == "" {
		if json {
			WriteJSON(w, 400, map[string]any{"error": "Invalid reset link"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/login?error=Invalid+reset+link", http.StatusFound)
		}
		return
	}

	if len(newPw) < 8 {
		jsonErr("Password must be at least 8 characters")
		return
	}
	if len([]byte(newPw)) > 72 {
		jsonErr("Password is too long")
		return
	}

	if newPw != confirm {
		jsonErr("Passwords do not match")
		return
	}

	var user models.User
	if err := database.DB.Where("reset_token = ? AND reset_token_expiry > ?", token, time.Now()).First(&user).Error; err != nil {
		if json {
			WriteJSON(w, 400, map[string]any{"error": "Invalid or expired reset link"})
		} else {
			http.Redirect(w, r, Cfg.AppURL+"/login?error=Invalid+or+expired+reset+link", http.StatusFound)
		}
		return
	}

	passwordHash, err := models.HashPassword(newPw)
	if err != nil {
		jsonErr("Password is invalid")
		return
	}

	database.DB.Model(&user).Updates(map[string]any{
		"password":             passwordHash,
		"reset_token":          nil,
		"reset_token_expiry":   nil,
		"must_change_password": false,
	})
	safeAsync("mailer.password_changed", func() { _ = mailer.SendPasswordChangedEmail(Cfg, user.Email) })

	if json {
		WriteJSON(w, 200, map[string]any{"message": "Password reset successfully"})
	} else {
		http.Redirect(w, r, Cfg.AppURL+"/login?message=Password+reset+successfully", http.StatusFound)
	}
}

func DeleteSession(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": "Invalid session ID"})
		return
	}

	var session models.Session
	if err := database.DB.First(&session, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "Session not found"})
		return
	}

	if session.UserID != user.ID {
		WriteJSON(w, 403, map[string]any{"error": "Forbidden"})
		return
	}

	database.DB.Delete(&session)
	WriteJSON(w, 200, map[string]any{"message": "Session revoked"})
}
