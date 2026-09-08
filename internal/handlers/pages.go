package handlers

import (
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"
)

var pageTemplates map[string]*template.Template

func parseUserAgent(ua *string) string {
	if ua == nil || *ua == "" {
		return "Unknown device"
	}
	s := *ua

	// Detect browser
	browser := "Unknown browser"
	switch {
	case strings.Contains(s, "Edg/"):
		browser = "Edge"
	case strings.Contains(s, "OPR/") || strings.Contains(s, "Opera"):
		browser = "Opera"
	case strings.Contains(s, "Brave"):
		browser = "Brave"
	case strings.Contains(s, "Vivaldi"):
		browser = "Vivaldi"
	case strings.Contains(s, "Chrome/") && !strings.Contains(s, "Chromium"):
		browser = "Chrome"
	case strings.Contains(s, "Safari/") && !strings.Contains(s, "Chrome"):
		browser = "Safari"
	case strings.Contains(s, "Firefox/"):
		browser = "Firefox"
	}

	// Detect OS
	os := ""
	switch {
	case strings.Contains(s, "Macintosh") || strings.Contains(s, "Mac OS"):
		os = "macOS"
	case strings.Contains(s, "Windows"):
		os = "Windows"
	case strings.Contains(s, "iPhone"):
		os = "iPhone"
	case strings.Contains(s, "iPad"):
		os = "iPad"
	case strings.Contains(s, "Android"):
		os = "Android"
	case strings.Contains(s, "Linux"):
		os = "Linux"
	case strings.Contains(s, "CrOS"):
		os = "ChromeOS"
	}

	if os != "" {
		return browser + " on " + os
	}
	return browser
}

func cleanIP(ip *string) string {
	if ip == nil || *ip == "" {
		return ""
	}
	s := *ip
	// Clean localhost variants
	if s == "[::1]" || s == "::1" || s == "127.0.0.1" {
		return "localhost"
	}
	// Strip port if present
	if idx := strings.LastIndex(s, ":"); idx > 0 {
		host := s[:idx]
		if host == "[::1]" || host == "::1" || host == "127.0.0.1" {
			return "localhost"
		}
		return host
	}
	return s
}

var funcMap = template.FuncMap{
	"deref": func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	},
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"formatDate": func(t time.Time) string {
		return t.Format("Jan 2, 2006")
	},
}

func InitTemplates(embedFS fs.FS) {
	tmplFS, _ := fs.Sub(embedFS, "templates")
	pageTemplates = make(map[string]*template.Template)

	// Auth pages (no sidebar)
	for _, page := range []string{"login.html", "register.html", "forgot-password.html", "reset-password.html", "verify-2fa.html"} {
		pageTemplates[page] = template.Must(
			template.New("").Funcs(funcMap).ParseFS(tmplFS, "base.html", page),
		)
	}
	// Dashboard pages (with sidebar)
	for _, page := range []string{"home.html", "profile.html", "security.html", "appearance.html", "password.html", "passkeys.html", "sessions.html", "2fa.html", "notifications.html", "privacy.html", "services.html"} {
		pageTemplates[page] = template.Must(
			template.New("").Funcs(funcMap).ParseFS(tmplFS, "base.html", "sidebar.html", page),
		)
	}
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	t, ok := pageTemplates[name]
	if !ok {
		http.Error(w, "Template not found: "+name, 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "Template error: "+err.Error(), 500)
	}
}

// Page: GET /login
func LoginPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	renderTemplate(w, "login.html", map[string]any{
		"Error":    r.URL.Query().Get("error"),
		"Message":  r.URL.Query().Get("message"),
		"ReturnTo": r.URL.Query().Get("return_to"),
	})
}

// Page: GET /forgot-password
func ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	renderTemplate(w, "forgot-password.html", map[string]any{
		"Error":   r.URL.Query().Get("error"),
		"Message": r.URL.Query().Get("message"),
	})
}

// Page: GET /reset-password
func ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Validate token exists and not expired
	var count int64
	database.DB.Model(&models.User{}).Where("reset_token = ? AND reset_token_expiry > ?", token, time.Now()).Count(&count)
	if count == 0 {
		http.Redirect(w, r, "/login?error=Invalid+or+expired+reset+link", http.StatusFound)
		return
	}

	renderTemplate(w, "reset-password.html", map[string]any{
		"Token": token,
		"Error": r.URL.Query().Get("error"),
	})
}

// Page: GET /verify-2fa
func Verify2FAPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	returnTo := r.URL.Query().Get("return_to")

	if token == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderTemplate(w, "verify-2fa.html", map[string]any{
		"Token":    token,
		"ReturnTo": returnTo,
		"Error":    r.URL.Query().Get("error"),
	})
}

// Page: GET /register
func RegisterPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	renderTemplate(w, "register.html", map[string]any{
		"Error":    r.URL.Query().Get("error"),
		"ReturnTo": r.URL.Query().Get("return_to"),
	})
}

// Page: GET /
func HomePage(w http.ResponseWriter, r *http.Request) {
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

	var sessionCount int64
	database.DB.Model(&models.Session{}).Where("user_id = ? AND expires_at > ?", user.ID, time.Now()).Count(&sessionCount)

	var passkeyCount int64
	database.DB.Model(&models.Passkey{}).Where("user_id = ?", user.ID).Count(&passkeyCount)

	renderTemplate(w, "home.html", map[string]any{
		"User":         user,
		"Initials":     initials,
		"SessionCount": sessionCount,
		"PasskeyCount": passkeyCount,
		"CSRFToken":    getCSRFToken(r),
		"Message":      r.URL.Query().Get("message"),
		"Error":        r.URL.Query().Get("error"),
		"Active":       "home",
	})
}

// Page: GET /profile
func ProfilePage(w http.ResponseWriter, r *http.Request) {
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

	renderTemplate(w, "profile.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "profile",
	})
}

// POST /profile
func ProfileUpdate(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	_ = r.ParseForm()
	updates := map[string]any{}

	if v := strings.TrimSpace(r.FormValue("first_name")); v != "" {
		updates["first_name"] = v
	}
	if v := strings.TrimSpace(r.FormValue("last_name")); v != "" {
		updates["last_name"] = v
	}
	if v := strings.TrimSpace(r.FormValue("phone")); v != "" {
		updates["phone"] = v
	}
	if v := strings.TrimSpace(strings.ToLower(r.FormValue("username"))); v != "" {
		var count int64
		database.DB.Model(&models.User{}).Where("username = ? AND id != ?", v, user.ID).Count(&count)
		if count > 0 {
			http.Redirect(w, r, "/profile?error=Username+already+taken", http.StatusFound)
			return
		}
		updates["username"] = v
	}

	if len(updates) > 0 {
		database.DB.Model(user).Updates(updates)
	}

	http.Redirect(w, r, "/profile?message=Profile+updated", http.StatusFound)
}

// Page: GET /security
func SecurityPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var sessions []models.Session
	database.DB.Where("user_id = ? AND expires_at > ?", user.ID, time.Now()).Find(&sessions)

	currentToken := middleware.ParseCookie(r.Header.Get("Cookie"), "session")

	type sessionView struct {
		ID        uint
		Device    string
		IP        string
		CreatedAt time.Time
		IsCurrent bool
	}
	var sessionViews []sessionView
	for _, s := range sessions {
		sessionViews = append(sessionViews, sessionView{
			ID:        s.ID,
			Device:    parseUserAgent(s.UserAgent),
			IP:        cleanIP(s.IPAddress),
			CreatedAt: s.CreatedAt,
			IsCurrent: s.Token == currentToken,
		})
	}

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	var passkeys []models.Passkey
	database.DB.Where("user_id = ?", user.ID).Find(&passkeys)

	renderTemplate(w, "security.html", map[string]any{
		"User":        user,
		"Initials":    initials,
		"Sessions":    sessionViews,
		"Passkeys":    passkeys,
		"TOTPEnabled": user.TOTPEnabled,
		"CSRFToken":   getCSRFToken(r),
		"Message":     r.URL.Query().Get("message"),
		"Error":       r.URL.Query().Get("error"),
		"Active":      "security",
	})
}

// Page: GET /security/password
func PasswordPage(w http.ResponseWriter, r *http.Request) {
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

	renderTemplate(w, "password.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "password",
	})
}

// Page: GET /security/passkeys
func PasskeysPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var passkeys []models.Passkey
	database.DB.Where("user_id = ?", user.ID).Find(&passkeys)

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	renderTemplate(w, "passkeys.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"Passkeys":  passkeys,
		"CSRFToken": getCSRFToken(r),
		"Active":    "passkeys",
	})
}

// Page: GET /security/sessions
func SessionsPage(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var sessions []models.Session
	database.DB.Where("user_id = ? AND expires_at > ?", user.ID, time.Now()).Find(&sessions)

	currentToken := middleware.ParseCookie(r.Header.Get("Cookie"), "session")

	type sessionView struct {
		ID        uint
		Device    string
		IP        string
		CreatedAt time.Time
		IsCurrent bool
	}
	var sessionViews []sessionView
	for _, s := range sessions {
		sessionViews = append(sessionViews, sessionView{
			ID:        s.ID,
			Device:    parseUserAgent(s.UserAgent),
			IP:        cleanIP(s.IPAddress),
			CreatedAt: s.CreatedAt,
			IsCurrent: s.Token == currentToken,
		})
	}

	initials := ""
	if len(user.FirstName) > 0 {
		initials += string(user.FirstName[0])
	}
	if len(user.LastName) > 0 {
		initials += string(user.LastName[0])
	}

	renderTemplate(w, "sessions.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"Sessions":  sessionViews,
		"CSRFToken": getCSRFToken(r),
		"Message":   r.URL.Query().Get("message"),
		"Error":     r.URL.Query().Get("error"),
		"Active":    "sessions",
	})
}

// Page: GET /appearance
func AppearancePage(w http.ResponseWriter, r *http.Request) {
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

	renderTemplate(w, "appearance.html", map[string]any{
		"User":      user,
		"Initials":  initials,
		"CSRFToken": getCSRFToken(r),
		"Active":    "appearance",
	})
}

// POST /security/password
func PasswordUpdate(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	_ = r.ParseForm()
	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if !user.CheckPassword(current) {
		http.Redirect(w, r, "/security/password?error=Current+password+is+incorrect", http.StatusFound)
		return
	}
	if len(newPw) < 8 {
		http.Redirect(w, r, "/security/password?error=Password+must+be+at+least+8+characters", http.StatusFound)
		return
	}
	if len([]byte(newPw)) > 72 {
		http.Redirect(w, r, "/security/password?error=Password+is+too+long", http.StatusFound)
		return
	}
	if newPw != confirm {
		http.Redirect(w, r, "/security/password?error=Passwords+do+not+match", http.StatusFound)
		return
	}

	passwordHash, err := models.HashPassword(newPw)
	if err != nil {
		http.Redirect(w, r, "/security/password?error=Password+is+invalid", http.StatusFound)
		return
	}
	database.DB.Model(user).Update("password", passwordHash)
	http.Redirect(w, r, "/security/password?message=Password+updated", http.StatusFound)
}

// POST /security/sessions/{id}/revoke
func SessionRevoke(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	id := r.PathValue("id")
	var session models.Session
	if err := database.DB.First(&session, id).Error; err != nil {
		http.Redirect(w, r, "/security?error=Session+not+found", http.StatusFound)
		return
	}
	if session.UserID != user.ID {
		http.Redirect(w, r, "/security?error=Forbidden", http.StatusFound)
		return
	}

	database.DB.Delete(&session)
	http.Redirect(w, r, "/security?message=Session+revoked", http.StatusFound)
}
