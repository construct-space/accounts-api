package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"
)

var csrfSecret []byte

func init() {
	csrfSecret = make([]byte, 32)
	rand.Read(csrfSecret)
}

func SetCSRFSecret(secret string) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		log.Println("[csrf] WARNING: CSRF_SECRET is unset; tokens will rotate on restart")
		return
	}
	decoded, err := hex.DecodeString(secret)
	if err == nil && len(decoded) >= 32 {
		csrfSecret = decoded
		return
	}
	csrfSecret = []byte(secret)
}

// GenerateCSRFToken creates a token tied to the session
func GenerateCSRFToken(sessionToken string) string {
	ts := time.Now().Unix()
	msg := sessionToken + ":" + hex.EncodeToString([]byte{byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts)})
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(msg))
	sig := hex.EncodeToString(mac.Sum(nil))
	return hex.EncodeToString([]byte{byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts)}) + "." + sig
}

// ValidateCSRFToken checks the token is valid and not expired (6h window)
func ValidateCSRFToken(token, sessionToken string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	tsBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(tsBytes) != 4 {
		return false
	}

	ts := int64(tsBytes[0])<<24 | int64(tsBytes[1])<<16 | int64(tsBytes[2])<<8 | int64(tsBytes[3])
	if time.Now().Unix()-ts > 6*3600 {
		return false
	}

	msg := sessionToken + ":" + parts[0]
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(msg))
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(parts[1]))
}

// CSRFProtect wraps a handler to enforce CSRF on POST/PUT/DELETE
func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			// Skip CSRF for API endpoints that use token auth (Authorization header)
			if r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}

			// Skip for login/register/forgot/reset/verify-2fa (no session yet)
			path := r.URL.Path
			if path == "/api/auth/login" || path == "/api/auth/register" ||
				path == "/forgot-password" || path == "/reset-password" || path == "/verify-2fa" ||
				path == "/api/auth/forgot-password" || path == "/api/auth/reset-password" || path == "/api/auth/verify-2fa" ||
				path == "/oauth/token" || path == "/oauth/revoke" ||
				path == "/api/passkey/login/begin" || path == "/api/passkey/login/finish" {
				next.ServeHTTP(w, r)
				return
			}

			sessionToken := ParseCookie(r.Header.Get("Cookie"), "session")
			csrfToken := r.FormValue("_csrf")
			if csrfToken == "" {
				csrfToken = r.Header.Get("X-CSRF-Token")
			}

			if !ValidateCSRFToken(csrfToken, sessionToken) {
				http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
