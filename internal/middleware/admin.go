package middleware

import (
	"net/http"
	"os"

	goauth "github.com/construct-space/go-auth"
)

// AdminAuth accepts requests carrying a matching X-Internal-Secret header.
// The secret is read from INTERNAL_SHARED_SECRET at call time.
func AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !goauth.Trusted(r, os.Getenv("INTERNAL_SHARED_SECRET")) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
