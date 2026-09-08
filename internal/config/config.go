package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Port           string
	AppURL         string
	AllowedOrigins []string
	DBDriver       string
	DBHost         string
	DBPort         string
	DBName         string
	DBUser         string
	DBPass         string
	DeliveryURL    string
	DeliveryAPIKey string
	EmailFrom      string
	// Peer services — called during /me/scope enrichment.
	SourceURL      string
	DeveloperURL   string
	InternalSecret string
	CSRFSecret     string

	// WebAuthn / passkey config. RPID must be the apex domain (or a parent
	// of every origin that should share passkeys); RPOrigins is the list of
	// origins we actually accept challenges from. Defaults target the
	// lisaos.dev production domains.
	WebAuthnRPID    string
	WebAuthnOrigins []string
}

func Load() *Config {
	loadEnvFile(".env")

	origins := strings.Split(env("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3050,http://localhost:4000,tauri://localhost"), ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	return &Config{
		Port:           env("PORT", "8000"),
		AppURL:         env("APP_URL", "http://localhost:8000"),
		AllowedOrigins: origins,
		DBDriver:       env("DB_DRIVER", "mysql"),
		DBHost:         env("DB_HOST", "localhost"),
		DBPort:         env("DB_PORT", "3306"),
		DBName:         env("DB_NAME", "construct"),
		DBUser:         env("DB_USER", "root"),
		DBPass:         env("DB_PASS", ""),
		DeliveryURL:    env("DELIVERY_URL", "https://delivery.lisaos.dev"),
		DeliveryAPIKey: env("DELIVERY_API_KEY", ""),
		EmailFrom:      env("EMAIL_FROM", "Construct <noreply@lisaos.dev>"),
		SourceURL:      env("SOURCE_URL", "https://source.lisaos.dev"),
		DeveloperURL:   env("DEVELOPER_URL", "https://developer.lisaos.dev"),
		InternalSecret: env("INTERNAL_SHARED_SECRET", ""),
		CSRFSecret:     env("CSRF_SECRET", ""),

		// Apex RPID → passkeys work across my.c.s, accounts.c.s, and any
		// future subdomain without re-registration on a single subdomain.
		// Existing passkeys registered under a subdomain RPID do need to
		// be re-registered once; this is the best a greenfield cutover
		// can do.
		WebAuthnRPID: env("WEBAUTHN_RPID", "lisaos.dev"),
		WebAuthnOrigins: splitCSV(env(
			"WEBAUTHN_ORIGINS",
			"https://my.lisaos.dev",
		)),
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) IsSecure() bool {
	return strings.HasPrefix(c.AppURL, "https")
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
}
