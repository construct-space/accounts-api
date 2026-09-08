package handlers

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/mailer"
	"construct/accounts/internal/middleware"
	"construct/accounts/internal/models"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn         *webauthn.WebAuthn
	challengeStore   = &challengeMap{m: make(map[string]*challengeEntry)}
	challengeCleanup sync.Once
)

type challengeEntry struct {
	session *webauthn.SessionData
	userID  uint
	expires time.Time
}

type challengeMap struct {
	mu sync.Mutex
	m  map[string]*challengeEntry
}

func (c *challengeMap) Set(key string, entry *challengeEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry
}

func (c *challengeMap) Get(key string) *challengeEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.m[key]
	if !ok || time.Now().After(entry.expires) {
		delete(c.m, key)
		return nil
	}
	return entry
}

func (c *challengeMap) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func InitWebAuthn() {
	// RPID is the "anchor" domain passkeys are bound to. We use the apex
	// (lisaos.dev) so a credential works on any subdomain — the
	// browser's check is "current origin must be equal to or a subdomain
	// of RPID", and sibling subdomains (my.c.s vs accounts.c.s) don't
	// qualify when RPID is either of them individually.
	rpid := Cfg.WebAuthnRPID
	if rpid == "" {
		u, _ := url.Parse(Cfg.AppURL)
		rpid = u.Hostname()
	}
	origins := Cfg.WebAuthnOrigins
	if len(origins) == 0 {
		origins = []string{Cfg.AppURL}
	}

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Construct",
		RPID:          rpid,
		RPOrigins:     origins,
	})
	if err != nil {
		panic("webauthn init: " + err.Error())
	}

	// Periodic cleanup of expired challenges
	challengeCleanup.Do(func() {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				challengeStore.mu.Lock()
				now := time.Now()
				for k, v := range challengeStore.m {
					if now.After(v.expires) {
						delete(challengeStore.m, k)
					}
				}
				challengeStore.mu.Unlock()
			}
		}()
	})
}

func getWebAuthnUser(user *models.User) *models.WebAuthnUser {
	var passkeys []models.Passkey
	database.DB.Where("user_id = ?", user.ID).Find(&passkeys)
	creds := make([]webauthn.Credential, len(passkeys))
	for i, p := range passkeys {
		creds[i] = p.ToCredential()
	}
	return &models.WebAuthnUser{User: user, Credentials: creds}
}

// POST /api/passkey/register/begin
func PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	wUser := getWebAuthnUser(user)
	options, session, err := webAuthn.BeginRegistration(wUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}

	token := middleware.ParseCookie(r.Header.Get("Cookie"), "session")
	challengeStore.Set("reg:"+token, &challengeEntry{
		session: session,
		userID:  user.ID,
		expires: time.Now().Add(5 * time.Minute),
	})

	WriteJSON(w, 200, options)
}

// POST /api/passkey/register/finish
func PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	token := middleware.ParseCookie(r.Header.Get("Cookie"), "session")
	entry := challengeStore.Get("reg:" + token)
	if entry == nil {
		WriteJSON(w, 400, map[string]any{"error": "Challenge expired"})
		return
	}
	challengeStore.Delete("reg:" + token)

	wUser := getWebAuthnUser(user)
	credential, err := webAuthn.FinishRegistration(wUser, *entry.session, r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}

	// Get passkey name from query or default
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}

	passkey := models.Passkey{
		UserID:         user.ID,
		Name:           name,
		CredentialID:   credential.ID,
		PublicKey:      credential.PublicKey,
		AAGUID:         credential.Authenticator.AAGUID,
		SignCount:      credential.Authenticator.SignCount,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}
	database.DB.Create(&passkey)
	safeAsync("mailer.passkey_added", func() { _ = mailer.SendPasskeyAddedEmail(Cfg, user.Email, passkey.Name) })

	WriteJSON(w, 200, map[string]any{"message": "Passkey registered", "id": passkey.ID, "name": passkey.Name})
}

// POST /api/passkey/login/begin
func PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, session, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		WriteJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}

	// Store challenge keyed by the challenge itself (no session cookie yet)
	challengeKey := session.Challenge
	challengeStore.Set("login:"+challengeKey, &challengeEntry{
		session: session,
		expires: time.Now().Add(5 * time.Minute),
	})

	// Send challenge key in response so client can send it back
	resp := map[string]any{
		"publicKey":    options.Response,
		"challengeKey": challengeKey,
	}
	WriteJSON(w, 200, resp)
}

// POST /api/passkey/login/finish
func PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	challengeKey := r.URL.Query().Get("challenge_key")
	returnTo := r.URL.Query().Get("return_to")

	entry := challengeStore.Get("login:" + challengeKey)
	if entry == nil {
		WriteJSON(w, 400, map[string]any{"error": "Challenge expired"})
		return
	}
	challengeStore.Delete("login:" + challengeKey)

	// Discoverable login handler — finds user by credential
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		// userHandle is the WebAuthnID (8-byte big-endian uint64)
		var userID uint64
		if len(userHandle) == 8 {
			userID = uint64(userHandle[0])<<56 | uint64(userHandle[1])<<48 |
				uint64(userHandle[2])<<40 | uint64(userHandle[3])<<32 |
				uint64(userHandle[4])<<24 | uint64(userHandle[5])<<16 |
				uint64(userHandle[6])<<8 | uint64(userHandle[7])
		}

		var user models.User
		if err := database.DB.First(&user, userID).Error; err != nil {
			return nil, err
		}

		return getWebAuthnUser(&user), nil
	}

	credential, err := webAuthn.FinishDiscoverableLogin(handler, *entry.session, r)
	if err != nil {
		WriteJSON(w, 401, map[string]any{"error": "Authentication failed"})
		return
	}

	// Update sign count and backup flags
	database.DB.Model(&models.Passkey{}).
		Where("credential_id = ?", credential.ID).
		Updates(map[string]any{
			"sign_count":      credential.Authenticator.SignCount,
			"backup_eligible": credential.Flags.BackupEligible,
			"backup_state":    credential.Flags.BackupState,
		})

	// Find the user from the credential
	var passkey models.Passkey
	database.DB.Where("credential_id = ?", credential.ID).First(&passkey)

	var user models.User
	database.DB.First(&user, passkey.UserID)

	// Create session
	now := time.Now()
	user.LastLogin = &now
	database.DB.Save(&user)

	ua := r.UserAgent()
	ip := getClientIP(r)
	sess := models.Session{
		Token:     models.GenerateSessionToken(),
		UserID:    user.ID,
		UserAgent: &ua,
		IPAddress: &ip,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	database.DB.Create(&sess)
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.Session{})

	w.Header().Set("Set-Cookie", middleware.SessionCookie(Cfg, sess.Token, false))

	redirectURL := safeRedirectURL(returnTo, Cfg)

	WriteJSON(w, 200, map[string]any{
		"message":     "Authenticated",
		"redirect_to": redirectURL,
	})
}

// GET /api/passkeys
func ListPasskeys(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	var passkeys []models.Passkey
	database.DB.Where("user_id = ?", user.ID).Order("created_at desc").Find(&passkeys)

	data := make([]map[string]any, len(passkeys))
	for i, p := range passkeys {
		data[i] = map[string]any{
			"id":         p.ID,
			"name":       p.Name,
			"created_at": p.CreatedAt,
		}
	}
	WriteJSON(w, 200, map[string]any{"passkeys": data})
}

// DELETE /api/passkey/{id}
func PasskeyDelete(w http.ResponseWriter, r *http.Request) {
	user := getLoggedInUser(r)
	if user == nil {
		WriteJSON(w, 401, map[string]any{"error": "Unauthorized"})
		return
	}

	id := r.PathValue("id")
	var passkey models.Passkey
	if err := database.DB.First(&passkey, id).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"error": "Passkey not found"})
		return
	}
	if passkey.UserID != user.ID {
		WriteJSON(w, 403, map[string]any{"error": "Forbidden"})
		return
	}

	database.DB.Delete(&passkey)
	safeAsync("mailer.passkey_removed", func() { _ = mailer.SendPasskeyRemovedEmail(Cfg, user.Email, passkey.Name) })
	WriteJSON(w, 200, map[string]any{"message": "Passkey removed"})
}
