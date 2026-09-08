package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strings"
	"time"

	"construct/accounts/internal/database"
	"construct/accounts/internal/models"
)

func Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	mode := q.Get("mode")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if scope == "" {
		scope = "profile email"
	}

	if clientID == "" || redirectURI == "" || responseType != "code" {
		htmlError(w, "Invalid OAuth request. Required: client_id, redirect_uri, response_type=code")
		return
	}

	var client models.OAuthClient
	if err := database.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil || !client.Active {
		htmlError(w, "Unknown application")
		return
	}

	// Validate redirect_uri matches the registered client redirect URI
	if redirectURI != client.RedirectURI {
		htmlError(w, "Invalid redirect_uri for this application")
		return
	}

	user := getLoggedInUser(r)
	if user == nil {
		returnURL := r.URL.String()
		loginURL := Cfg.AppURL + "/login?return_to=" + encodeParam(returnURL)
		if loginHint := q.Get("login_hint"); loginHint != "" {
			loginURL += "&login_hint=" + encodeParam(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Generate code
	var codeChallengePtr, codeChallengeMethodPtr *string
	if codeChallenge != "" {
		codeChallengePtr = &codeChallenge
		codeChallengeMethodPtr = &codeChallengeMethod
	}
	var statePtr *string
	if state != "" {
		statePtr = &state
	}

	code := models.OAuthCode{
		Code:                models.GenerateOAuthCode(),
		ClientID:            clientID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               statePtr,
		CodeChallenge:       codeChallengePtr,
		CodeChallengeMethod: codeChallengeMethodPtr,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
	database.DB.Create(&code)

	// Clean up expired codes
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.OAuthCode{})
	database.DB.Where("used = ?", true).Delete(&models.OAuthCode{})

	// Popup mode
	if mode == "popup" {
		origin := getOrigin(redirectURI)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Authorization</title></head>
<body>
<script>
(function() {
  var data = {type: 'oauth_callback', code: '%s', state: '%s'};
  if (window.opener) {
    window.opener.postMessage(data, '%s');
    window.close();
  } else {
    var sep = '%s'.indexOf('?') > -1 ? '&' : '?';
    window.location.href = '%s' + sep + 'code=' + encodeURIComponent('%s') + '&state=' + encodeURIComponent('%s');
  }
})();
</script>
</body></html>`,
			html.EscapeString(code.Code),
			html.EscapeString(derefStr(statePtr)),
			html.EscapeString(origin),
			html.EscapeString(redirectURI),
			html.EscapeString(redirectURI),
			html.EscapeString(code.Code),
			html.EscapeString(derefStr(statePtr)),
		)
		return
	}

	// Build callback URL
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	callbackURL := redirectURI + sep + "code=" + code.Code
	if state != "" {
		callbackURL += "&state=" + state
	}

	// Custom protocol URIs (e.g. construct://oauth/callback)
	if !strings.HasPrefix(redirectURI, "http://") && !strings.HasPrefix(redirectURI, "https://") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		escapedURL := html.EscapeString(callbackURL)
		escapedName := html.EscapeString(client.Name)
		escapedCode := html.EscapeString(code.Code)
		jsURL := template.JSEscapeString(callbackURL)
		jsCode := template.JSEscapeString(code.Code)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Authorization Successful</title>
<link href="https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--app-bg:#ffffff;--app-fg:#1e293b;--app-muted:#94a3b8;--app-accent:#34C759;--app-accent-fg:#ffffff;--app-border:#e2e8f0;--app-canvas:#f1f5f9;--app-card:#ffffff;--app-input:#f8fafc;}
@media(prefers-color-scheme:dark){:root{--app-bg:#18181b;--app-fg:#fafafa;--app-muted:#71717a;--app-accent:#34C759;--app-accent-fg:#ffffff;--app-border:#27272a;--app-canvas:#09090b;--app-card:#1e1e22;--app-input:#27272a;}}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Rubik',-apple-system,sans-serif;background:var(--app-canvas);color:var(--app-fg);display:flex;align-items:center;justify-content:center;min-height:100vh;-webkit-font-smoothing:antialiased;}
.card{text-align:center;max-width:420px;width:90%%;padding:40px 32px;background:var(--app-card);border:1px solid var(--app-border);border-radius:16px;}
.check{width:56px;height:56px;border-radius:50%%;background:rgba(52,199,89,0.1);display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px;}
.check svg{color:var(--app-accent);}
h1{font-size:20px;font-weight:600;margin-bottom:8px;letter-spacing:-0.3px;}
h1 strong{color:var(--app-accent);}
.desc{color:var(--app-muted);font-size:14px;line-height:1.5;margin-bottom:28px;}
.desc strong{color:var(--app-fg);}
.open-btn{display:inline-block;padding:12px 32px;background:var(--app-accent);color:var(--app-accent-fg);text-decoration:none;border-radius:10px;font-weight:600;font-size:14px;transition:opacity 0.15s;}
.open-btn:hover{opacity:0.9;}
.copy-section{margin-top:20px;padding-top:20px;border-top:1px solid var(--app-border);}
.copy-label{font-size:11px;color:var(--app-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;}
.copy-row{display:flex;align-items:center;gap:8px;background:var(--app-input);border:1px solid var(--app-border);border-radius:8px;padding:8px 12px;}
.copy-url{flex:1;font-size:12px;color:var(--app-muted);word-break:break-all;text-align:left;font-family:ui-monospace,monospace;}
.copy-btn{background:none;border:1px solid var(--app-border);color:var(--app-muted);padding:6px 12px;border-radius:6px;font-size:11px;cursor:pointer;white-space:nowrap;transition:all 0.15s;}
.copy-btn:hover{border-color:var(--app-accent);color:var(--app-accent);}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(52,199,89,0.3);border-top-color:var(--app-accent);border-radius:50%%;animation:spin 0.8s linear infinite;margin-right:6px;vertical-align:middle;}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:12px;color:var(--app-muted);margin-top:16px;}
</style>
</head><body>
<div class="card">
  <div class="check"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></div>
  <h1>CONSTRUCT:<strong>AUTH</strong></h1>
  <p class="desc">Authorization successful. Redirecting you back to <strong>%s</strong>...</p>
  <a class="open-btn" id="open" href="%s">Open %s</a>
  <div class="status"><span class="spinner"></span>Attempting to open automatically...</div>
  <div class="copy-section">
    <div class="copy-label">If the app didn't open, copy your code</div>
    <div class="copy-row">
      <span class="copy-url" id="authCode">%s</span>
      <button class="copy-btn" onclick="copyCode()">Copy</button>
    </div>
  </div>
</div>
<script>
window.location.href="%s";
var pollCode="%s";
var pollTimer=setInterval(function(){
  fetch('/oauth/code-status?code='+encodeURIComponent(pollCode))
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.used){
        clearInterval(pollTimer);
        var s=document.querySelector('.status');
        s.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--app-accent)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px;"><polyline points="20 6 9 17 4 12"/></svg>Signed in successfully. You may close this tab.';
        var btn=document.getElementById('open');
        btn.textContent='Close';
        btn.href='#';
        btn.onclick=function(e){e.preventDefault();window.close();};
        document.querySelector('.copy-section').style.display='none';
      }
    }).catch(function(){});
},2000);
function copyCode(){
  var c=document.getElementById('authCode').textContent;
  navigator.clipboard.writeText(c).then(function(){
    var btn=document.querySelector('.copy-btn');btn.textContent='Copied!';
    setTimeout(function(){btn.textContent='Copy';},2000);
  });
}
</script>
</body></html>`,
			escapedName,
			escapedURL,
			escapedName,
			escapedCode,
			jsURL,
			jsCode,
		)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, callbackURL, http.StatusFound)
}

// GET /oauth/code-status?code=xxx — check if an auth code has been exchanged
func CodeStatus(w http.ResponseWriter, r *http.Request) {
	codeStr := r.URL.Query().Get("code")
	if codeStr == "" {
		WriteJSON(w, 400, map[string]any{"error": "missing code"})
		return
	}
	var oauthCode models.OAuthCode
	if err := database.DB.Where("code = ?", codeStr).First(&oauthCode).Error; err != nil {
		WriteJSON(w, 404, map[string]any{"used": false})
		return
	}
	WriteJSON(w, 200, map[string]any{"used": oauthCode.Used})
}

func Token(w http.ResponseWriter, r *http.Request) {
	body, err := parseBody(r)
	if err != nil {
		WriteJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}

	grantType := body["grant_type"]
	clientID := body["client_id"]
	clientSecret := body["client_secret"]

	if grantType == "refresh_token" {
		handleRefreshToken(w, body, clientID, clientSecret)
		return
	}

	if grantType != "authorization_code" {
		WriteJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	code := body["code"]
	codeVerifier := body["code_verifier"]
	redirectURI := body["redirect_uri"]

	if code == "" || clientID == "" {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	var client models.OAuthClient
	if err := database.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		WriteJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}

	var oauthCode models.OAuthCode
	if err := database.DB.Where("code = ?", code).First(&oauthCode).Error; err != nil || oauthCode.Used || oauthCode.IsExpired() {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Authorization code is invalid or expired",
		})
		return
	}

	if oauthCode.ClientID != clientID {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Code was not issued to this client",
		})
		return
	}

	if redirectURI != "" && oauthCode.RedirectURI != redirectURI {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "redirect_uri mismatch",
		})
		return
	}

	// PKCE or client_secret
	if oauthCode.CodeChallenge != nil && *oauthCode.CodeChallenge != "" {
		if codeVerifier == "" {
			WriteJSON(w, 400, map[string]any{
				"error":             "invalid_request",
				"error_description": "code_verifier is required for PKCE",
			})
			return
		}
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != *oauthCode.CodeChallenge {
			WriteJSON(w, 400, map[string]any{
				"error":             "invalid_grant",
				"error_description": "code_verifier does not match code_challenge",
			})
			return
		}
	} else {
		if clientSecret == "" || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
			WriteJSON(w, 401, map[string]any{"error": "invalid_client"})
			return
		}
	}

	// Mark code as used
	database.DB.Model(&oauthCode).Update("used", true)

	// Generate tokens
	accessToken := models.AccessToken{
		Token:     models.GenerateAccessToken(),
		ClientID:  clientID,
		UserID:    oauthCode.UserID,
		Scope:     oauthCode.Scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	database.DB.Create(&accessToken)

	refreshToken := models.RefreshToken{
		Token:         models.GenerateRefreshToken(),
		AccessTokenID: &accessToken.ID,
		UserID:        oauthCode.UserID,
		ClientID:      clientID,
		Scope:         oauthCode.Scope,
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
	}
	database.DB.Create(&refreshToken)

	// Cleanup
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.AccessToken{})
	database.DB.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	WriteJSON(w, 200, map[string]any{
		"access_token":  accessToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(accessToken.ExpiresAt).Seconds()),
		"refresh_token": refreshToken.Token,
		"scope":         accessToken.Scope,
	})
}

func handleRefreshToken(w http.ResponseWriter, body map[string]string, clientID, clientSecret string) {
	refreshTokenStr := body["refresh_token"]
	if refreshTokenStr == "" || clientID == "" {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	var client models.OAuthClient
	if err := database.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		WriteJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}
	// Every OAuth client in this service has a secret (column is NOT NULL),
	// so we always require + constant-time compare it. Previous impl
	// skipped the check when the caller omitted the secret, which let a
	// stolen refresh token be exchanged by an unauthenticated caller.
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(client.ClientSecret)) != 1 {
		WriteJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}

	var rt models.RefreshToken
	if err := database.DB.Where("token = ?", refreshTokenStr).First(&rt).Error; err != nil || !rt.IsValid() {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Refresh token is invalid or expired",
		})
		return
	}

	// Bind the refresh to its original client — a stolen token must not
	// be exchangeable under a different client_id. RFC 6749 §10.4.
	if rt.ClientID != clientID {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Refresh token was issued to a different client",
		})
		return
	}

	// Refuse to mint new tokens for suspended users — their old tokens
	// stop working via identityFromHeaders / getLoggedInUser, but without
	// this check they could still refresh into fresh ones.
	var rtUser models.User
	if err := database.DB.First(&rtUser, rt.UserID).Error; err != nil || rtUser.Suspended {
		WriteJSON(w, 400, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Account is suspended",
		})
		return
	}

	// Revoke old
	database.DB.Model(&rt).Update("revoked", true)

	// New tokens
	newAccessToken := models.AccessToken{
		Token:     models.GenerateAccessToken(),
		ClientID:  clientID,
		UserID:    rt.UserID,
		Scope:     rt.Scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	database.DB.Create(&newAccessToken)

	newRefreshToken := models.RefreshToken{
		Token:         models.GenerateRefreshToken(),
		AccessTokenID: &newAccessToken.ID,
		UserID:        rt.UserID,
		ClientID:      clientID,
		Scope:         rt.Scope,
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
	}
	database.DB.Create(&newRefreshToken)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	WriteJSON(w, 200, map[string]any{
		"access_token":  newAccessToken.Token,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(newAccessToken.ExpiresAt).Seconds()),
		"refresh_token": newRefreshToken.Token,
		"scope":         newAccessToken.Scope,
	})
}

func UserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		WriteJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	var token models.AccessToken
	if err := database.DB.Where("token = ?", tokenStr).First(&token).Error; err != nil || !token.IsValid() {
		WriteJSON(w, 401, map[string]any{
			"error":             "invalid_token",
			"error_description": "Token is expired or revoked",
		})
		return
	}

	var user models.User
	if err := database.DB.First(&user, token.UserID).Error; err != nil {
		WriteJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}

	WriteJSON(w, 200, user.ProfileJSON())
}

func Revoke(w http.ResponseWriter, r *http.Request) {
	body, _ := parseBody(r)
	tokenStr := body["token"]
	if tokenStr != "" {
		database.DB.Model(&models.AccessToken{}).Where("token = ?", tokenStr).Update("revoked", true)
	}
	WriteJSON(w, 200, map[string]any{"revoked": true})
}

func getOrigin(uri string) string {
	if idx := strings.Index(uri, "://"); idx >= 0 {
		rest := uri[idx+3:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx >= 0 {
			return uri[:idx+3+slashIdx]
		}
		return uri
	}
	return "*"
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
