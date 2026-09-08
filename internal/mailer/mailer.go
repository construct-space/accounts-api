package mailer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"construct/accounts/internal/config"
)

type emailRequest struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
	Layout  string `json:"layout,omitempty"`
}

func send(cfg *config.Config, to, subject, html, text string) error {
	if cfg.DeliveryURL == "" || cfg.DeliveryAPIKey == "" {
		log.Printf("[DEV] Email to %s: %s", to, subject)
		return nil
	}

	payload := emailRequest{
		From:    cfg.EmailFrom,
		To:      to,
		Subject: subject,
		HTML:    html,
		Text:    text,
		// renderEmail() already wraps the body in the accounts layout —
		// tell delivery to skip its own "construct" layout, otherwise
		// the recipient sees a card-in-card with two headers and two
		// footers. Delivery's field is `layout` (not `template`).
		Layout: "none",
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", cfg.DeliveryURL+"/api/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeliveryAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("delivery API returned %d", resp.StatusCode)
	}

	log.Printf("[email] Sent '%s' to %s", subject, to)
	return nil
}

// --- Password Reset ---

func SendResetEmail(cfg *config.Config, to, token string) error {
	resetURL := cfg.AppURL + "/reset-password?token=" + token

	html := renderEmail(
		"Reset your password",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			We received a request to reset your password.
		</p>`+
			button(resetURL, "Reset Password")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
		</p>`,
	)

	text := fmt.Sprintf("Reset your Construct password\n\nWe received a request to reset your password.\n\nReset your password: %s\n\nThis link expires in 1 hour. If you didn't request this, you can safely ignore this email.", resetURL)

	return send(cfg, to, "Reset your Construct password", html, text)
}

// --- Welcome ---

func SendWelcomeEmail(cfg *config.Config, to, name string) error {
	greeting := "Your account is ready"
	if name != "" {
		greeting = name + ", your account is ready"
	}

	html := renderEmail(
		greeting,
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			Thanks for signing up for Construct. Your account has been created and you can now sign in to access your dashboard, projects, and all platform services.
		</p>`+
			button(cfg.AppURL, "Go to your account")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't create this account, you can safely ignore this email or contact our support team.
		</p>`,
	)

	text := fmt.Sprintf("%s\n\nThanks for signing up for Construct. Your account has been created and you can now sign in to access your dashboard, projects, and all platform services.\n\nGo to your account: %s\n\nIf you didn't create this account, you can safely ignore this email.", greeting, cfg.AppURL)

	return send(cfg, to, greeting+" &#8212; Construct", html, text)
}

// --- Email Verification ---

func SendVerificationEmail(cfg *config.Config, to, token string) error {
	verifyURL := cfg.AppURL + "/verify-email?token=" + token

	html := renderEmail(
		"Verify your email",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			Please verify your email address to complete your account setup.
		</p>`+
			button(verifyURL, "Verify Email")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			This link expires in 24 hours. If you didn't create a Construct account, you can safely ignore this email.
		</p>`,
	)

	text := fmt.Sprintf("Verify your email\n\nPlease verify your email address to complete your account setup.\n\nVerify: %s\n\nThis link expires in 24 hours.", verifyURL)

	return send(cfg, to, "Verify your Construct email", html, text)
}

// --- Login from New Device ---

func SendNewLoginEmail(cfg *config.Config, to, device, location, ipAddress string) error {
	html := renderEmail(
		"New sign-in to your account",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			We detected a new sign-in to your Construct account.
		</p>
		<table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 24px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px">
			<tr><td style="padding:16px 20px">
				<table cellpadding="0" cellspacing="0" border="0" width="100%">
					<tr><td style="padding:4px 0;color:#6b7280;font-size:13px;font-family:Rubik,-apple-system,sans-serif">Device</td>
						<td style="padding:4px 0;color:#111827;font-size:13px;font-family:Rubik,-apple-system,sans-serif" align="right">`+device+`</td></tr>
					<tr><td style="padding:4px 0;color:#6b7280;font-size:13px;font-family:Rubik,-apple-system,sans-serif">Location</td>
						<td style="padding:4px 0;color:#111827;font-size:13px;font-family:Rubik,-apple-system,sans-serif" align="right">`+location+`</td></tr>
					<tr><td style="padding:4px 0;color:#6b7280;font-size:13px;font-family:Rubik,-apple-system,sans-serif">IP Address</td>
						<td style="padding:4px 0;color:#111827;font-size:13px;font-family:Rubik,-apple-system,sans-serif" align="right">`+ipAddress+`</td></tr>
				</table>
			</td></tr>
		</table>
		<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If this was you, no action is needed. If you don't recognize this activity, please <a href="`+cfg.AppURL+`/security" style="color:#FF2D55;text-decoration:none">secure your account</a> immediately.
		</p>`,
	)

	text := fmt.Sprintf("New sign-in to your Construct account\n\nDevice: %s\nLocation: %s\nIP Address: %s\n\nIf this was you, no action is needed. If you don't recognize this activity, secure your account: %s/security", device, location, ipAddress, cfg.AppURL)

	return send(cfg, to, "New sign-in to your Construct account", html, text)
}

// --- Password Changed ---

func SendPasswordChangedEmail(cfg *config.Config, to string) error {
	html := renderEmail(
		"Password changed",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			Your Construct account password was successfully changed.
		</p>
		<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't make this change, please <a href="`+cfg.AppURL+`/forgot-password" style="color:#FF2D55;text-decoration:none">reset your password</a> immediately and review your account security.
		</p>`,
	)

	text := fmt.Sprintf("Password changed\n\nYour Construct account password was successfully changed.\n\nIf you didn't make this change, reset your password immediately: %s/forgot-password", cfg.AppURL)

	return send(cfg, to, "Your Construct password was changed", html, text)
}

// --- Two-Factor Authentication ---

func SendTwoFactorEnabledEmail(cfg *config.Config, to string) error {
	html := renderEmail(
		"Two-factor authentication enabled",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			Two-factor authentication has been enabled on your Construct account. You'll be asked for a verification code each time you sign in.
		</p>
		<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			Make sure to keep your recovery codes in a safe place. If you didn't make this change, please <a href="`+cfg.AppURL+`/security" style="color:#FF2D55;text-decoration:none">secure your account</a> immediately.
		</p>`,
	)

	text := fmt.Sprintf("Two-factor authentication enabled\n\nTwo-factor authentication has been enabled on your Construct account.\n\nMake sure to keep your recovery codes in a safe place. If you didn't make this change, secure your account: %s/security", cfg.AppURL)

	return send(cfg, to, "Two-factor authentication enabled", html, text)
}

func SendTwoFactorDisabledEmail(cfg *config.Config, to string) error {
	html := renderEmail(
		"Two-factor authentication disabled",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			Two-factor authentication has been removed from your Construct account. Your account is now less secure.
		</p>`+
			button(cfg.AppURL+"/security", "Review Security Settings")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't make this change, please re-enable two-factor authentication and change your password immediately.
		</p>`,
	)

	text := fmt.Sprintf("Two-factor authentication disabled\n\nTwo-factor authentication has been removed from your Construct account.\n\nReview your security settings: %s/security", cfg.AppURL)

	return send(cfg, to, "Two-factor authentication disabled", html, text)
}

// --- Invite ---

func SendInviteEmail(cfg *config.Config, to, inviterName, teamName, token string) error {
	inviteURL := cfg.AppURL + "/invite?token=" + token

	html := renderEmail(
		"You've been invited",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			<strong>`+inviterName+`</strong> invited you to join <strong>`+teamName+`</strong> on Construct.
		</p>`+
			button(inviteURL, "Accept Invite")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			This invitation expires in 7 days. If you don't want to join, you can safely ignore this email.
		</p>`,
	)

	text := fmt.Sprintf("%s invited you to join %s on Construct.\n\nAccept invite: %s\n\nThis invitation expires in 7 days.", inviterName, teamName, inviteURL)

	return send(cfg, to, inviterName+" invited you to "+teamName, html, text)
}

// --- OAuth App Authorized ---

func SendOAuthAuthorizedEmail(cfg *config.Config, to, appName string) error {
	html := renderEmail(
		"App connected to your account",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			<strong>`+appName+`</strong> was granted access to your Construct account.
		</p>`+
			button(cfg.AppURL+"/services", "Manage Connected Apps")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't authorize this app, revoke its access immediately from your account settings.
		</p>`,
	)

	text := fmt.Sprintf("%s was granted access to your Construct account.\n\nManage connected apps: %s/services\n\nIf you didn't authorize this app, revoke its access immediately.", appName, cfg.AppURL)

	return send(cfg, to, appName+" connected to your Construct account", html, text)
}

// --- Passkey Added ---

func SendPasskeyAddedEmail(cfg *config.Config, to, passkeyName string) error {
	html := renderEmail(
		"Passkey added to your account",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			A new passkey <strong>`+passkeyName+`</strong> was added to your Construct account. You can now use it to sign in without a password.
		</p>`+
			button(cfg.AppURL+"/security/passkeys", "Manage Passkeys")+
			`<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't add this passkey, please <a href="`+cfg.AppURL+`/security" style="color:#FF2D55;text-decoration:none">secure your account</a> immediately.
		</p>`,
	)

	text := fmt.Sprintf("Passkey added to your account\n\nA new passkey \"%s\" was added to your Construct account.\n\nManage passkeys: %s/security/passkeys\n\nIf you didn't add this passkey, secure your account immediately.", passkeyName, cfg.AppURL)

	return send(cfg, to, "Passkey added to your Construct account", html, text)
}

// --- Passkey Removed ---

func SendPasskeyRemovedEmail(cfg *config.Config, to, passkeyName string) error {
	html := renderEmail(
		"Passkey removed from your account",
		`<p style="margin:0 0 24px;color:#374151;font-size:15px;line-height:1.6">
			The passkey <strong>`+passkeyName+`</strong> was removed from your Construct account.
		</p>
		<p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.6">
			If you didn't remove this passkey, please <a href="`+cfg.AppURL+`/security" style="color:#FF2D55;text-decoration:none">secure your account</a> immediately.
		</p>`,
	)

	text := fmt.Sprintf("Passkey removed from your account\n\nThe passkey \"%s\" was removed from your Construct account.\n\nIf you didn't remove this passkey, secure your account: %s/security", passkeyName, cfg.AppURL)

	return send(cfg, to, "Passkey removed from your Construct account", html, text)
}

// --- Template helpers ---

func button(url, label string) string {
	return `<table cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
		<tr><td style="border-radius:10px;background:#FF2D55" align="center">
			<a href="` + url + `" target="_blank" style="display:inline-block;padding:14px 40px;color:#ffffff;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;font-weight:600;text-decoration:none;text-transform:uppercase;letter-spacing:1px">` + label + `</a>
		</td></tr>
	</table>`
}

const logoURL = "https://lisaos.dev/accounts.png"

func renderEmail(title, content string) string {
	return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<meta name="color-scheme" content="light"/>
<meta name="supported-color-schemes" content="light"/>
<title>` + title + `</title>
<!--[if !mso]><!-->
<link href="https://fonts.googleapis.com/css2?family=Rubik:wght@400;500;600&display=swap" rel="stylesheet"/>
<!--<![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f3f4f6;-webkit-font-smoothing:antialiased;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">

<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f3f4f6">
<tr><td align="center" style="padding:48px 16px">

<table width="520" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;width:100%">

<!-- Logo -->
<tr><td style="padding:0 0 24px">
	<img src="` + logoURL + `" alt="Construct Accounts" width="180" height="52" style="display:block;border:0;outline:none"/>
</td></tr>

<!-- Card -->
<tr><td style="background-color:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
<table width="100%" cellpadding="0" cellspacing="0" border="0">

<tr><td style="padding:40px 40px 0">
	<h1 style="margin:0 0 24px;font-size:24px;font-weight:600;color:#111827;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">` + title + `</h1>
</td></tr>

<tr><td style="padding:0 40px 40px">
	` + content + `
</td></tr>

</table>
</td></tr>

<!-- Footer -->
<tr><td style="padding:28px 0 0" align="center">
	<p style="margin:0 0 8px;font-size:12px;color:#9ca3af;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.5">
		This email was sent to the address associated with your Construct account.<br/>
		This is an automated message — please do not reply. Need help? Visit <a href="https://lisaos.dev/support" style="color:#9ca3af;text-decoration:underline">Construct Support</a>.
	</p>
	<p style="margin:0;font-size:12px;color:#d1d5db;font-family:Rubik,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
		<a href="https://lisaos.dev" style="color:#d1d5db;text-decoration:none">lisaos.dev</a>
	</p>
</td></tr>

</table>

</td></tr>
</table>

</body>
</html>`
}
