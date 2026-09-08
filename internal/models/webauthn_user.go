package models

import (
	"encoding/binary"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser wraps User to satisfy the webauthn.User interface.
type WebAuthnUser struct {
	User        *User
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.User.ID))
	return b
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.User.Name()
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
