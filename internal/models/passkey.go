package models

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Passkey struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID         uint      `gorm:"not null;index" json:"user_id"`
	Name           string    `gorm:"size:255;not null" json:"name"`
	CredentialID   []byte    `gorm:"type:varbinary(1024);not null;uniqueIndex:idx_cred_id,length:255" json:"-"`
	PublicKey      []byte    `gorm:"type:blob;not null" json:"-"`
	AAGUID         []byte    `gorm:"type:varbinary(36)" json:"-"`
	SignCount      uint32    `gorm:"default:0" json:"-"`
	BackupEligible bool      `gorm:"default:false" json:"-"`
	BackupState    bool      `gorm:"default:false" json:"-"`
	CreatedAt      time.Time `json:"created_at"`
}

func (p *Passkey) ToCredential() webauthn.Credential {
	return webauthn.Credential{
		ID:              p.CredentialID,
		PublicKey:       p.PublicKey,
		AttestationType: "none",
		Flags: webauthn.CredentialFlags{
			BackupEligible: p.BackupEligible,
			BackupState:    p.BackupState,
			UserPresent:    true,
			UserVerified:   true,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    p.AAGUID,
			SignCount: p.SignCount,
		},
	}
}
