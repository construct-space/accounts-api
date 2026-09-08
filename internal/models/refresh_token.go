package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type RefreshToken struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Token         string    `gorm:"size:128;uniqueIndex;not null" json:"token"`
	AccessTokenID *uint     `gorm:"column:access_token_id" json:"access_token_id,omitempty"`
	UserID        uint      `gorm:"column:user_id;not null" json:"user_id"`
	ClientID      string    `gorm:"column:client_id;size:100;not null" json:"client_id"`
	Scope         string    `gorm:"size:500;default:'profile email'" json:"scope"`
	ExpiresAt     time.Time `gorm:"not null" json:"expires_at"`
	Revoked       bool      `gorm:"default:false" json:"revoked"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (t *RefreshToken) IsValid() bool {
	return !t.Revoked && time.Now().Before(t.ExpiresAt)
}

func GenerateRefreshToken() string {
	b := make([]byte, 48)
	rand.Read(b)
	return "crt_" + hex.EncodeToString(b)
}
