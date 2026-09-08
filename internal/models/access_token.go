package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type AccessToken struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Token     string    `gorm:"size:128;uniqueIndex;not null" json:"token"`
	ClientID  string    `gorm:"column:client_id;size:100;not null" json:"client_id"`
	UserID    uint      `gorm:"column:user_id;not null" json:"user_id"`
	Scope     string    `gorm:"size:500;default:'profile email'" json:"scope"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	Revoked   bool      `gorm:"default:false" json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (AccessToken) TableName() string {
	return "access_tokens"
}

func (t *AccessToken) IsValid() bool {
	return !t.Revoked && time.Now().Before(t.ExpiresAt)
}

func GenerateAccessToken() string {
	b := make([]byte, 48)
	rand.Read(b)
	return "cat_" + hex.EncodeToString(b)
}
