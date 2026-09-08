package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type Session struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Token     string    `gorm:"size:128;uniqueIndex;not null" json:"-"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	UserAgent *string   `gorm:"type:text" json:"user_agent,omitempty"`
	IPAddress *string   `gorm:"size:255" json:"ip_address,omitempty"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func GenerateSessionToken() string {
	b := make([]byte, 48)
	rand.Read(b)
	return hex.EncodeToString(b)
}
