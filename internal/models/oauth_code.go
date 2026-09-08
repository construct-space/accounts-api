package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type OAuthCode struct {
	ID                  uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Code                string    `gorm:"size:128;uniqueIndex;not null" json:"code"`
	ClientID            string    `gorm:"column:client_id;size:100;not null" json:"client_id"`
	UserID              uint      `gorm:"column:user_id;not null" json:"user_id"`
	RedirectURI         string    `gorm:"column:redirect_uri;type:text;not null" json:"redirect_uri"`
	Scope               string    `gorm:"size:500;default:'profile email'" json:"scope"`
	State               *string   `gorm:"type:text" json:"state,omitempty"`
	CodeChallenge       *string   `gorm:"column:code_challenge;size:256" json:"-"`
	CodeChallengeMethod *string   `gorm:"column:code_challenge_method;size:10" json:"-"`
	ExpiresAt           time.Time `gorm:"not null" json:"expires_at"`
	Used                bool      `gorm:"default:false" json:"used"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (OAuthCode) TableName() string {
	return "oauth_codes"
}

func (c *OAuthCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

func GenerateOAuthCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
