package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type OAuthClient struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	ClientID     string    `gorm:"column:client_id;size:100;uniqueIndex;not null" json:"client_id"`
	ClientSecret string    `gorm:"column:client_secret;size:255;not null" json:"-"`
	Name         string    `gorm:"size:200;not null" json:"name"`
	RedirectURI  string    `gorm:"column:redirect_uri;type:text;not null" json:"redirect_uri"`
	Description  *string   `gorm:"type:text" json:"description,omitempty"`
	LogoURL      *string   `gorm:"column:logo_url;type:text" json:"logo_url,omitempty"`
	Active       bool      `gorm:"default:true" json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}

func GenerateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "csk_" + hex.EncodeToString(b)
}
