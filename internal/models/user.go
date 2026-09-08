package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID                 uint       `gorm:"primaryKey;autoIncrement" json:"-"`
	UUID               string     `gorm:"size:36;not null;default:''" json:"uuid"`
	FirstName          string     `gorm:"size:255;not null" json:"first_name"`
	LastName           string     `gorm:"size:255;not null" json:"last_name"`
	Username           string     `gorm:"size:255;uniqueIndex;not null" json:"username"`
	Email              string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Password           string     `gorm:"size:255;not null" json:"-"`
	AvatarURL          string     `gorm:"size:2048;not null;default:''" json:"avatar_url,omitempty"`
	Phone              *string    `gorm:"size:255" json:"phone,omitempty"`
	ResetToken         *string    `gorm:"type:text" json:"-"`
	ResetTokenExpiry   *time.Time `json:"-"`
	TOTPSecret         *string    `gorm:"type:text" json:"-"`
	TOTPEnabled        bool       `gorm:"default:false" json:"totp_enabled"`
	Suspended          bool       `gorm:"default:false;index" json:"suspended"`
	SuspendedAt        *time.Time `json:"suspended_at,omitempty"`
	SuspendedReason    string     `gorm:"size:500" json:"suspended_reason,omitempty"`
	MustChangePassword bool       `gorm:"default:false" json:"must_change_password"`
	LastLogin          *time.Time `json:"last_login,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	// developer_status + developer_at columns removed from the model —
	// developer identity lives in the developer service. Columns remain
	// in the DB (GORM AutoMigrate won't drop them) until a manual cleanup
	// migration runs; they're unread and write-only by nothing.
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.UUID == "" {
		u.UUID = GenerateUUID()
	}
	return nil
}

func GenerateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (u *User) Name() string {
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

func (u *User) ProfileJSON() map[string]any {
	return map[string]any{
		"id":         u.UUID,
		"uuid":       u.UUID,
		"name":       u.Name(),
		"first_name": u.FirstName,
		"last_name":  u.LastName,
		"username":   u.Username,
		"email":      u.Email,
		"avatar_url": u.AvatarURL,
	}
}

func HashPassword(plain string) (string, error) {
	if len([]byte(plain)) > 72 {
		return "", fmt.Errorf("password exceeds bcrypt limit")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt failed: %w", err)
	}
	return string(hash), nil
}

func (u *User) CheckPassword(plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plain)) == nil
}

func GenerateResetToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
