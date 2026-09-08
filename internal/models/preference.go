package models

import (
	"encoding/json"
	"time"
)

type Preference struct {
	ID        uint            `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uint            `gorm:"not null;uniqueIndex:idx_user_key" json:"user_id"`
	Key       string          `gorm:"size:255;not null;uniqueIndex:idx_user_key" json:"key"`
	Value     json.RawMessage `gorm:"type:text;not null" json:"value"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}
