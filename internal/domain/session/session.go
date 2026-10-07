package session

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	TokenHash         []byte
	CSRFTokenHash     []byte
	CreatedAt         time.Time
	LastSeenAt        time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevokedReason     *string
}
