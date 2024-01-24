package refresh

import (
	"fmt"
	"math/rand"
	"time"
)

type RefreshSession struct {
	ID        int
	UserID    int
	Token     string
	ExpiresAt time.Time
}

func NewRefreshToken() (string, error) {
	b := make([]byte, 32)

	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	if _, err := r.Read(b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
