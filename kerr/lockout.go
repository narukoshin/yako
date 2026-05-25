package kerr

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"
)

type LockoutState struct {
	Attempts    int
	LastFailure time.Time
	HMAC        []byte
}

const maxConsecutive = 3

var ErrLocked = &Error{
	Code:    "LOCKED",
	Message: "too many failed attempts",
}

func SignLockout(s *LockoutState, key []byte) []byte {
	data := fmt.Sprintf("%d:%d", s.Attempts, s.LastFailure.UnixNano())
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func VerifyLockout(s *LockoutState, key []byte) bool {
	if s == nil {
		return true
	}
	expected := SignLockout(s, key)
	return hmac.Equal(s.HMAC, expected)
}

func lockoutDelay(attempts int) time.Duration {
	if attempts <= maxConsecutive {
		return 0
	}
	n := attempts - maxConsecutive - 1
	d := 10 * time.Minute
	for i := 0; i < n; i++ {
		d *= 2
		if d >= 24*time.Hour {
			return 24 * time.Hour
		}
	}
	return d
}

func formatRemaining(d time.Duration) string {
	if d >= 24*time.Hour {
		h := d.Hours() / 24
		if h == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%.0f days", h)
	}
	if d >= time.Hour {
		h := d.Hours()
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%.0f hours", h)
	}
	m := d.Minutes()
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%.0f minutes", m)
}

func CheckLockout(s *LockoutState) error {
	if s == nil {
		return nil
	}
	if s.Attempts <= maxConsecutive {
		return nil
	}
	elapsed := time.Since(s.LastFailure)
	delay := lockoutDelay(s.Attempts)
	if elapsed < delay {
		remaining := delay - elapsed
		return &Error{
			Code:    "LOCKED",
			Message: fmt.Sprintf("too many failed attempts; try again in %s", formatRemaining(remaining)),
		}
	}
	return nil
}

func RecordFailure(s *LockoutState) {
	if s.Attempts < 255 {
		s.Attempts++
	}
	s.LastFailure = time.Now()
}

func ResetLockout(s *LockoutState) {
	s.Attempts = 0
	s.LastFailure = time.Time{}
}

func LockoutAttempts(s *LockoutState) int {
	if s == nil {
		return 0
	}
	return s.Attempts
}
