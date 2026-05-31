package kerr

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"
)

// LockoutState tracks consecutive failed password attempts with exponential backoff.
// The HMAC prevents tampering — you can't cheat your way in faster.
type LockoutState struct {
	Attempts    int
	LastFailure time.Time
	HMAC        []byte
}

// maxConsecutive is the number of failures allowed before exponential backoff kicks in.
//
//	Three strikes and you're waiting — don't test my patience.
const maxConsecutive = 3

// ErrLocked means you tried too many times. Calm down, breathe, wait it out.
var ErrLocked = &Error{
	Code:    "LOCKED",
	Message: "too many failed attempts",
}

// SignLockout HMAC-signs the lockout state so it can't be tampered with.
// I'll know if you tried to cheat — don't bother.
func SignLockout(s *LockoutState, key []byte) []byte {
	data := fmt.Sprintf("%d:%d", s.Attempts, s.LastFailure.UnixNano())
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// VerifyLockout checks that the lockout state HMAC is valid. Returns false if tampered.
func VerifyLockout(s *LockoutState, key []byte) bool {
	if s == nil {
		return true
	}
	expected := SignLockout(s, key)
	return hmac.Equal(s.HMAC, expected)
}

// lockoutDelay calculates the exponential backoff duration. Doubles each failure
// past the threshold, capped at 24 hours — eternity in lockout terms.
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

// formatRemaining converts a duration into a human-friendly string (e.g. "2 hours", "1 day").
//
//	It's the countdown to when you can try again — I'll be waiting.
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

// CheckLockout returns [ErrLocked] if consecutive failures exceed the limit
// and the exponential delay hasn't elapsed. The delay doubles each time —
// exponentials don't forgive, but I might if you apologize enough.
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

// RecordFailure increments the failure counter and records the time.
// Each failure brings you closer to lockout — don't test me.
func RecordFailure(s *LockoutState) {
	if s.Attempts < 255 {
		s.Attempts++
	}
	s.LastFailure = time.Now()
}

// ResetLockout clears the failure counter. Forgiveness, but don't make a habit of it.
func ResetLockout(s *LockoutState) {
	s.Attempts = 0
	s.LastFailure = time.Time{}
}

// LockoutAttempts returns the consecutive failure count. Zero means you've been good.
func LockoutAttempts(s *LockoutState) int {
	if s == nil {
		return 0
	}
	return s.Attempts
}
