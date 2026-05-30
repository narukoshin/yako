package kerr

import (
	"errors"
	"testing"
	"time"
)

func TestCheckLockoutFresh(t *testing.T) {
	s := &LockoutState{}
	if err := CheckLockout(s); err != nil {
		t.Fatalf("fresh state should not be locked: %v", err)
	}
}

func TestCheckLockoutNil(t *testing.T) {
	if err := CheckLockout(nil); err != nil {
		t.Fatalf("nil should not be locked: %v", err)
	}
}

func TestRecordAndCheck(t *testing.T) {
	s := &LockoutState{}

	for i := 0; i < 3; i++ {
		if err := CheckLockout(s); err != nil {
			t.Fatalf("attempt %d should not be locked: %v", i+1, err)
		}
		RecordFailure(s)
	}

	if err := CheckLockout(s); err != nil {
		t.Fatalf("3 failures should not trigger lockout: %v", err)
	}

	RecordFailure(s)

	if err := CheckLockout(s); err == nil {
		t.Fatal("4th failure should trigger lockout delay")
	} else {
		var ke *Error
		if !errors.As(err, &ke) || ke.Code != "LOCKED" {
			t.Fatalf("expected LOCKED error, got %v", err)
		}
	}
}

func TestResetLockout(t *testing.T) {
	s := &LockoutState{}
	for i := 0; i < 5; i++ {
		RecordFailure(s)
	}
	if err := CheckLockout(s); err == nil {
		t.Fatal("expected lockout after 5 failures")
	}
	ResetLockout(s)
	if err := CheckLockout(s); err != nil {
		t.Fatalf("after reset should not be locked: %v", err)
	}
}

func TestLockoutAttempts(t *testing.T) {
	s := &LockoutState{}
	for i := 0; i < 5; i++ {
		RecordFailure(s)
	}
	if LockoutAttempts(s) != 5 {
		t.Fatalf("expected 5 attempts, got %d", LockoutAttempts(s))
	}
	ResetLockout(s)
	if LockoutAttempts(s) != 0 {
		t.Fatalf("expected 0 after reset, got %d", LockoutAttempts(s))
	}
}

func TestSignAndVerify(t *testing.T) {
	key1 := []byte("test-key-12345678")
	key2 := []byte("different-key-12345")
	s := &LockoutState{Attempts: 3, LastFailure: time.Now()}
	s.HMAC = SignLockout(s, key1)

	if !VerifyLockout(s, key1) {
		t.Fatal("valid signature should verify")
	}

	if VerifyLockout(s, key2) {
		t.Fatal("wrong key should not verify")
	}

	s.Attempts = 99
	if VerifyLockout(s, key1) {
		t.Fatal("tampered state should not verify")
	}
}

func TestNilVerify(t *testing.T) {
	if !VerifyLockout(nil, []byte("key")) {
		t.Fatal("nil should verify as true")
	}
}

func TestMaxConsecutiveAllowed(t *testing.T) {
	s := &LockoutState{}
	for i := 0; i < 3; i++ {
		if err := CheckLockout(s); err != nil {
			t.Fatalf("attempt %d should pass: %v", i+1, err)
		}
		RecordFailure(s)
	}
	if err := CheckLockout(s); err != nil {
		t.Fatal("3 attempts exactly should not lock")
	}
	RecordFailure(s)
	if err := CheckLockout(s); err == nil {
		t.Fatal("4 attempts should lock")
	}
}

func TestCapAt255(t *testing.T) {
	s := &LockoutState{}
	for i := 0; i < 300; i++ {
		RecordFailure(s)
	}
	if s.Attempts > 255 {
		t.Fatalf("attempts should be capped at 255, got %d", s.Attempts)
	}
}

func TestLockoutDelayExponential(t *testing.T) {
	tests := []struct {
		attempts int
		minDelay time.Duration
	}{
		{3, 0},
		{4, 10 * time.Minute},
		{5, 20 * time.Minute},
		{6, 40 * time.Minute},
		{100, 24 * time.Hour},
	}
	for _, tt := range tests {
		got := lockoutDelay(tt.attempts)
		if got != tt.minDelay {
			t.Errorf("lockoutDelay(%d) = %v, want %v", tt.attempts, got, tt.minDelay)
		}
	}
}
