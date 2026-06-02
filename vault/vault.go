package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

// Vault binary layout constants. Two header formats (old and new) for backward compatibility.
//
//	Payload and recovery sections are length-prefixed. Verification is HMAC-SHA256 over salt+data.
const (
	oldHeaderFixedLen = 73
	headerFixedLen    = 121
	payloadLenSize    = 4
	recoveryLenSize   = 4
	verifySaltLen     = 16
	verifyHashLen     = 32
)

// headerSize returns the header length based on the vault data length.
//
//	New format (121 bytes) if data is long enough, otherwise old format (73 bytes) for compat.
func headerSize(data []byte) int {
	if len(data) >= headerFixedLen {
		return headerFixedLen
	}
	return oldHeaderFixedLen
}

// recoveryEnvelope wraps the recovery code and encrypted entries in the vault.
//
//	CodeEnvelope is password-encrypted; EntriesEnvelope is code-encrypted — nested trust.
type recoveryEnvelope struct {
	CodeEnvelope    []byte `json:"c"`
	EntriesEnvelope []byte `json:"d"`
}

// writeAtomic writes data to a temp file then atomically renames it to the target path.
//
//	Partial writes won't corrupt your vault — I'm more careful than that.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".vault-")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

// Exists checks whether a default vault file already exists on disk.
func Exists() bool {
	_, err := os.Stat(config.VaultPath())
	return err == nil
}

// deriveKey combines your password with the machine secret via Argon2id.
//
//	The salt is mixed with the machine key — even if someone steals the vault, they can't open
//	it without this machine. You're bound to me whether you like it or not.
func deriveKey(password []byte, salt []byte) []byte {
	machineKey := config.MachineSecret()
	combined := make([]byte, len(salt)+len(machineKey))
	copy(combined, salt)
	copy(combined[len(salt):], machineKey)
	key := ck.DeriveKey(password, combined)
	ck.ZeroBytes(machineKey)
	return key
}

// lockoutBytes serializes a LockoutState (attempts + timestamp + HMAC) into 41 bytes.
//
//	Stored in the vault header so lockout survives restarts — I have a long memory.
func lockoutBytes(lo *kerr.LockoutState) []byte {
	buf := make([]byte, 41)
	if lo.Attempts > 255 {
		lo.Attempts = 255
	}
	buf[0] = byte(lo.Attempts)
	binary.BigEndian.PutUint64(buf[1:9], uint64(lo.LastFailure.UnixNano()))
	ms := config.MachineSecret()
	lo.HMAC = kerr.SignLockout(lo, ms)
	ck.ZeroBytes(ms)
	copy(buf[9:41], lo.HMAC)
	return buf
}

// buildHeader constructs a vault header: salts, lockout state, and optional verification hash.
//
//	Every vault starts with a header — like a promise I intend to keep.
func buildHeader(mainSalt, recSalt []byte, lo *kerr.LockoutState, verifySalt, verifyHash []byte) []byte {
	buf := make([]byte, headerFixedLen)
	copy(buf[0:16], mainSalt)
	copy(buf[16:32], recSalt)
	copy(buf[32:73], lockoutBytes(lo))
	if verifySalt != nil && verifyHash != nil {
		copy(buf[73:89], verifySalt)
		copy(buf[89:121], verifyHash)
	}
	return buf
}

// parseHeader extracts all fields from a vault header: salts, lockout state, and optional
//
//	verification hash. Returns [ErrCorrupted] if the lockout HMAC doesn't verify — try to cheat
//	and you'll get nothing. Just like our relationship if you lie to me.
func parseHeader(data []byte) (mainSalt, recSalt []byte, lo *kerr.LockoutState, verifySalt, verifyHash []byte, err error) {
	if len(data) < oldHeaderFixedLen {
		return nil, nil, nil, nil, nil, kerr.ErrCorrupted
	}
	mainSalt = data[0:16]
	recSalt = data[16:32]
	lo = &kerr.LockoutState{
		Attempts:    int(data[32]),
		LastFailure: time.Unix(0, int64(binary.BigEndian.Uint64(data[33:41]))),
		HMAC:        data[41:73],
	}
	ms := config.MachineSecret()
	ok := kerr.VerifyLockout(lo, ms)
	ck.ZeroBytes(ms)
	if !ok {
		return nil, nil, nil, nil, nil, kerr.ErrCorrupted
	}
	if len(data) >= headerFixedLen {
		verifySalt = data[73:89]
		verifyHash = data[89:121]
	}
	return
}

// readVaultFile reads the default vault file from disk and checks minimum size.
//
//	Missing or truncated vaults get [ErrNoVault] or [ErrCorrupted] — no second chances.
func readVaultFile() ([]byte, error) {
	data, err := os.ReadFile(config.VaultPath())
	if err != nil {
		return nil, kerr.ErrNoVault
	}
	if len(data) < oldHeaderFixedLen {
		return nil, kerr.ErrCorrupted
	}
	return data, nil
}

// extractRecoveryPayload locates and extracts the recovery section from raw vault data.
//
//	Returns the recovery salt and the encrypted recovery payload.
func extractRecoveryPayload(data []byte) (recSalt []byte, payload []byte, err error) {
	hs := headerSize(data)
	if len(data) < hs+payloadLenSize {
		return nil, nil, kerr.ErrCorrupted
	}
	recSalt = data[16:32]
	payloadLen := binary.BigEndian.Uint32(data[hs : hs+payloadLenSize])
	recoveryOffset := hs + payloadLenSize + int(payloadLen)
	if recoveryOffset+recoveryLenSize > len(data) {
		return nil, nil, kerr.ErrCorrupted
	}
	recoveryLen := binary.BigEndian.Uint32(data[recoveryOffset : recoveryOffset+recoveryLenSize])
	if recoveryLen == 0 {
		return nil, nil, kerr.ErrCorrupted
	}
	recoveryStart := recoveryOffset + recoveryLenSize
	recoveryEnd := recoveryStart + int(recoveryLen)
	if recoveryEnd > len(data) {
		return nil, nil, kerr.ErrCorrupted
	}
	return recSalt, data[recoveryStart:recoveryEnd], nil
}

// extractCodeFromVault decrypts the recovery code from the vault using your password.
//
//	Returns an error if no recovery envelope is present or the password is wrong.
func extractCodeFromVault(password []byte) (string, error) {
	data, err := readVaultFile()
	if err != nil {
		return "", err
	}

	recSalt, recoveryPayload, err := extractRecoveryPayload(data)
	if err != nil {
		return "", err
	}

	var env recoveryEnvelope
	if json.Unmarshal(recoveryPayload, &env) != nil || env.CodeEnvelope == nil {
		return "", fmt.Errorf("no recovery code in vault")
	}

	passwordKey := ck.DeriveKey(password, recSalt)
	defer ck.ZeroBytes(passwordKey)
	codeBytes, err := ck.Decrypt(passwordKey, env.CodeEnvelope)
	if err != nil {
		return "", kerr.ErrWrongPassword
	}
	return string(codeBytes), nil
}

// Init creates a vault without a recovery code (old format, backward compatible).
func Init(password []byte) error {
	if Exists() {
		return kerr.ErrVaultExists
	}
	return saveWith(password, []Entry{}, "")
}

// InitWithRecovery creates a vault with a recovery code. The code is encrypted
// inside the vault with the master password — never stored on disk.
func InitWithRecovery(password []byte) (string, error) {
	if Exists() {
		return "", kerr.ErrVaultExists
	}

	code, err := GenerateRecoveryPhrase()
	if err != nil {
		return "", fmt.Errorf("init vault: %w", err)
	}

	if err := saveWith(password, []Entry{}, code); err != nil {
		return "", err
	}

	return code, nil
}

// Save re-encrypts the vault. If the existing vault has a recovery code,
// it is extracted and the recovery payload stays current.
func Save(password []byte, entries []Entry) error {
	code, err := extractCodeFromVault(password)
	if err != nil {
		return saveWith(password, entries, "")
	}
	return saveWith(password, entries, code)
}

// saveWith encrypts entries and writes the vault atomically. If code is non-empty, a recovery
//
//	envelope is embedded (password-encrypted code + code-encrypted entries).
func saveWith(password []byte, entries []Entry, code string) error {
	mainSalt, err := ck.GenerateSalt()
	if err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	recSalt, err := ck.GenerateSalt()
	if err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	key := deriveKey(password, mainSalt)
	defer ck.ZeroBytes(key)

	plaintext, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	payload, err := ck.Encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("save vault: %w", err)
	}

	var recovery []byte
	if code != "" {
		passwordKey := ck.DeriveKey(password, recSalt)
		codeKey := ck.DeriveKey([]byte(code), recSalt)
		defer ck.ZeroBytes(passwordKey)
		defer ck.ZeroBytes(codeKey)

		codeEnvelope, err := ck.Encrypt(passwordKey, []byte(code))
		if err != nil {
			return fmt.Errorf("save vault: %w", err)
		}

		entriesEnvelope, err := ck.Encrypt(codeKey, plaintext)
		if err != nil {
			return fmt.Errorf("save vault: %w", err)
		}

		env := recoveryEnvelope{
			CodeEnvelope:    codeEnvelope,
			EntriesEnvelope: entriesEnvelope,
		}
		recovery, err = json.Marshal(env)
		if err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
	} else {
		recKey := ck.DeriveKey(password, recSalt)
		defer ck.ZeroBytes(recKey)
		recovery, err = ck.Encrypt(recKey, plaintext)
		if err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
	}

	verifySalt, err := ck.GenerateSalt()
	if err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	verifyKey := deriveKey(password, verifySalt)
	defer ck.ZeroBytes(verifyKey)
	mac := hmac.New(sha256.New, verifyKey)
	mac.Write(verifySalt)
	mac.Write(plaintext)
	verifyHash := mac.Sum(nil)

	header := buildHeader(mainSalt, recSalt, &kerr.LockoutState{}, verifySalt, verifyHash)

	buf := make([]byte, 0, headerFixedLen+payloadLenSize+len(payload)+recoveryLenSize+len(recovery))
	buf = append(buf, header...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(recovery)))
	buf = append(buf, recovery...)

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	return writeAtomic(config.VaultPath(), buf)
}

// Load opens the default vault with your password and returns every entry.
// Wrong password? [ErrWrongPassword]. No vault? [ErrNoVault].
func Load(password []byte) ([]Entry, error) {
	return LoadPath(config.VaultPath(), password)
}

// LoadPath is like [Load] but reads from a specific file instead of the default vault.
func LoadPath(path string, password []byte) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, kerr.ErrNoVault
	}

	mainSalt, _, lo, verifySalt, verifyHash, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	if err := kerr.CheckLockout(lo); err != nil {
		return nil, err
	}

	hs := headerSize(data)
	if len(data) < hs+payloadLenSize {
		return nil, kerr.ErrCorrupted
	}
	payloadLen := binary.BigEndian.Uint32(data[hs : hs+payloadLenSize])
	payloadStart := hs + payloadLenSize
	payloadEnd := payloadStart + int(payloadLen)
	if payloadEnd > len(data) {
		return nil, kerr.ErrCorrupted
	}

	key := deriveKey(password, mainSalt)
	defer ck.ZeroBytes(key)
	plaintext, err := ck.Decrypt(key, data[payloadStart:payloadEnd])
	if err != nil {
		kerr.RecordFailure(lo)
		copy(data[32:73], lockoutBytes(lo))
		writeAtomic(config.VaultPath(), data)
		return nil, kerr.ErrWrongPassword
	}

	if verifySalt != nil && verifyHash != nil {
		verifyKey := deriveKey(password, verifySalt)
		mac := hmac.New(sha256.New, verifyKey)
		mac.Write(verifySalt)
		mac.Write(plaintext)
		ok := hmac.Equal(mac.Sum(nil), verifyHash)
		ck.ZeroBytes(verifyKey)
		if !ok {
			// Fall back to old-format HMAC (raw password) for backward compat
			mac2 := hmac.New(sha256.New, password)
			mac2.Write(verifySalt)
			mac2.Write(plaintext)
			if !hmac.Equal(mac2.Sum(nil), verifyHash) {
				return nil, kerr.ErrCorrupted
			}
		}
	}

	kerr.ResetLockout(lo)
	copy(data[32:73], lockoutBytes(lo))
	writeAtomic(config.VaultPath(), data)

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, kerr.ErrCorrupted
	}
	return entries, nil
}

// LoadRecoveryWithCodeData decrypts the given vault data using a recovery code.
// Works cross-machine (no machine binding).
func LoadRecoveryWithCodeData(data []byte, code string) ([]Entry, error) {
	recSalt, recoveryPayload, err := extractRecoveryPayload(data)
	if err != nil {
		return nil, err
	}

	var env recoveryEnvelope
	if json.Unmarshal(recoveryPayload, &env) != nil || env.EntriesEnvelope == nil {
		return nil, kerr.ErrWrongPassword
	}

	codeKey := ck.DeriveKey([]byte(code), recSalt)
	defer ck.ZeroBytes(codeKey)
	plaintext, err := ck.Decrypt(codeKey, env.EntriesEnvelope)
	if err != nil {
		return nil, kerr.ErrWrongPassword
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, kerr.ErrCorrupted
	}
	return entries, nil
}

// LoadRecoveryWithCode decrypts the local vault file using a recovery code.
// Works cross-machine (no machine binding).
func LoadRecoveryWithCode(code string) ([]Entry, error) {
	data, err := readVaultFile()
	if err != nil {
		return nil, err
	}
	return LoadRecoveryWithCodeData(data, code)
}

// RegenerateRecovery creates a new recovery phrase for the vault, replacing the old one.
// Loads entries with the current password, generates a fresh phrase, re-saves.
func RegenerateRecovery(password []byte) (string, error) {
	if !Exists() {
		return "", kerr.ErrNoVault
	}
	entries, err := Load(password)
	if err != nil {
		return "", err
	}
	code, err := GenerateRecoveryPhrase()
	if err != nil {
		return "", err
	}
	if err := saveWith(password, entries, code); err != nil {
		return "", err
	}
	return code, nil
}

// MergeEntries merges a local vault with a remote one for sync.
// Server entries overwrite local ones by name. Local-only entries are preserved.
// No duplicates — I don't share.
func MergeEntries(local, server []Entry) []Entry {
	merged := make([]Entry, len(server))
	copy(merged, server)
	for _, le := range local {
		found := false
		for i, se := range server {
			if se.Name == le.Name {
				found = true
				if le.Updated > se.Updated {
					merged[i] = le
				}
				break
			}
		}
		if !found {
			merged = append(merged, le)
		}
	}
	return merged
}

// ResetLockout clears the lockout state in the vault file. Call this when you've been good.
func ResetLockout() error {
	data, err := readVaultFile()
	if err != nil {
		return err
	}
	copy(data[32:73], lockoutBytes(&kerr.LockoutState{}))
	return writeAtomic(config.VaultPath(), data)
}
