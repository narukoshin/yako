package vault

import (
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

const (
	headerFixedLen  = 73
	payloadLenSize  = 4
	recoveryLenSize = 4
)

type recoveryEnvelope struct {
	CodeEnvelope    []byte `json:"c"`
	EntriesEnvelope []byte `json:"d"`
}

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

func Exists() bool {
	_, err := os.Stat(config.VaultPath())
	return err == nil
}

func deriveKey(password []byte, salt []byte) []byte {
	machineKey := config.MachineSecret()
	combined := append(salt, machineKey...)
	return ck.DeriveKey(password, combined)
}

func lockoutBytes(lo *kerr.LockoutState) []byte {
	buf := make([]byte, 41)
	if lo.Attempts > 255 {
		lo.Attempts = 255
	}
	buf[0] = byte(lo.Attempts)
	binary.BigEndian.PutUint64(buf[1:9], uint64(lo.LastFailure.UnixNano()))
	lo.HMAC = kerr.SignLockout(lo, config.MachineSecret())
	copy(buf[9:41], lo.HMAC)
	return buf
}

func buildHeader(mainSalt, recSalt []byte, lo *kerr.LockoutState) []byte {
	buf := make([]byte, headerFixedLen)
	copy(buf[0:16], mainSalt)
	copy(buf[16:32], recSalt)
	copy(buf[32:73], lockoutBytes(lo))
	return buf
}

func parseHeader(data []byte) (mainSalt, recSalt []byte, lo *kerr.LockoutState, err error) {
	if len(data) < headerFixedLen {
		return nil, nil, nil, kerr.ErrCorrupted
	}
	mainSalt = data[0:16]
	recSalt = data[16:32]
	lo = &kerr.LockoutState{
		Attempts:    int(data[32]),
		LastFailure: time.Unix(0, int64(binary.BigEndian.Uint64(data[33:41]))),
		HMAC:        data[41:73],
	}
	if !kerr.VerifyLockout(lo, config.MachineSecret()) {
		return nil, nil, nil, kerr.ErrCorrupted
	}
	return
}

func readVaultFile() ([]byte, error) {
	data, err := os.ReadFile(config.VaultPath())
	if err != nil {
		return nil, kerr.ErrNoVault
	}
	if len(data) < headerFixedLen {
		return nil, kerr.ErrCorrupted
	}
	return data, nil
}

func extractRecoveryPayload(data []byte) (recSalt []byte, payload []byte, err error) {
	if len(data) < headerFixedLen+payloadLenSize {
		return nil, nil, kerr.ErrCorrupted
	}
	recSalt = data[16:32]
	payloadLen := binary.BigEndian.Uint32(data[headerFixedLen : headerFixedLen+payloadLenSize])
	recoveryOffset := headerFixedLen + payloadLenSize + int(payloadLen)
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
		recovery, err = ck.Encrypt(recKey, plaintext)
		if err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
	}

	header := buildHeader(mainSalt, recSalt, &kerr.LockoutState{})

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

func Load(password []byte) ([]Entry, error) {
	return LoadPath(config.VaultPath(), password)
}

func LoadPath(path string, password []byte) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, kerr.ErrNoVault
	}

	mainSalt, _, lo, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	if err := kerr.CheckLockout(lo); err != nil {
		return nil, err
	}

	if len(data) < headerFixedLen+payloadLenSize {
		return nil, kerr.ErrCorrupted
	}
	payloadLen := binary.BigEndian.Uint32(data[headerFixedLen : headerFixedLen+payloadLenSize])
	payloadStart := headerFixedLen + payloadLenSize
	payloadEnd := payloadStart + int(payloadLen)
	if payloadEnd > len(data) {
		return nil, kerr.ErrCorrupted
	}

	key := deriveKey(password, mainSalt)
	plaintext, err := ck.Decrypt(key, data[payloadStart:payloadEnd])
	if err != nil {
		kerr.RecordFailure(lo)
		copy(data[32:73], lockoutBytes(lo))
		writeAtomic(config.VaultPath(), data)
		return nil, kerr.ErrWrongPassword
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

// LoadRecoveryWithCode decrypts the recovery payload using a recovery code.
// Works cross-machine (no machine binding).
func LoadRecoveryWithCode(code string) ([]Entry, error) {
	data, err := readVaultFile()
	if err != nil {
		return nil, err
	}

	recSalt, recoveryPayload, err := extractRecoveryPayload(data)
	if err != nil {
		return nil, err
	}

	var env recoveryEnvelope
	if json.Unmarshal(recoveryPayload, &env) != nil || env.EntriesEnvelope == nil {
		return nil, kerr.ErrWrongPassword
	}

	codeKey := ck.DeriveKey([]byte(code), recSalt)
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

func ResetLockout() error {
	data, err := readVaultFile()
	if err != nil {
		return err
	}
	copy(data[32:73], lockoutBytes(&kerr.LockoutState{}))
	return writeAtomic(config.VaultPath(), data)
}
