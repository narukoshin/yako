package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	ck "github.com/narukoshin/yako/v1/crypto"
)

// UserRole defines the role of a server user (admin or regular user).
type UserRole string

// UserStatus defines whether a user account is active or banned.
type UserStatus string

const (
	// RoleAdmin has full access to all admin endpoints.
	RoleAdmin UserRole = "admin"

	// RoleUser has standard access to their own vault only.
	RoleUser UserRole = "user"

	// StatusActive means the user can log in and use the service.
	StatusActive UserStatus = "active"

	// StatusBanned means the user is locked out. No appeals — I don't forgive twice.
	StatusBanned UserStatus = "banned"
)

// User represents a registered server user with credentials, role, and status.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	Role         UserRole   `json:"role"`
	Status       UserStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
}

// InviteCode is a one-time-use code for user registration. Expires after a set time.
type InviteCode struct {
	Code      string    `json:"code"`
	CreatedBy string    `json:"created_by"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// Store manages all server persistence: users, vaults, invite codes, refresh tokens,
// and blocked token hashes. File-based JSON storage, encrypted at rest when a storage key
// is configured — because even files deserve privacy.
type Store struct {
	Config     *Config
	storageKey []byte
	mu         sync.RWMutex
}

// NewStore creates a Store backed by the given config. Decodes the storage key if present.
func NewStore(cfg *Config) *Store {
	s := &Store{Config: cfg}
	if cfg.StorageKey != "" {
		if key, err := hex.DecodeString(cfg.StorageKey); err == nil {
			s.storageKey = key
		}
	}
	return s
}

// encryptForStorage encrypts data with the storage key, or returns plaintext if no key is set.
func (s *Store) encryptForStorage(plaintext []byte) ([]byte, error) {
	if s.storageKey == nil {
		return plaintext, nil
	}
	return ck.Encrypt(s.storageKey, plaintext)
}

// decryptFromStorage decrypts data with the storage key, or returns it as-is if no key is set.
func (s *Store) decryptFromStorage(ciphertext []byte) ([]byte, error) {
	if s.storageKey == nil {
		return ciphertext, nil
	}
	return ck.Decrypt(s.storageKey, ciphertext)
}

// readFile reads a file from disk and decrypts it transparently.
func (s *Store) readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s.decryptFromStorage(data)
}

// writeFile encrypts data transparently and writes it to disk.
func (s *Store) writeFile(path string, data []byte) error {
	encrypted, err := s.encryptForStorage(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0600)
}

// LoadUsers reads all registered users from disk. Returns nil slice if file doesn't exist.
func (s *Store) LoadUsers() ([]User, error) {
	data, err := s.readFile(s.Config.UsersPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// saveUsers serializes and writes the user list to disk with optional encryption.
func (s *Store) saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.UsersPath(), data)
}

// GetUser looks up a user by their unique ID.
func (s *Store) GetUser(id string) (*User, error) {
	users, err := s.LoadUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID == id {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// FindUser looks up a user by their username.
func (s *Store) FindUser(username string) (*User, error) {
	users, err := s.LoadUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Username == username {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// UpdateUser replaces an existing user's data in the users file.
func (s *Store) UpdateUser(updated *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.LoadUsers()
	if err != nil {
		return err
	}

	for i, u := range users {
		if u.ID == updated.ID {
			users[i] = *updated
			return s.saveUsers(users)
		}
	}
	return fmt.Errorf("user not found")
}

// DeleteUser removes a user by username from the users file.
func (s *Store) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.LoadUsers()
	if err != nil {
		return err
	}

	for i, u := range users {
		if u.Username == username {
			users = append(users[:i], users[i+1:]...)
			return s.saveUsers(users)
		}
	}
	return fmt.Errorf("user not found")
}

// UserCount returns the total number of registered users.
func (s *Store) UserCount() (int, error) {
	users, err := s.LoadUsers()
	if err != nil {
		return 0, err
	}
	return len(users), nil
}

// Register creates a new user account after validating the invite code.
// Password must be at least 8 characters. Username must be unique.
func (s *Store) Register(username, password, inviteCode string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	users, err := s.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	if err := checkUsernameUnique(users, username); err != nil {
		return nil, err
	}

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	if err := consumeInviteCode(codes, inviteCode); err != nil {
		return nil, err
	}

	if err := s.saveInviteCodes(codes); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	user, err := newUser(username, password)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	users = append(users, *user)
	if err := s.saveUsers(users); err != nil {
		return nil, err
	}

	return user, nil
}

// checkUsernameUnique returns an error if the username already exists in the user list.
func checkUsernameUnique(users []User, username string) error {
	for _, u := range users {
		if u.Username == username {
			return fmt.Errorf("username already taken")
		}
	}
	return nil
}

// consumeInviteCode validates and marks an invite code as used. Modifies codes in place.
func consumeInviteCode(codes []InviteCode, code string) error {
	for i, c := range codes {
		if c.Code == code {
			if c.Used {
				return fmt.Errorf("invite code already used")
			}
			if time.Now().UTC().After(c.ExpiresAt) {
				return fmt.Errorf("invite code expired")
			}
			codes[i].Used = true
			return nil
		}
	}
	return fmt.Errorf("invite code not found")
}

// newUser creates a User with a bcrypt-hashed password and a random ID.
func newUser(username, password string) (*User, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}

	return &User{
		ID:           hex.EncodeToString(id),
		Username:     username,
		PasswordHash: hash,
		Role:         RoleUser,
		Status:       StatusActive,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// Authenticate verifies username/password against bcrypt hashes.
// Wrong credentials always return "invalid credentials" — no hints about which was wrong.
func (s *Store) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users, err := s.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	for _, u := range users {
		if u.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err == nil {
				return &u, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		}
	}
	return nil, fmt.Errorf("invalid credentials")
}

// CreateAdmin bootstraps the first admin user. Only works when no users exist.
func (s *Store) CreateAdmin(username, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	if len(users) > 0 {
		return nil, fmt.Errorf("admin already exists")
	}

	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("create admin: %w", err)
	}

	user := &User{
		ID:           hex.EncodeToString(id),
		Username:     username,
		PasswordHash: hash,
		Role:         RoleAdmin,
		Status:       StatusActive,
		CreatedAt:    time.Now().UTC(),
	}

	users = append(users, *user)
	if err := s.saveUsers(users); err != nil {
		return nil, err
	}

	return user, nil
}

// LoadInviteCodes reads all invite codes from disk. Returns nil slice if file doesn't exist.
func (s *Store) LoadInviteCodes() ([]InviteCode, error) {
	data, err := s.readFile(s.Config.invitesPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var codes []InviteCode
	if err := json.Unmarshal(data, &codes); err != nil {
		return nil, err
	}
	return codes, nil
}

// saveInviteCodes serializes and writes the invite code list to disk with encryption.
func (s *Store) saveInviteCodes(codes []InviteCode) error {
	data, err := json.MarshalIndent(codes, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.invitesPath(), data)
}

// CreateInviteCode generates a random invite code with an optional expiry (default 24h, max 168h).
func (s *Store) CreateInviteCode(createdBy string, expiryHours int) (*InviteCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expiryHours <= 0 || expiryHours > 168 {
		expiryHours = 24
	}

	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("create invite: %w", err)
	}

	code := &InviteCode{
		Code:      hex.EncodeToString(codeBytes),
		CreatedBy: createdBy,
		ExpiresAt: time.Now().UTC().Add(time.Duration(expiryHours) * time.Hour),
		Used:      false,
	}

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return nil, err
	}

	codes = append(codes, *code)
	if err := s.saveInviteCodes(codes); err != nil {
		return nil, err
	}

	return code, nil
}

// ValidateInviteCode checks whether an invite code is valid, unexpired, and unused.
func (s *Store) ValidateInviteCode(code string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return fmt.Errorf("invalid invite code")
	}

	for _, c := range codes {
		if c.Code == code {
			if c.Used {
				return fmt.Errorf("invite code already used")
			}
			if time.Now().UTC().After(c.ExpiresAt) {
				return fmt.Errorf("invite code expired")
			}
			return nil
		}
	}
	return fmt.Errorf("invite code not found")
}

// ConsumeInviteCode marks an invite code as used. One-time use — like my patience when you
// forget the password again.
func (s *Store) ConsumeInviteCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return err
	}

	for i, c := range codes {
		if c.Code == code {
			if c.Used {
				return fmt.Errorf("invite code already used")
			}
			codes[i].Used = true
			return s.saveInviteCodes(codes)
		}
	}
	return fmt.Errorf("invite code not found")
}

// DeleteInviteCode removes an invite code from the store.
func (s *Store) DeleteInviteCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return err
	}

	for i, c := range codes {
		if c.Code == code {
			codes = append(codes[:i], codes[i+1:]...)
			return s.saveInviteCodes(codes)
		}
	}
	return fmt.Errorf("invite code not found")
}

// SaveVault writes a user's encrypted vault data to disk.
func (s *Store) SaveVault(userID string, data []byte) error {
	return s.writeFile(s.Config.VaultPath(userID), data)
}

// LoadVault reads a user's encrypted vault data from disk. Returns nil if none exists.
func (s *Store) LoadVault(userID string) ([]byte, error) {
	data, err := s.readFile(s.Config.VaultPath(userID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

// DeleteVault removes a user's vault file from disk. No take-backs.
func (s *Store) DeleteVault(userID string) error {
	return os.Remove(s.Config.VaultPath(userID))
}

// RefreshToken is a long-lived token for obtaining new JWT tokens without re-authentication.
// Stored by SHA256 hash — the raw token is returned to the user and never saved.
type RefreshToken struct {
	Hash      string    `json:"h"`
	UserID    string    `json:"u"`
	ExpiresAt time.Time `json:"e"`
}

// refreshTokensPath returns the path to the refresh tokens file.
func (s *Store) refreshTokensPath() string {
	return filepath.Join(s.Config.DataDir, "refresh_tokens")
}

// LoadRefreshTokens reads all refresh tokens from disk. Returns nil slice if file doesn't exist.
func (s *Store) LoadRefreshTokens() ([]RefreshToken, error) {
	data, err := s.readFile(s.refreshTokensPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var tokens []RefreshToken
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// saveRefreshTokens serializes and writes the refresh token list to disk with encryption.
func (s *Store) saveRefreshTokens(tokens []RefreshToken) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	return s.writeFile(s.refreshTokensPath(), data)
}

// CreateRefreshToken generates a random refresh token (32 bytes, hex-encoded) for a user.
// The token hash is stored; the raw value is returned exactly once — lose it and it's gone.
func (s *Store) CreateRefreshToken(userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("refresh token: %w", err)
	}
	token := hex.EncodeToString(b)
	hash := sha256Hex(token)
	rt := RefreshToken{
		Hash:      hash,
		UserID:    userID,
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tokens, err := s.LoadRefreshTokens()
	if err != nil {
		return "", err
	}
	tokens = append(tokens, rt)
	if err := s.saveRefreshTokens(tokens); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateRefreshToken checks a raw refresh token against stored hashes.
// Returns the user ID if valid and not expired.
func (s *Store) ValidateRefreshToken(token string) (string, error) {
	hash := sha256Hex(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens, err := s.LoadRefreshTokens()
	if err != nil {
		return "", err
	}
	for _, rt := range tokens {
		if rt.Hash == hash {
			if time.Now().UTC().After(rt.ExpiresAt) {
				return "", fmt.Errorf("refresh token expired")
			}
			return rt.UserID, nil
		}
	}
	return "", fmt.Errorf("refresh token not found")
}

// DeleteRefreshToken removes a specific refresh token by its raw value.
func (s *Store) DeleteRefreshToken(token string) error {
	hash := sha256Hex(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	tokens, err := s.LoadRefreshTokens()
	if err != nil {
		return err
	}
	filtered := make([]RefreshToken, 0, len(tokens))
	for _, rt := range tokens {
		if rt.Hash != hash {
			filtered = append(filtered, rt)
		}
	}
	return s.saveRefreshTokens(filtered)
}

// DeleteUserRefreshTokens removes all refresh tokens for a given user. Logout = scorched earth.
func (s *Store) DeleteUserRefreshTokens(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokens, err := s.LoadRefreshTokens()
	if err != nil {
		return err
	}
	filtered := make([]RefreshToken, 0, len(tokens))
	for _, rt := range tokens {
		if rt.UserID != userID {
			filtered = append(filtered, rt)
		}
	}
	return s.saveRefreshTokens(filtered)
}

// sha256Hex returns the lowercase hex-encoded SHA256 hash of a string.
func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// LoadBlockedTokens reads blocked token hashes from disk. Returns nil slice if file doesn't exist.
func (s *Store) LoadBlockedTokens() ([]string, error) {
	data, err := s.readFile(s.Config.BlockedTokensPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var hashes []string
	if err := json.Unmarshal(data, &hashes); err != nil {
		return nil, err
	}
	return hashes, nil
}

// SaveBlockedTokens persists blocked token hashes to disk.
func (s *Store) SaveBlockedTokens(hashes []string) error {
	data, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.BlockedTokensPath(), data)
}

// Destroy wipes all server data except the config file. Nuclear option — use with care,
// or don't use at all. Like my heart.
func (s *Store) Destroy() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.Config.DataDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read data dir: %w", err)
	}
	for _, e := range entries {
		if e.Name() == "config.yml" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", e.Name(), err)
		}
	}
	return nil
}

// hashPassword hashes a password with bcrypt at cost 13. Slow enough to annoy attackers,
//
//	fast enough that you won't notice — like my texting pace.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
