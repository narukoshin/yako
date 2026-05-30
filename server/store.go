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

type UserRole string
type UserStatus string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"

	StatusActive UserStatus = "active"
	StatusBanned UserStatus = "banned"
)

type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	Role         UserRole   `json:"role"`
	Status       UserStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
}

type InviteCode struct {
	Code      string    `json:"code"`
	CreatedBy string    `json:"created_by"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type Store struct {
	Config     *Config
	storageKey []byte
	mu         sync.RWMutex
}

func NewStore(cfg *Config) *Store {
	s := &Store{Config: cfg}
	if cfg.StorageKey != "" {
		if key, err := hex.DecodeString(cfg.StorageKey); err == nil {
			s.storageKey = key
		}
	}
	return s
}

func (s *Store) encryptForStorage(plaintext []byte) ([]byte, error) {
	if s.storageKey == nil {
		return plaintext, nil
	}
	return ck.Encrypt(s.storageKey, plaintext)
}

func (s *Store) decryptFromStorage(ciphertext []byte) ([]byte, error) {
	if s.storageKey == nil {
		return ciphertext, nil
	}
	return ck.Decrypt(s.storageKey, ciphertext)
}

func (s *Store) readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s.decryptFromStorage(data)
}

func (s *Store) writeFile(path string, data []byte) error {
	encrypted, err := s.encryptForStorage(data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0600)
}

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

func (s *Store) saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.UsersPath(), data)
}

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

func (s *Store) UserCount() (int, error) {
	users, err := s.LoadUsers()
	if err != nil {
		return 0, err
	}
	return len(users), nil
}

func (s *Store) Register(username, password, inviteCode string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	user := &User{
		ID:           hex.EncodeToString(id),
		Username:     username,
		PasswordHash: hash,
		Role:         RoleUser,
		Status:       StatusActive,
		CreatedAt:    time.Now().UTC(),
	}

	users, err := s.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	for _, u := range users {
		if u.Username == username {
			return nil, fmt.Errorf("username already taken")
		}
	}

	codes, err := s.LoadInviteCodes()
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	var consumed bool
	for i, c := range codes {
		if c.Code == inviteCode {
			if c.Used {
				return nil, fmt.Errorf("invite code already used")
			}
			if time.Now().UTC().After(c.ExpiresAt) {
				return nil, fmt.Errorf("invite code expired")
			}
			codes[i].Used = true
			if err := s.saveInviteCodes(codes); err != nil {
				return nil, fmt.Errorf("register: %w", err)
			}
			consumed = true
			break
		}
	}
	if !consumed {
		return nil, fmt.Errorf("invite code not found")
	}

	users = append(users, *user)
	if err := s.saveUsers(users); err != nil {
		return nil, err
	}

	return user, nil
}

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

func (s *Store) saveInviteCodes(codes []InviteCode) error {
	data, err := json.MarshalIndent(codes, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.invitesPath(), data)
}

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

func (s *Store) SaveVault(userID string, data []byte) error {
	return s.writeFile(s.Config.VaultPath(userID), data)
}

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

func (s *Store) DeleteVault(userID string) error {
	return os.Remove(s.Config.VaultPath(userID))
}

type RefreshToken struct {
	Hash      string    `json:"h"`
	UserID    string    `json:"u"`
	ExpiresAt time.Time `json:"e"`
}

func (s *Store) refreshTokensPath() string {
	return filepath.Join(s.Config.DataDir, "refresh_tokens")
}

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

func (s *Store) saveRefreshTokens(tokens []RefreshToken) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	return s.writeFile(s.refreshTokensPath(), data)
}

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

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

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

func (s *Store) SaveBlockedTokens(hashes []string) error {
	data, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	return s.writeFile(s.Config.BlockedTokensPath(), data)
}

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

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
