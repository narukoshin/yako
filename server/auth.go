package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTManager struct {
	secret    []byte
	blocked   map[string]bool
	blockedMu sync.RWMutex
}

func NewJWTManager(secret string, initialBlocked []string) *JWTManager {
	m := &JWTManager{
		secret:  []byte(secret),
		blocked: make(map[string]bool),
	}
	for _, h := range initialBlocked {
		m.blocked[h] = true
	}
	return m
}

func (m *JWTManager) GenerateToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *JWTManager) ValidateToken(tokenStr string) (string, error) {
	if m.isBlocked(tokenStr) {
		return "", jwt.ErrSignatureInvalid
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return m.secret, nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", jwt.ErrSignatureInvalid
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", jwt.ErrSignatureInvalid
	}
	return sub, nil
}

func (m *JWTManager) BlockToken(tokenStr string) {
	var parser jwt.Parser
	token, _, _ := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return
			}
		}
	}
	h := sha256.Sum256([]byte(tokenStr))
	m.blockedMu.Lock()
	m.blocked[hex.EncodeToString(h[:])] = true
	m.blockedMu.Unlock()
}

func (m *JWTManager) isBlocked(tokenStr string) bool {
	h := sha256.Sum256([]byte(tokenStr))
	m.blockedMu.RLock()
	blocked := m.blocked[hex.EncodeToString(h[:])]
	m.blockedMu.RUnlock()
	return blocked
}

func (m *JWTManager) AllBlocked() []string {
	m.blockedMu.RLock()
	defer m.blockedMu.RUnlock()
	hashes := make([]string, 0, len(m.blocked))
	for h := range m.blocked {
		hashes = append(hashes, h)
	}
	return hashes
}

type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}
	if req.InviteCode == "" {
		writeError(w, http.StatusBadRequest, "invite code required")
		return
	}

	user, err := s.store.Register(req.Username, req.Password, req.InviteCode)
	if err != nil {
		status := http.StatusConflict
		if err.Error() == "invite code already used" || err.Error() == "invite code expired" || err.Error() == "invite code not found" {
			status = http.StatusForbidden
		}
		writeError(w, status, err.Error())
		return
	}

	token, err := s.jwt.GenerateToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := s.store.CreateRefreshToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"token":         token,
		"refresh_token": refreshToken,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, err := s.store.Authenticate(req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if user.Status == StatusBanned {
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}

	token, err := s.jwt.GenerateToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := s.store.CreateRefreshToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token":         token,
		"refresh_token": refreshToken,
	})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}

	userID, err := s.store.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	user, err := s.store.GetUser(userID)
	if err != nil || user.Status == StatusBanned {
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}

	if err := s.store.DeleteRefreshToken(req.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	newToken, err := s.jwt.GenerateToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	newRefreshToken, err := s.store.CreateRefreshToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"token":         newToken,
		"refresh_token": newRefreshToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if len(tokenStr) > 7 {
		tokenStr = tokenStr[7:]
		s.jwt.BlockToken(tokenStr)
		if err := s.store.SaveBlockedTokens(s.jwt.AllBlocked()); err != nil {
			log.Printf("warning: failed to persist blocked tokens: %v", err)
		}

		userID, err := s.jwt.ValidateToken(tokenStr)
		if err == nil {
			s.store.DeleteUserRefreshTokens(userID)
		}
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.NewDecoder(r.Body).Decode(&req) == nil && req.RefreshToken != "" {
		s.store.DeleteRefreshToken(req.RefreshToken)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	user, err := s.store.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get user")
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := s.store.DeleteVault(user.ID); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: failed to delete vault: %v", err)
	}
	if err := s.store.DeleteUserRefreshTokens(user.ID); err != nil {
		log.Printf("warning: failed to delete refresh tokens: %v", err)
	}
	if err := s.store.DeleteUser(user.Username); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete user: %v", err))
		return
	}

	tokenStr := r.Header.Get("Authorization")
	if len(tokenStr) > 7 {
		tokenStr = tokenStr[7:]
		s.jwt.BlockToken(tokenStr)
		if err := s.store.SaveBlockedTokens(s.jwt.AllBlocked()); err != nil {
			log.Printf("warning: failed to persist blocked tokens: %v", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
