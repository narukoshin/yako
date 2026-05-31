package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	vault "github.com/narukoshin/yako/v1/vault"
)

// handleGetVault processes GET /api/v1/vault. Returns the user's encrypted vault as
//
//	application/octet-stream. Empty vaults get 404 — nothing to see here.
func (s *Server) handleGetVault(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	data, err := s.store.LoadVault(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read vault")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "no vault uploaded")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Write(data)
}

// handleHeadVault processes HEAD /api/v1/vault. Returns headers without the body — just checking
//
//	if it's there, like I check my phone for your messages.
func (s *Server) handleHeadVault(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	info, err := os.Stat(s.Config.VaultPath(userID))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "no vault uploaded")
			return
		}
		writeError(w, http.StatusInternalServerError, "read vault")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}

// handlePutVault processes PUT /api/v1/vault. Uploads/replaces the user's encrypted vault.
//
//	Body is capped at 100 MB — that's a lot of secrets.
func (s *Server) handlePutVault(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	r.Body = http.MaxBytesReader(w, r.Body, 100*1024*1024)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body")
		return
	}

	if err := s.store.SaveVault(userID, data); err != nil {
		writeError(w, http.StatusInternalServerError, "save vault")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleDeleteVault processes DELETE /api/v1/vault. Removes the user's vault from the server.
//
//	Your secrets leave when you do — no traces, no memories.
func (s *Server) handleDeleteVault(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	if err := s.store.DeleteVault(userID); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "no vault uploaded")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete vault")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// recoveryTracker enforces per-user rate limiting on recovery code attempts.
//
//	Three wrong guesses and the vault is destroyed — no refunds, no regrets.
type recoveryTracker struct {
	mu       sync.Mutex
	attempts map[string]int
}

// newRecoveryTracker creates a recoveryTracker with an empty attempts map.
func newRecoveryTracker() *recoveryTracker {
	return &recoveryTracker{attempts: make(map[string]int)}
}

// recordAttempt increments the attempt counter for a user. Returns the new count.
func (rt *recoveryTracker) recordAttempt(userID string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.attempts[userID]++
	return rt.attempts[userID]
}

// resetAttempts clears the attempt counter for a user. Forgiveness for the lucky ones.
func (rt *recoveryTracker) resetAttempts(userID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.attempts, userID)
}

// handleRecoverVault processes POST /api/v1/recover. Validates a BIP39 recovery phrase against
//
//	the user's vault. Three wrong attempts = vault self-destruct. Don't test me.
func (s *Server) handleRecoverVault(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(ctxKeyUserID).(string)

	var req struct {
		Phrase string `json:"phrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Phrase == "" {
		writeError(w, http.StatusBadRequest, "phrase required")
		return
	}

	data, err := s.store.LoadVault(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read vault")
		return
	}
	if data == nil {
		writeError(w, http.StatusNotFound, "no vault uploaded")
		return
	}

	if vault.VerifyRecoveryCode(data, req.Phrase) {
		s.recoveryTracker.resetAttempts(userID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	attempts := s.recoveryTracker.recordAttempt(userID)
	switch attempts {
	case 1:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "invalid",
			"message":  "Tch! You're doing it wrong again, aren't you?",
			"attempts": 1,
		})
	case 2:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "invalid",
			"message":  "Are you trying to make me crazy or something?!",
			"attempts": 2,
		})
	default:
		s.store.DeleteVault(userID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "destroyed",
			"message":  "That's your last chance! I'm deleting your data forever!",
			"attempts": 3,
		})
	}
}
