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

type recoveryTracker struct {
	mu       sync.Mutex
	attempts map[string]int
}

func newRecoveryTracker() *recoveryTracker {
	return &recoveryTracker{attempts: make(map[string]int)}
}

func (rt *recoveryTracker) recordAttempt(userID string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.attempts[userID]++
	return rt.attempts[userID]
}

func (rt *recoveryTracker) resetAttempts(userID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.attempts, userID)
}

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
