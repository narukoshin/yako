package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
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
