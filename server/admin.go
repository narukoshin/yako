package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type userInfo struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Role      UserRole   `json:"role"`
	Status    UserStatus `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.LoadUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load users")
		return
	}

	info := make([]userInfo, 0, len(users))
	for _, u := range users {
		info = append(info, userInfo{
			ID:        u.ID,
			Username:  u.Username,
			Role:      u.Role,
			Status:    u.Status,
			CreatedAt: u.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"users": info})
}

func (s *Server) handleAdminInvite(w http.ResponseWriter, r *http.Request) {
	adminID := r.Context().Value(ctxKeyUserID).(string)
	admin, err := s.store.GetUser(adminID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get admin")
		return
	}

	var req struct {
		ExpiryHours int `json:"expiry_hours"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	code, err := s.store.CreateInviteCode(admin.Username, req.ExpiryHours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create invite")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"invite_code": code.Code,
		"expires_at":  code.ExpiresAt,
		"created_by":  admin.Username,
	})
}

func (s *Server) handleAdminInvites(w http.ResponseWriter, r *http.Request) {
	codes, err := s.store.LoadInviteCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load invites")
		return
	}

	if codes == nil {
		codes = []InviteCode{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"invites": codes})
}

func (s *Server) handleAdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	if err := s.store.DeleteInviteCode(code); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAdminBanUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}

	adminID := r.Context().Value(ctxKeyUserID).(string)
	admin, err := s.store.GetUser(adminID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get admin")
		return
	}

	if admin.Username == username {
		writeError(w, http.StatusBadRequest, "cannot ban yourself")
		return
	}

	user, err := s.store.FindUser(username)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	user.Status = StatusBanned
	if err := s.store.UpdateUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, "update user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "banned", "username": username})
}

func (s *Server) handleAdminUnbanUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}

	user, err := s.store.FindUser(username)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	user.Status = StatusActive
	if err := s.store.UpdateUser(user); err != nil {
		writeError(w, http.StatusInternalServerError, "update user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "username": username})
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username required")
		return
	}

	adminID := r.Context().Value(ctxKeyUserID).(string)
	admin, err := s.store.GetUser(adminID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get admin")
		return
	}

	if admin.Username == username {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	user, err := s.store.FindUser(username)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := s.store.DeleteVault(user.ID); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: failed to delete vault for %s: %v", username, err)
	}

	if err := s.store.DeleteUser(username); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete user: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "username": username})
}
