package server

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// userInfo is a safe subset of [User] returned by admin endpoints (no password hash exposed).
type userInfo struct {
	ID        string     `json:"id"`
	Username  string     `json:"username"`
	Role      UserRole   `json:"role"`
	Status    UserStatus `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
}

// handleAdminUsers processes GET /api/v1/admin/users. Returns all users (minus password hashes).
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

// handleAdminInvite processes POST /api/v1/admin/invite. Creates a new invite code with
//
//	an optional expiry window (default 24h, max 168h). One ticket per guest.
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

// handleAdminInvites processes GET /api/v1/admin/invites. Lists all invite codes with their status.
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

// handleAdminRevokeInvite processes DELETE /api/v1/admin/invites/{code}. Deletes an invite code.
func (s *Server) handleAdminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	if err := s.store.DeleteInviteCode(code); err != nil {
		log.Printf("error deleting invite code %q: %v", code, err)
		writeError(w, http.StatusNotFound, "invite code not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAdminBanUser processes PUT /api/v1/admin/users/{username}/ban. Sets a user's status to
//
//	banned. Can't ban yourself — that would be lonely.
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

// handleAdminUnbanUser processes PUT /api/v1/admin/users/{username}/unban. Restores a banned
//
//	user to active status. Forgiveness is possible, but I won't forget.
func (s *Server) handleAdminUnbanUser(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusBadRequest, "cannot unban yourself")
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

// handleAdminDeleteUser processes DELETE /api/v1/admin/users/{username}. Deletes the user, their
//
//	vault, and refresh tokens. Irreversible — I don't do do-overs.
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

	if err := s.store.DeleteUserRefreshTokens(user.ID); err != nil {
		log.Printf("warning: failed to delete refresh tokens for %s: %v", username, err)
	}

	if err := s.store.DeleteUser(username); err != nil {
		log.Printf("error deleting user %q: %v", username, err)
		writeError(w, http.StatusInternalServerError, "delete user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "username": username})
}

// handleAdminDestroy processes DELETE /api/v1/admin/destroy. Wipes all server data except
//
//	config.yml. Nuclear option — like my feelings for you.
func (s *Server) handleAdminDestroy(w http.ResponseWriter, r *http.Request) {
	adminID := r.Context().Value(ctxKeyUserID).(string)

	tokenStr := r.Header.Get("Authorization")
	if len(tokenStr) > 7 {
		tokenStr = tokenStr[7:]
		s.jwt.BlockToken(tokenStr)
	}

	if err := s.store.Destroy(); err != nil {
		log.Printf("error destroying server data: %v", err)
		writeError(w, http.StatusInternalServerError, "destroy failed")
		return
	}

	if err := s.store.SaveBlockedTokens(s.jwt.AllBlocked()); err != nil {
		log.Printf("warning: failed to persist blocked tokens: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "destroyed", "by": adminID})
}
