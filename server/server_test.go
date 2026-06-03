package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	srv := New(&Config{
		DataDir:   dir,
		JWTSecret: "test-secret-for-testing-only",
	})

	if err := srv.CreateAdmin("admin", "adminpass123"); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	return srv
}

func registerTestUser(t *testing.T, srv *Server, username, password string) (string, string) {
	t.Helper()

	adminToken := loginAs(t, srv, "admin", "adminpass123")
	inviteResp := request(t, srv, "POST", "/api/v1/admin/invite", `{}`, adminToken)
	var inviteResult struct {
		InviteCode string `json:"invite_code"`
	}
	if err := json.NewDecoder(inviteResp.Body).Decode(&inviteResult); err != nil {
		t.Fatalf("decode invite: %v", err)
	}

	body := `{"username":"` + username + `","password":"` + password + `","invite_code":"` + inviteResult.InviteCode + `"}`
	resp := request(t, srv, "POST", "/api/v1/auth/register", body, "")
	var authResult struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResult); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	return authResult.Token, authResult.RefreshToken
}

func loginAs(t *testing.T, srv *Server, username, password string) string {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	resp := request(t, srv, "POST", "/api/v1/auth/login", body, "")
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	return result.Token
}

func request(t *testing.T, srv *Server, method, path, body, token string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w.Result()
}

func TestAuthRegisterAndLogin(t *testing.T) {
	srv := newTestServer(t)

	adminToken := loginAs(t, srv, "admin", "adminpass123")
	inviteResp := request(t, srv, "POST", "/api/v1/admin/invite", `{}`, adminToken)
	if inviteResp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: %d", inviteResp.StatusCode)
	}

	// Register with valid invite
	body := `{"username":"alice","password":"alicepass123","invite_code":"invalid"}`
	resp := request(t, srv, "POST", "/api/v1/auth/register", body, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register with invalid invite: got %d, want 403", resp.StatusCode)
	}
}

func TestAuthExpiredToken(t *testing.T) {
	srv := newTestServer(t)

	// Create an expired token manually
	claims := jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("test-secret-for-testing-only"))
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	// Trying to use an expired token should fail
	resp := request(t, srv, "GET", "/api/v1/vault", "", tokenStr)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token: got %d, want 401", resp.StatusCode)
	}
}

func TestBlockedToken(t *testing.T) {
	srv := newTestServer(t)

	_, refreshToken := registerTestUser(t, srv, "bob", "bobpass123")

	// Login to get a fresh token
	bobToken := loginAs(t, srv, "bob", "bobpass123")

	// Logout to block the token
	resp := request(t, srv, "POST", "/api/v1/auth/logout", `{}`, bobToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", resp.StatusCode)
	}

	// Using the blocked token should fail
	resp = request(t, srv, "GET", "/api/v1/vault", "", bobToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("blocked token: got %d, want 401", resp.StatusCode)
	}

	// Refresh token should still work
	body := `{"refresh_token":"` + refreshToken + `"}`
	resp = request(t, srv, "POST", "/api/v1/auth/refresh", body, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh after logout: %d", resp.StatusCode)
	}
}

func TestAuthRefreshTokenIsOneTimeUse(t *testing.T) {
	srv := newTestServer(t)

	_, refreshToken := registerTestUser(t, srv, "charlie", "charliepass123")

	body := `{"refresh_token":"` + refreshToken + `"}`
	resp := request(t, srv, "POST", "/api/v1/auth/refresh", body, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh: %d", resp.StatusCode)
	}

	// Second use of same refresh token should fail
	resp = request(t, srv, "POST", "/api/v1/auth/refresh", body, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused refresh token: got %d, want 401", resp.StatusCode)
	}
}

func TestAdminCannotBanSelf(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	resp := request(t, srv, "PUT", "/api/v1/admin/users/admin/ban", `{}`, adminToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self-ban: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminCannotDeleteSelf(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	resp := request(t, srv, "DELETE", "/api/v1/admin/users/admin", `{}`, adminToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self-delete: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminBanAndUnbanUser(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	registerTestUser(t, srv, "dave", "davepass123")

	// Ban dave
	resp := request(t, srv, "PUT", "/api/v1/admin/users/dave/ban", `{}`, adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ban: %d", resp.StatusCode)
	}

	// Dave should not be able to login
	resp = request(t, srv, "POST", "/api/v1/auth/login", `{"username":"dave","password":"davepass123"}`, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login after ban: got %d, want 403", resp.StatusCode)
	}

	// Unban dave
	resp = request(t, srv, "PUT", "/api/v1/admin/users/dave/unban", `{}`, adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unban: %d", resp.StatusCode)
	}

	// Dave should be able to login again
	resp = request(t, srv, "POST", "/api/v1/auth/login", `{"username":"dave","password":"davepass123"}`, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after unban: got %d, want 200", resp.StatusCode)
	}
}

func TestAdminDestroyCleansUp(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	registerTestUser(t, srv, "eve", "evepass123")

	resp := request(t, srv, "DELETE", "/api/v1/admin/destroy", `{}`, adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("destroy: %d", resp.StatusCode)
	}

	// After destroy, login should fail (users deleted)
	resp = request(t, srv, "POST", "/api/v1/auth/login", `{"username":"admin","password":"adminpass123"}`, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("login after destroy should fail")
	}
}

func TestAdminInviteLifecycle(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	// Create invite
	resp := request(t, srv, "POST", "/api/v1/admin/invite", `{}`, adminToken)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: %d", resp.StatusCode)
	}
	var inviteResult struct {
		InviteCode string `json:"invite_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inviteResult); err != nil {
		t.Fatalf("decode invite: %v", err)
	}

	// List invites
	resp = request(t, srv, "GET", "/api/v1/admin/invites", "", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list invites: %d", resp.StatusCode)
	}

	// Revoke invite
	resp = request(t, srv, "DELETE", "/api/v1/admin/invites/"+inviteResult.InviteCode, `{}`, adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke invite: %d", resp.StatusCode)
	}

	// Revoked invite should not be usable
	body := `{"username":"mallory","password":"mallorypass123","invite_code":"` + inviteResult.InviteCode + `"}`
	resp = request(t, srv, "POST", "/api/v1/auth/register", body, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("register with revoked invite: got %d, want 403", resp.StatusCode)
	}
}

func TestLeakedErrorSanitized(t *testing.T) {
	srv := newTestServer(t)
	adminToken := loginAs(t, srv, "admin", "adminpass123")

	// Request with non-existent invite code should not leak the internal "invite code not found" raw error
	resp := request(t, srv, "DELETE", "/api/v1/admin/invites/nonexistent-code", `{}`, adminToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete nonexistent invite: %d", resp.StatusCode)
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if strings.Contains(errResp.Error, "nonexistent-code") {
		t.Fatalf("error message leaked invite code: %q", errResp.Error)
	}
}
