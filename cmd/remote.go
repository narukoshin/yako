package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

const adminCacheDuration = 5 * time.Minute

type remoteConfig struct {
	ServerURL    string `json:"server_url"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Username     string `json:"username,omitempty"`
}

func remoteConfigPath() string {
	return filepath.Join(config.AppDir(), "remote")
}

func loadRemoteConfig() (*remoteConfig, error) {
	encrypted, err := os.ReadFile(remoteConfigPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in; run 'yako remote login <server-url>' first")
	}

	data, err := ck.Decrypt(config.MachineSecret(), encrypted)
	if err != nil {
		return nil, kerr.ErrCorrupted
	}

	var rc remoteConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, kerr.ErrCorrupted
	}
	if rc.ServerURL == "" {
		return nil, fmt.Errorf("remote not configured; run 'yako remote login'")
	}
	return &rc, nil
}

func saveRemoteConfig(rc *remoteConfig) error {
	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	encrypted, err := ck.Encrypt(config.MachineSecret(), data)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(remoteConfigPath(), encrypted, 0600)
}

// --- Admin credential caching ---

type adminRemoteConfig struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	CachedAt  int64  `json:"cached_at"`
}

func adminRemoteConfigPath() string {
	return filepath.Join(config.AppDir(), "admin_remote")
}

func saveAdminConfig(rc *adminRemoteConfig) error {
	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	encrypted, err := ck.Encrypt(config.MachineSecret(), data)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(adminRemoteConfigPath(), encrypted, 0600)
}

func loadAdminConfig() (*adminRemoteConfig, error) {
	encrypted, err := os.ReadFile(adminRemoteConfigPath())
	if err != nil {
		return nil, err
	}

	data, err := ck.Decrypt(config.MachineSecret(), encrypted)
	if err != nil {
		return nil, kerr.ErrCorrupted
	}

	var rc adminRemoteConfig
	if err := json.Unmarshal(data, &rc); err != nil {
		return nil, kerr.ErrCorrupted
	}
	if rc.ServerURL == "" || rc.Token == "" {
		return nil, fmt.Errorf("incomplete admin config")
	}
	return &rc, nil
}

func getAdminToken() (string, string, error) {
	rc, err := loadAdminConfig()
	if err == nil {
		if time.Since(time.Unix(rc.CachedAt, 0)) < adminCacheDuration {
			return rc.ServerURL, rc.Token, nil
		}
		fmt.Println("Admin session expired; please log in again")
	}

	serverURL, err := resolveAdminServerURL()
	if err != nil {
		return "", "", err
	}

	return adminLoginFlow(serverURL)
}

func resolveAdminServerURL() (string, error) {
	rc, err := loadAdminConfig()
	if err == nil && rc.ServerURL != "" {
		return rc.ServerURL, nil
	}

	raw, err := os.ReadFile(remoteConfigPath())
	if err == nil {
		data, err := ck.Decrypt(config.MachineSecret(), raw)
		if err == nil {
			var urc remoteConfig
			if json.Unmarshal(data, &urc) == nil && urc.ServerURL != "" {
				return urc.ServerURL, nil
			}
		}
	}

	return readLine("Server URL: ")
}

func adminLoginFlow(serverURL string) (string, string, error) {
	username, err := readLine("Admin username: ")
	if err != nil {
		return "", "", err
	}
	password, err := readPassphrase("Admin password: ")
	if err != nil {
		return "", "", err
	}

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	resp, err := http.Post(apiURL(serverURL, "/auth/login"), "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", kerr.CleanHTTPError("admin login", resp.StatusCode, respBody)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	ac := &adminRemoteConfig{
		ServerURL: serverURL,
		Token:     result.Token,
		CachedAt:  time.Now().Unix(),
	}
	if err := saveAdminConfig(ac); err != nil {
		return "", "", fmt.Errorf("save admin config: %w", err)
	}

	fmt.Println("Admin session cached (expires in 5 minutes)")
	return serverURL, result.Token, nil
}

func init() {
	rootCmd.AddCommand(remoteCmd)

	remoteCmd.AddGroup(&cobra.Group{ID: "client", Title: "Client Commands:"})
	remoteCmd.AddGroup(&cobra.Group{ID: "admin", Title: "Admin Commands:"})

	remoteLoginCmd.GroupID = "client"
	remoteRegisterCmd.GroupID = "client"
	remotePushCmd.GroupID = "client"
	remotePullCmd.GroupID = "client"
	remoteLogoutCmd.GroupID = "client"
	remoteStatusCmd.GroupID = "client"
	remoteDeleteVaultCmd.GroupID = "client"
	remoteInviteCmd.GroupID = "admin"
	remoteInvitesCmd.GroupID = "admin"
	remoteDeleteInviteCmd.GroupID = "admin"
	remoteUsersCmd.GroupID = "admin"
	remoteBanCmd.GroupID = "admin"
	remoteUnbanCmd.GroupID = "admin"
	remoteDeleteUserCmd.GroupID = "admin"

	remoteCmd.AddCommand(remoteLoginCmd)
	remoteCmd.AddCommand(remoteRegisterCmd)
	remoteCmd.AddCommand(remotePushCmd)
	remoteCmd.AddCommand(remotePullCmd)
	remoteCmd.AddCommand(remoteLogoutCmd)
	remoteCmd.AddCommand(remoteStatusCmd)
	remoteCmd.AddCommand(remoteDeleteVaultCmd)
	remoteCmd.AddCommand(remoteInviteCmd)
	remoteCmd.AddCommand(remoteInvitesCmd)
	remoteCmd.AddCommand(remoteDeleteInviteCmd)
	remoteCmd.AddCommand(remoteUsersCmd)
	remoteCmd.AddCommand(remoteBanCmd)
	remoteCmd.AddCommand(remoteUnbanCmd)
	remoteCmd.AddCommand(remoteDeleteUserCmd)
	remoteInviteCmd.Flags().IntVarP(&inviteExpiry, "expiry", "e", 24, "Invite code expiry in hours")
	remoteLogoutCmd.Flags().BoolVarP(&logoutAdmin, "admin", "a", false, "Also clear cached admin session")
}

var inviteExpiry int

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Sync vault with a remote server",
}

var remoteLoginCmd = &cobra.Command{
	Use:   "login <server-url>",
	Short: "Authenticate with the sync server",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteLogin(args[0])
	},
}

var remoteRegisterCmd = &cobra.Command{
	Use:   "register <server-url>",
	Short: "Register a new account (requires invite code)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteRegister(args[0])
	},
}

var remotePushCmd = &cobra.Command{
	Use:   "push",
	Short: "Upload vault to remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemotePush()
	},
}

var remotePullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Download vault from remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemotePull()
	},
}

var (
	logoutAdmin bool
)

var remoteLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Invalidate token and remove stored credentials",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteLogout()
	},
}

var remoteStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check connection to remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteStatus()
	},
}

func apiURL(base, path string) string {
	return base + "/api/v1" + path
}

func refreshAccessToken(rc *remoteConfig) (string, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": rc.RefreshToken})
	resp, err := http.Post(apiURL(rc.ServerURL, "/auth/refresh"), "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", kerr.CleanHTTPError("refresh token", resp.StatusCode, respBody)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parse refresh response: %w", err)
	}

	rc.Token = result.Token
	if err := saveRemoteConfig(rc); err != nil {
		return "", fmt.Errorf("save refreshed token: %w", err)
	}
	return result.Token, nil
}

func doRequestWithRefresh(method, url string, body []byte, rc *remoteConfig) (*http.Response, error) {
	resp, err := doRequest(method, url, rc.Token, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && rc.RefreshToken != "" {
		resp.Body.Close()
		newToken, err := refreshAccessToken(rc)
		if err != nil {
			return doRequest(method, url, rc.Token, body)
		}
		rc.Token = newToken
		return doRequest(method, url, rc.Token, body)
	}
	return resp, nil
}

func doRequest(method, url, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func runRemoteLogin(serverURL string) error {
	username, err := readLine("Username: ")
	if err != nil {
		return err
	}
	password, err := readPassphrase("Password: ")
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	resp, err := http.Post(apiURL(serverURL, "/auth/login"), "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("login", resp.StatusCode, respBody)
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	rc := &remoteConfig{
		ServerURL:    serverURL,
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		Username:     username,
	}
	if err := saveRemoteConfig(rc); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("Logged in successfully")
	return nil
}

func runRemoteRegister(serverURL string) error {
	username, err := readLine("Username: ")
	if err != nil {
		return err
	}
	password, err := readAndConfirmPassword("Password: ", "Confirm password: ")
	if err != nil {
		return err
	}
	inviteCode, err := readLine("Invite code: ")
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]string{
		"username":    username,
		"password":    password,
		"invite_code": inviteCode,
	})

	resp, err := http.Post(apiURL(serverURL, "/auth/register"), "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("register", resp.StatusCode, respBody)
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	rc := &remoteConfig{
		ServerURL:    serverURL,
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		Username:     username,
	}
	if err := saveRemoteConfig(rc); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("Registered and logged in successfully")
	return nil
}

func runRemotePush() error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, err := readPassphrase("Master password: ")
	if err != nil {
		return err
	}

	entries, err := vault.Load([]byte(pw))
	if err != nil {
		return err
	}

	vaultData, err := os.ReadFile(config.VaultPath())
	if err != nil {
		return fmt.Errorf("read vault: %w", err)
	}

	resp, err := doRequestWithRefresh("PUT", apiURL(rc.ServerURL, "/vault"), vaultData, rc)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("upload", resp.StatusCode, respBody)
	}

	fmt.Printf("Vault uploaded (%d entries)\n", len(entries))
	return nil
}

func runRemotePull() error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	resp, err := doRequestWithRefresh("GET", apiURL(rc.ServerURL, "/vault"), nil, rc)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("no vault on server; push one first")
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("download", resp.StatusCode, respBody)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}

	tmpPath := config.VaultPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp vault: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath)
		}
	}()

	if vault.Exists() {
		pw, entries, err := unlockVault()
		if err != nil {
			return err
		}

		serverEntries, err := vault.LoadPath(tmpPath, []byte(pw))
		if err != nil {
			return fmt.Errorf("server vault is incompatible: %w", err)
		}

		merged := vault.MergeEntries(entries, serverEntries)

		if err := vault.Save([]byte(pw), merged); err != nil {
			return fmt.Errorf("save merged vault: %w", err)
		}
		fmt.Printf("Vault merged (%d server + %d local = %d total)\n", len(serverEntries), len(merged)-len(serverEntries), len(merged))
	} else {
		if err := os.Rename(tmpPath, config.VaultPath()); err != nil {
			return fmt.Errorf("replace vault: %w", err)
		}
		cleanup = false
		fmt.Println("Vault downloaded")
	}
	return nil
}

func runRemoteLogout() error {
	if logoutAdmin {
		if err := os.Remove(adminRemoteConfigPath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove admin credentials: %w", err)
		}
		fmt.Println("Admin session cleared")
	}

	rc, err := loadRemoteConfig()
	if err != nil {
		fmt.Println("Already logged out")
		return nil
	}

	resp, err := doRequest("POST", apiURL(rc.ServerURL, "/auth/logout"), rc.Token, nil)
	if err == nil {
		resp.Body.Close()
	}

	if err := os.Remove(remoteConfigPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove credentials: %w", err)
	}

	fmt.Println("Logged out")
	return nil
}

func runRemoteStatus() error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	resp, err := http.Get(apiURL(rc.ServerURL, "/health"))
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	fmt.Println("Server is reachable")
	return nil
}

func runRemoteDeleteVault() error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	resp, err := doRequestWithRefresh("DELETE", apiURL(rc.ServerURL, "/account"), nil, rc)
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("delete account", resp.StatusCode, respBody)
	}

	if err := os.Remove(remoteConfigPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove credentials: %w", err)
	}

	fmt.Println("Account and vault deleted from server")
	return nil
}

// --- Admin commands ---

var remoteDeleteVaultCmd = &cobra.Command{
	Use:     "delete-vault",
	Aliases: []string{"destroy"},
	Short:   "Delete your vault from the server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteDeleteVault()
	},
}

var remoteInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Create a single-use invite code",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteInvite()
	},
}

var remoteInvitesCmd = &cobra.Command{
	Use:   "invites",
	Short: "List all invite codes",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteInvites()
	},
}

var remoteDeleteInviteCmd = &cobra.Command{
	Use:   "delete-invite <code>",
	Short: "Revoke an invite code",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteDeleteInvite(args[0])
	},
}

var remoteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all registered users",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteUsers()
	},
}

var remoteBanCmd = &cobra.Command{
	Use:   "ban <username>",
	Short: "Ban a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteBan(args[0])
	},
}

var remoteUnbanCmd = &cobra.Command{
	Use:   "unban <username>",
	Short: "Unban a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteUnban(args[0])
	},
}

var remoteDeleteUserCmd = &cobra.Command{
	Use:   "delete-user <username>",
	Short: "Delete a user and their vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteDeleteUser(args[0])
	},
}

func runRemoteInvite() error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]int{"expiry_hours": inviteExpiry})
	resp, err := doRequest("POST", apiURL(serverURL, "/admin/invite"), token, body)
	if err != nil {
		return fmt.Errorf("create invite: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("create invite", resp.StatusCode, respBody)
	}

	var result struct {
		InviteCode string `json:"invite_code"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("Invite code: %s\n", result.InviteCode)
	fmt.Printf("Expires at:  %s\n", result.ExpiresAt)
	return nil
}

func runRemoteInvites() error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("GET", apiURL(serverURL, "/admin/invites"), token, nil)
	if err != nil {
		return fmt.Errorf("list invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("list invites", resp.StatusCode, respBody)
	}

	var result struct {
		Invites []struct {
			Code      string `json:"code"`
			CreatedBy string `json:"created_by"`
			ExpiresAt string `json:"expires_at"`
			Used      bool   `json:"used"`
		} `json:"invites"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if len(result.Invites) == 0 {
		fmt.Println("No invite codes")
		return nil
	}

	fmt.Printf("%-36s %-20s %-35s %s\n", "Code", "Created By", "Expires (UTC)", "Used")
	for _, c := range result.Invites {
		fmt.Printf("%-36s %-20s %-35s %v\n", c.Code, c.CreatedBy, c.ExpiresAt, c.Used)
	}
	return nil
}

func runRemoteDeleteInvite(code string) error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("DELETE", apiURL(serverURL, "/admin/invites/"+code), token, nil)
	if err != nil {
		return fmt.Errorf("delete invite: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("delete invite", resp.StatusCode, respBody)
	}

	fmt.Printf("Invite code '%s' revoked\n", code)
	return nil
}

func runRemoteUsers() error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("GET", apiURL(serverURL, "/admin/users"), token, nil)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("list users", resp.StatusCode, respBody)
	}

	var result struct {
		Users []struct {
			ID        string `json:"id"`
			Username  string `json:"username"`
			Role      string `json:"role"`
			Status    string `json:"status"`
			CreatedAt string `json:"created_at"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if len(result.Users) == 0 {
		fmt.Println("No users registered")
		return nil
	}

	fmt.Printf("%-20s %-8s %-8s %s\n", "Username", "Role", "Status", "Created (UTC)")
	for _, u := range result.Users {
		fmt.Printf("%-20s %-8s %-8s %s\n", u.Username, u.Role, u.Status, u.CreatedAt)
	}
	return nil
}

func runRemoteBan(username string) error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("PUT", apiURL(serverURL, "/admin/users/"+username+"/ban"), token, nil)
	if err != nil {
		return fmt.Errorf("ban user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("ban", resp.StatusCode, respBody)
	}

	fmt.Printf("User '%s' banned\n", username)
	return nil
}

func runRemoteUnban(username string) error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("PUT", apiURL(serverURL, "/admin/users/"+username+"/unban"), token, nil)
	if err != nil {
		return fmt.Errorf("unban user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("unban", resp.StatusCode, respBody)
	}

	fmt.Printf("User '%s' unbanned\n", username)
	return nil
}

func runRemoteDeleteUser(username string) error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	resp, err := doRequest("DELETE", apiURL(serverURL, "/admin/users/"+username), token, nil)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("delete user", resp.StatusCode, respBody)
	}

	fmt.Printf("User '%s' deleted\n", username)
	return nil
}
