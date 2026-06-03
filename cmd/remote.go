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

// adminCacheDuration is how long an admin session token is cached (5 minutes).
const adminCacheDuration = 5 * time.Minute

// remoteConfig stores the user's remote server credentials, encrypted on disk.
type remoteConfig struct {
	ServerURL    string `json:"server_url"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Username     string `json:"username,omitempty"`
}

// remoteConfigPath returns the path to the encrypted remote config file.
func remoteConfigPath() string {
	return filepath.Join(config.AppDir(), "remote")
}

// loadRemoteConfig reads and decrypts the remote config from disk. Machine-bound encryption.
func loadRemoteConfig() (*remoteConfig, error) {
	encrypted, err := os.ReadFile(remoteConfigPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in; run 'yako remote login <server-url>' first")
	}

	ms := config.MachineSecret()
	data, err := ck.Decrypt(ms, encrypted)
	ck.ZeroBytes(ms)
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

// saveRemoteConfig encrypts and writes the remote config to disk. Machine-bound, just like us.
func saveRemoteConfig(rc *remoteConfig) error {
	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	ms := config.MachineSecret()
	encrypted, err := ck.Encrypt(ms, data)
	ck.ZeroBytes(ms)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(remoteConfigPath(), encrypted, 0600)
}

// adminRemoteConfig stores cached admin credentials for server management.
type adminRemoteConfig struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
	CachedAt  int64  `json:"cached_at"`
}

// adminRemoteConfigPath returns the path to the encrypted admin remote config file.
func adminRemoteConfigPath() string {
	return filepath.Join(config.AppDir(), "admin_remote")
}

// saveAdminConfig encrypts and writes the admin remote config to disk.
func saveAdminConfig(rc *adminRemoteConfig) error {
	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	ms := config.MachineSecret()
	encrypted, err := ck.Encrypt(ms, data)
	ck.ZeroBytes(ms)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(adminRemoteConfigPath(), encrypted, 0600)
}

// loadAdminConfig reads and decrypts the admin remote config from disk.
func loadAdminConfig() (*adminRemoteConfig, error) {
	encrypted, err := os.ReadFile(adminRemoteConfigPath())
	if err != nil {
		return nil, err
	}

	ms := config.MachineSecret()
	data, err := ck.Decrypt(ms, encrypted)
	ck.ZeroBytes(ms)
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

// getAdminToken returns a valid admin token, either from cache or by prompting for login.
func getAdminToken() (string, string, error) {
	rc, err := loadAdminConfig()
	if err == nil && time.Since(time.Unix(rc.CachedAt, 0)) < adminCacheDuration {
		if verifyAdminToken(rc.ServerURL, rc.Token) {
			return rc.ServerURL, rc.Token, nil
		}
		fmt.Println("Admin session expired; please log in again")
		os.Remove(adminRemoteConfigPath())
	}

	serverURL, err := resolveAdminServerURL()
	if err != nil {
		return "", "", err
	}

	return adminLoginFlow(serverURL)
}

// verifyAdminToken checks if the cached admin token is still valid by hitting /admin/users.
func verifyAdminToken(serverURL, token string) bool {
	resp, err := doRequest("GET", apiURL(serverURL, "/admin/users"), token, nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// resolveAdminServerURL determines the server URL: from cached admin config, user remote config,
//
//	or by prompting the user. I'll find you anywhere.
func resolveAdminServerURL() (string, error) {
	rc, err := loadAdminConfig()
	if err == nil && rc.ServerURL != "" {
		return rc.ServerURL, nil
	}

	raw, err := os.ReadFile(remoteConfigPath())
	if err == nil {
		ms := config.MachineSecret()
		data, err := ck.Decrypt(ms, raw)
		ck.ZeroBytes(ms)
		if err == nil {
			var urc remoteConfig
			if json.Unmarshal(data, &urc) == nil && urc.ServerURL != "" {
				return urc.ServerURL, nil
			}
		}
	}

	return readLine("Server URL: ")
}

// adminLoginFlow prompts for admin credentials, authenticates, caches the session, and returns
//
//	the server URL + token.
func adminLoginFlow(serverURL string) (string, string, error) {
	username, err := readLine("Admin username: ")
	if err != nil {
		return "", "", err
	}
	password, err := readPassphrase("Admin password: ")
	if err != nil {
		return "", "", err
	}
	defer ck.ZeroBytes(password)

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": string(password),
	})

	resp, err := doRequest("POST", apiURL(serverURL, "/auth/login"), "", body)
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

// init registers the remote command, all its subcommands (client + admin groups), and their flags.
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
	remoteDestroyServerCmd.GroupID = "admin"
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
	remoteCmd.AddCommand(remoteDestroyServerCmd)
	remoteCmd.AddCommand(remoteInviteCmd)
	remoteCmd.AddCommand(remoteInvitesCmd)
	remoteCmd.AddCommand(remoteDeleteInviteCmd)
	remoteCmd.AddCommand(remoteUsersCmd)
	remoteCmd.AddCommand(remoteBanCmd)
	remoteCmd.AddCommand(remoteUnbanCmd)
	remoteCmd.AddCommand(remoteDeleteUserCmd)
	remoteInviteCmd.Flags().IntVarP(&inviteExpiry, "expiry", "e", 24, "Invite code expiry in hours")
	remotePullCmd.Flags().BoolVarP(&pullRecovery, "recovery", "r", false, "Use recovery phrase to decrypt vault from server (cross-machine)")
	remoteLogoutCmd.Flags().BoolVarP(&logoutAdmin, "admin", "a", false, "Also clear cached admin session")
}

// inviteExpiry is the default expiry hours for invite codes.
var inviteExpiry int

// remoteCmd is the parent command for all remote sync subcommands.
var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Sync vault with a remote server",
}

// remoteLoginCmd prompts for credentials and saves them to the encrypted remote config.
var remoteLoginCmd = &cobra.Command{
	Use:   "login <server-url>",
	Short: "Authenticate with the sync server",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteLogin(args[0])
	},
}

// remoteRegisterCmd creates a new account on the remote server with username, password, and invite code.
var remoteRegisterCmd = &cobra.Command{
	Use:   "register <server-url>",
	Short: "Register a new account (requires invite code)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteRegister(args[0])
	},
}

// remotePushCmd uploads the local vault to the remote server.
var remotePushCmd = &cobra.Command{
	Use:   "push",
	Short: "Upload vault to remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemotePush()
	},
}

// remotePullCmd downloads the server vault and merges it with the local one.
var remotePullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Download vault from remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemotePull()
	},
}

// logoutAdmin and pullRecovery are flags for the remote logout and pull commands respectively.
var (
	logoutAdmin  bool
	pullRecovery bool
)

// remoteLogoutCmd invalidates the server token and removes local stored credentials.
var remoteLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Invalidate token and remove stored credentials",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteLogout()
	},
}

// remoteStatusCmd checks whether the remote server is reachable via the /health endpoint.
var remoteStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check connection to remote server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteStatus()
	},
}

// apiURL joins the server base URL with the /api/v1 prefix and the given path.
func apiURL(base, path string) string {
	return base + "/api/v1" + path
}

// refreshAccessToken exchanges the stored refresh token for a new access token and persists it.
func refreshAccessToken(rc *remoteConfig) (string, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": rc.RefreshToken})
	resp, err := doRequest("POST", apiURL(rc.ServerURL, "/auth/refresh"), "", body)
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

// doRequestWithRefresh executes an HTTP request and retries with a refreshed token on 401.
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

// doRequest creates and executes an HTTP request with an optional Bearer token and JSON content-type.
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

// runRemoteLogin authenticates with username/password and saves the credentials to the encrypted remote config.
func runRemoteLogin(serverURL string) error {
	username, err := readLine("Username: ")
	if err != nil {
		return err
	}
	password, err := readPassphrase("Password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(password)

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": string(password),
	})

	resp, err := doRequest("POST", apiURL(serverURL, "/auth/login"), "", body)
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

// runRemoteRegister prompts for credentials and invite code, creates an account, and saves the config.
func runRemoteRegister(serverURL string) error {
	username, err := readLine("Username: ")
	if err != nil {
		return err
	}
	password, err := readAndConfirmPassword("Password: ", "Confirm password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(password)
	inviteCode, err := readLine("Invite code: ")
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]string{
		"username":    username,
		"password":    string(password),
		"invite_code": inviteCode,
	})

	resp, err := doRequest("POST", apiURL(serverURL, "/auth/register"), "", body)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return kerr.CleanHTTPError("register", resp.StatusCode, respBody)
	}

	token, refreshToken, err := parseTokenResponse(resp.Body)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	rc := &remoteConfig{
		ServerURL:    serverURL,
		Token:        token,
		RefreshToken: refreshToken,
		Username:     username,
	}
	if err := saveRemoteConfig(rc); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("Registered and logged in successfully")
	return nil
}

// parseTokenResponse decodes a JSON body with token and refresh_token fields.
func parseTokenResponse(r io.Reader) (token, refreshToken string, err error) {
	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return "", "", err
	}
	return result.Token, result.RefreshToken, nil
}

// runRemotePush encrypts and uploads the vault file to the remote server.
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
	defer ck.ZeroBytes(pw)

	entries, err := vault.Load(pw)
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

// runRemotePull downloads the server vault and merges it with local entries; supports --recovery flag.
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

	if pullRecovery {
		return runRemotePullRecovery(data)
	}

	return pullInstallVault(data)
}

// pullInstallVault writes downloaded vault data to a temp file, then merges with the local
// vault (if it exists) or replaces it entirely.
func pullInstallVault(data []byte) error {
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
		defer ck.ZeroBytes(pw)

		serverEntries, err := vault.LoadPath(tmpPath, pw)
		if err != nil {
			return fmt.Errorf("server vault is incompatible: %w", err)
		}

		merged := vault.MergeEntries(entries, serverEntries)

		if err := vault.Save(pw, merged); err != nil {
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

// runRemotePullRecovery attempts recovery from the remote server with up to 3 tries; destroys the vault on 3 failures.
func runRemotePullRecovery(data []byte) error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	serverEntries, err := recoverServerEntries(rc, data)
	if err != nil {
		return err
	}

	return installRecoveredEntries(serverEntries)
}

// recoverServerEntries prompts for recovery phrase up to 3 times, verifies against the server,
// and returns decrypted entries on success. The server destroys the vault after 3 failures.
func recoverServerEntries(rc *remoteConfig, data []byte) ([]vault.Entry, error) {
	for attempt := 1; attempt <= 3; attempt++ {
		phrase, err := readLine(fmt.Sprintf("Recovery phrase (%d words, space-separated): ", vault.PhraseWords))
		if err != nil {
			return nil, err
		}

		resp, err := doRequestWithRefresh("POST", apiURL(rc.ServerURL, "/recover"),
			[]byte(`{"phrase":"`+phrase+`"}`), rc)
		zeroString(phrase)
		if err != nil {
			return nil, fmt.Errorf("recover request: %w", err)
		}

		var result struct {
			Status   string `json:"status"`
			Message  string `json:"message"`
			Attempts int    `json:"attempts"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		switch result.Status {
		case "ok":
			entries, err := vault.LoadRecoveryWithCodeData(data, phrase)
			if err != nil {
				return nil, fmt.Errorf("decrypt vault: %w", err)
			}
			fmt.Println("(Stops pouting and looks at you with a tiny smile)")
			return entries, nil
		case "invalid":
			if attempt < 3 {
				fmt.Println(result.Message)
				fmt.Println()
			}
		case "destroyed":
			fmt.Println(result.Message)
			fmt.Println("(Grabs her hair in frustration before finally letting go of the vault)")
			return nil, fmt.Errorf("vault destroyed on server after 3 failed recovery attempts")
		}
	}
	return nil, fmt.Errorf("recovery failed")
}

// installRecoveredEntries merges recovered server entries with the local vault if it exists,
// or creates a new vault with a new password.
func installRecoveredEntries(serverEntries []vault.Entry) error {
	if vault.Exists() {
		pw, entries, err := unlockVault()
		if err != nil {
			return err
		}
		defer ck.ZeroBytes(pw)

		merged := vault.MergeEntries(entries, serverEntries)
		if err := vault.Save(pw, merged); err != nil {
			return fmt.Errorf("save merged vault: %w", err)
		}
		fmt.Printf("Vault merged (%d server + %d local = %d total)\n", len(serverEntries), len(merged)-len(serverEntries), len(merged))
	} else {
		pw, err := readAndConfirmPassword("New master password: ", "Confirm new master password: ")
		if err != nil {
			return err
		}
		defer ck.ZeroBytes(pw)
		if err := vault.Save(pw, serverEntries); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		fmt.Println("Vault recovered")
		fmt.Println("Recovery code was NOT transferred. Run 'yako config generate-recovery' to create a new one.")
	}
	return nil
}

// zeroString overwrites the contents of s with zeroes for the first 512 bytes.
func zeroString(s string) {
	for i := 0; i < len(s) && i < 512; i++ {
		b := []byte(s)
		for j := range b {
			b[j] = 0
		}
	}
}

// runRemoteLogout invalidates the token on the server and removes local credentials (and optionally admin cache).
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

// runRemoteStatus checks server health and reports whether it's reachable, including version info.
func runRemoteStatus() error {
	rc, err := loadRemoteConfig()
	if err != nil {
		return err
	}

	resp, err := doRequest("GET", apiURL(rc.ServerURL, "/health"), "", nil)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("parse health: %w", err)
	}

	fmt.Printf("Server version: %s (client: %s)\n", health.Version, config.VERSION)

	if health.Version != "" {
		cmp := config.CompareVersions(health.Version, config.VERSION)
		if cmp < 0 {
			fmt.Fprintf(os.Stderr, "Warning: server is outdated (%s < %s). Update your server for compatibility.\n", health.Version, config.VERSION)
		} else if cmp > 0 {
			fmt.Fprintf(os.Stderr, "Warning: client is outdated (%s < %s). Rebuild with the latest code.\n", config.VERSION, health.Version)
		}
	}

	return nil
}

// runRemoteDeleteVault deletes the user's account and vault from the server and clears local credentials.
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

// runRemoteDestroyServer wipes all server data after admin confirmation (requires URL re-entry).
func runRemoteDestroyServer() error {
	serverURL, token, err := getAdminToken()
	if err != nil {
		return err
	}

	fmt.Print("This will delete ALL users, vaults, and data from the server. Are you sure? (y/n): ")
	resp, err := readLine("")
	if err != nil {
		return err
	}
	if resp != "y" {
		fmt.Println("Cancelled")
		return nil
	}

	fmt.Print("Type the server URL to confirm: ")
	confirmURL, err := readLine("")
	if err != nil {
		return err
	}
	if confirmURL != serverURL {
		fmt.Println("Server URL does not match. Cancelled.")
		return nil
	}

	resp2, err := doRequest("DELETE", apiURL(serverURL, "/admin/destroy"), token, nil)
	if err != nil {
		return fmt.Errorf("destroy server: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		return kerr.CleanHTTPError("destroy server", resp2.StatusCode, body)
	}

	os.Remove(adminRemoteConfigPath())

	fmt.Println("Server destroyed. All data has been wiped.")
	return nil
}

// remoteDeleteVaultCmd deletes the user's vault from the remote server.
var remoteDeleteVaultCmd = &cobra.Command{
	Use:     "delete-vault",
	Aliases: []string{"destroy"},
	Short:   "Delete your vault from the server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteDeleteVault()
	},
}

// remoteDestroyServerCmd wipes all server data (admin only, requires token).
var remoteDestroyServerCmd = &cobra.Command{
	Use:   "destroy-server",
	Short: "Wipe all data (users, vaults, invites) from the server",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteDestroyServer()
	},
}

// remoteInviteCmd creates a single-use invite code with configurable expiry (--expiry).
var remoteInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Create a single-use invite code",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteInvite()
	},
}

// remoteInvitesCmd lists all invite codes with their creator, expiry, and used status.
var remoteInvitesCmd = &cobra.Command{
	Use:   "invites",
	Short: "List all invite codes",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteInvites()
	},
}

// remoteDeleteInviteCmd revokes an invite code by its value.
var remoteDeleteInviteCmd = &cobra.Command{
	Use:   "delete-invite <code>",
	Short: "Revoke an invite code",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteDeleteInvite(args[0])
	},
}

// remoteUsersCmd lists all registered users with roles and statuses (admin only).
var remoteUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "List all registered users",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRemoteUsers()
	},
}

// remoteBanCmd bans a user account (admin only).
var remoteBanCmd = &cobra.Command{
	Use:   "ban <username>",
	Short: "Ban a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteBan(args[0])
	},
}

// remoteUnbanCmd unban a user account (admin only).
var remoteUnbanCmd = &cobra.Command{
	Use:   "unban <username>",
	Short: "Unban a user account",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteUnban(args[0])
	},
}

// remoteDeleteUserCmd deletes a user and their vault from the server (admin only).
var remoteDeleteUserCmd = &cobra.Command{
	Use:   "delete-user <username>",
	Short: "Delete a user and their vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runRemoteDeleteUser(args[0])
	},
}

// runRemoteInvite creates a single-use invite code by calling the admin API.
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

// runRemoteInvites fetches and prints all invite codes from the server (admin only).
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

// runRemoteDeleteInvite revokes an invite code by its value (admin only).
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

// runRemoteUsers lists all registered users with roles and statuses (admin only).
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

// runRemoteBan bans a user account by username (admin only).
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

// runRemoteUnban removes a ban from a user account (admin only).
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

// runRemoteDeleteUser deletes a user and their vault by username (admin only).
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
