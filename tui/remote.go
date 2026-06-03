package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/config"
	"github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

// initRemoteForm populates the remote-login or remote-register form inputs and focuses the URL field.
func (m model) initRemoteForm(register bool) model {
	m.remoteRegister = register

	numInputs := 3
	if register {
		numInputs = 4
	}
	inputs := make([]textinput.Model, numInputs)

	ti := textinput.New()
	ti.Placeholder = "https://example.com:8443"
	ti.SetValue("https://")
	ti.CharLimit = 256
	ti.Width = 40
	ti.Focus()
	inputs[0] = ti

	ti = textinput.New()
	ti.Placeholder = "username"
	ti.CharLimit = 128
	ti.Width = 40
	inputs[1] = ti

	ti = textinput.New()
	ti.Placeholder = "password"
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.CharLimit = 256
	ti.Width = 40
	inputs[2] = ti

	if register {
		ti = textinput.New()
		ti.Placeholder = "invite code"
		ti.CharLimit = 128
		ti.Width = 40
		inputs[3] = ti
	}

	m.remoteInputs = inputs
	m.remoteFocused = 0
	m.remoteMsg = ""
	return m
}

// updateRemote dispatches to the login-form handler or the home-screen handler depending on whether inputs are active.
func (m model) updateRemote(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.remoteInputs != nil {
		return m.updateRemoteLogin(msg)
	}
	return m.updateRemoteHome(msg)
}

// updateRemoteHome handles the remote-sync home screen: login, register, push, pull, logout, and delete-vault actions.
func (m model) updateRemoteHome(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		m.screen = screenList
		return m, nil

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "l":
			return m.initRemoteForm(false), nil
		case "u":
			m.remoteMsg = ""
			return m.initRemoteForm(true), nil
		case "p":
			return m.requireToken(m.handlePush)
		case "g":
			return m.requireToken(m.handlePull)
		case "o":
			return m.handleLogout()
		case "d":
			return m.requireToken(m.handleDeleteConfirm)
		case "y":
			if m.remoteConfirmDelVault {
				return m.handleDeleteVaultConfirm()
			}
		}
	}

	if m.remoteConfirmDelVault {
		m.remoteConfirmDelVault = false
		m.remoteMsg = ""
		return m, nil
	}

	return m, nil
}

// requireToken guards an action with a "not connected" message if no token is set.
func (m model) requireToken(action func() (model, tea.Cmd)) (tea.Model, tea.Cmd) {
	if m.remoteToken == "" {
		m.remoteMsg = "not connected; login first"
		return m, nil
	}
	return action()
}

func (m model) handlePush() (model, tea.Cmd) {
	var pushErr error
	m, pushErr = m.remotePush()
	if pushErr != nil {
		m.remoteMsg = errStyle.Render(pushErr.Error())
	} else {
		m.remoteMsg = successStyle.Render("Vault pushed successfully")
	}
	return m, nil
}

func (m model) handlePull() (model, tea.Cmd) {
	var pullErr error
	m, pullErr = m.remotePull()
	if pullErr != nil {
		m.remoteMsg = errStyle.Render(pullErr.Error())
	} else {
		m.remoteMsg = successStyle.Render("Vault pulled successfully")
	}
	return m, nil
}

func (m model) handleLogout() (model, tea.Cmd) {
	if m.remoteToken == "" {
		return m, nil
	}
	remoteRequest("POST", apiURL(m.remoteURL, "/auth/logout"), m.remoteToken, nil)
	if err := os.Remove(config.AppDir() + "/remote"); err != nil && !os.IsNotExist(err) {
		m.remoteMsg = errStyle.Render(fmt.Sprintf("failed to remove saved credentials: %v", err))
		return m, nil
	}
	m.remoteURL = ""
	m.remoteToken = ""
	m.remoteRefreshToken = ""
	m.remoteUser = ""
	m.remoteMsg = successStyle.Render("Logged out")
	return m, nil
}

func (m model) handleDeleteConfirm() (model, tea.Cmd) {
	m.remoteConfirmDelVault = true
	m.remoteMsg = errStyle.Render("Delete vault from server? (y/n)")
	return m, nil
}

func (m model) handleDeleteVaultConfirm() (model, tea.Cmd) {
	m.remoteConfirmDelVault = false
	var delErr error
	m, delErr = m.remoteDeleteVault()
	if delErr != nil {
		m.remoteMsg = errStyle.Render(delErr.Error())
	} else {
		m.remoteMsg = successStyle.Render("Account and vault deleted from server")
	}
	return m, nil
}

// updateRemoteLogin handles tab navigation and submission of the remote login/register form.
func (m model) updateRemoteLogin(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		m.remoteInputs = nil
		m.remoteMsg = ""
		return m, nil

	case tea.KeyTab:
		return m.advanceFocus(1), nil

	case tea.KeyShiftTab:
		return m.advanceFocus(-1), nil

	case tea.KeyEnter:
		return m.submitRemoteForm()

	default:
		var cmd tea.Cmd
		m.remoteInputs[m.remoteFocused], cmd = m.remoteInputs[m.remoteFocused].Update(msg)
		return m, cmd
	}
}

// advanceFocus moves the focus by delta (+1 or -1), wrapping around the input fields.
func (m model) advanceFocus(delta int) model {
	m.remoteInputs[m.remoteFocused].Blur()
	count := len(m.remoteInputs)
	m.remoteFocused = (m.remoteFocused + delta + count) % count
	m.remoteInputs[m.remoteFocused].Focus()
	return m
}

// submitRemoteForm handles the login or register form submission.
func (m model) submitRemoteForm() (tea.Model, tea.Cmd) {
	url := m.remoteInputs[0].Value()
	user := m.remoteInputs[1].Value()
	pass := m.remoteInputs[2].Value()
	if url == "" || user == "" || pass == "" {
		return m, nil
	}

	var (
		token        string
		refreshToken string
		err          error
	)
	if m.remoteRegister {
		code := m.remoteInputs[3].Value()
		if code == "" {
			return m, nil
		}
		token, refreshToken, err = remoteRegister(url, user, pass, code)
	} else {
		token, refreshToken, err = remoteLogin(url, user, pass)
	}
	if err != nil {
		m.remoteMsg = errStyle.Render(err.Error())
		return m, nil
	}

	m.remoteURL = url
	m.remoteToken = token
	m.remoteRefreshToken = refreshToken
	m.remoteUser = user
	m.remoteInputs = nil
	action := "Connected"
	if m.remoteRegister {
		action = "Registered and connected"
	}
	m.remoteMsg = successStyle.Render(fmt.Sprintf("%s as %s", action, user))
	if err := m.saveRemoteToken(); err != nil {
		m.remoteMsg = errStyle.Render(fmt.Sprintf("Connected but failed to save credentials: %v", err))
	}
	return m, nil
}

// viewRemote renders either the login form or the home screen depending on whether inputs are active.
func (m model) viewRemote() string {
	if m.remoteInputs != nil {
		return m.viewRemoteLogin()
	}
	return m.viewRemoteHome()
}

// viewRemoteHome renders the remote-sync dashboard showing connection status, server info, and action buttons.
func (m model) viewRemoteHome() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🌐 Remote Sync"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", m.width))
	b.WriteString("\n\n")

	if m.remoteToken == "" {
		b.WriteString(infoStyle.Render("Not connected to any server."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [l] Login  [u] Register"))
	} else {
		b.WriteString(fieldStyle.Render("Server: "))
		b.WriteString(valueStyle.Render(m.remoteURL))
		b.WriteString("\n")
		b.WriteString(fieldStyle.Render("User:   "))
		b.WriteString(valueStyle.Render(m.remoteUser))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [p] Push vault  [g] Pull vault  [d] Delete vault  [o] Logout"))
	}

	b.WriteString("\n\n")
	if m.remoteMsg != "" {
		b.WriteString(m.remoteMsg)
		b.WriteString("\n\n")
	}
	b.WriteString(helpStyle.Render(" [esc] Back to vault"))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

// viewRemoteLogin renders the server URL, username, password, and optional invite-code fields.
func (m model) viewRemoteLogin() string {
	var b strings.Builder

	if m.remoteRegister {
		b.WriteString(titleStyle.Render("📝 Remote Register"))
	} else {
		b.WriteString(titleStyle.Render("🔑 Remote Login"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", m.width))
	b.WriteString("\n\n")

	labels := []string{"Server URL", "Username", "Password"}
	if m.remoteRegister {
		labels = append(labels, "Invite Code")
	}
	for i := range m.remoteInputs {
		label := fieldStyle.Render(labels[i] + ":")
		input := m.remoteInputs[i].View()
		b.WriteString(fmt.Sprintf("%s %s\n", label, input))
	}

	if m.remoteMsg != "" {
		b.WriteString("\n")
		b.WriteString(m.remoteMsg)
	}

	action := "login"
	if m.remoteRegister {
		action = "register"
	}
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render(fmt.Sprintf(" [tab] next  [shift+tab] prev  [enter] %s  [esc] cancel", action)))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

// doAuthRequest performs an authenticated HTTP request, automatically refreshing the token
// on a 401 response.
func (m model) doAuthRequest(method, url string, body []byte) (*http.Response, model, error) {
	resp, err := remoteRequest(method, url, m.remoteToken, body)
	if err != nil {
		return nil, m, err
	}

	if resp.StatusCode == http.StatusUnauthorized && m.remoteRefreshToken != "" {
		resp.Body.Close()
		m, err = m.refreshAccessToken()
		if err != nil {
			return nil, m, err
		}
		resp, err = remoteRequest(method, url, m.remoteToken, body)
		if err != nil {
			return nil, m, err
		}
	}
	return resp, m, nil
}

// remotePush uploads the local vault file to the server; retries with a refreshed token on 401.
func (m model) remotePush() (model, error) {
	data, err := os.ReadFile(config.VaultPath())
	if err != nil {
		return m, fmt.Errorf("read vault: %w", err)
	}

	resp, m, err := m.doAuthRequest("PUT", apiURL(m.remoteURL, "/vault"), data)
	if err != nil {
		return m, fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return m, kerr.CleanHTTPError("push", resp.StatusCode, respBody)
	}
	return m, nil
}

// remotePull downloads the server vault, merges it with local entries via [vault.MergeEntries], and saves the result.
func (m model) remotePull() (model, error) {
	localEntries := make([]vault.Entry, len(m.entries))
	copy(localEntries, m.entries)

	resp, m, err := m.doAuthRequest("GET", apiURL(m.remoteURL, "/vault"), nil)
	if err != nil {
		return m, fmt.Errorf("pull: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return m, fmt.Errorf("no vault on server")
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return m, kerr.CleanHTTPError("pull", resp.StatusCode, respBody)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return m, fmt.Errorf("read response: %w", err)
	}

	tmpPath := config.VaultPath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return m, fmt.Errorf("write temp vault: %w", err)
	}
	defer os.Remove(tmpPath)

	serverEntries, err := vault.LoadPath(tmpPath, m.masterPassword)
	if err != nil {
		return m, fmt.Errorf("server vault is incompatible: %w", err)
	}

	merged := vault.MergeEntries(localEntries, serverEntries)

	if err := vault.Save(m.masterPassword, merged); err != nil {
		return m, fmt.Errorf("save merged vault: %w", err)
	}

	m.entries = merged
	m = m.rebuildList()

	return m, nil
}

// remoteDeleteVault deletes the user's account and vault from the server and clears local saved credentials.
func (m model) remoteDeleteVault() (model, error) {
	resp, m, err := m.doAuthRequest("DELETE", apiURL(m.remoteURL, "/account"), nil)
	if err != nil {
		return m, fmt.Errorf("delete account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return m, kerr.CleanHTTPError("delete account", resp.StatusCode, respBody)
	}

	m.remoteURL = ""
	m.remoteToken = ""
	m.remoteRefreshToken = ""
	m.remoteUser = ""

	if err := os.Remove(config.AppDir() + "/remote"); err != nil && !os.IsNotExist(err) {
		return m, fmt.Errorf("remove credentials: %w", err)
	}

	return m, nil
}

// loadRemoteToken reads and decrypts the persisted remote session file, returning the stored server URL, tokens, and username.
func loadRemoteToken() (serverURL, token, refreshToken, username string) {
	data, err := os.ReadFile(config.AppDir() + "/remote")
	if err != nil {
		return "", "", "", ""
	}
	decrypted, err := crypto.Decrypt(config.MachineSecret(), data)
	if err != nil {
		return "", "", "", ""
	}
	var rc struct {
		ServerURL    string `json:"server_url"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Username     string `json:"username,omitempty"`
	}
	if json.Unmarshal(decrypted, &rc) != nil || rc.ServerURL == "" {
		return "", "", "", ""
	}
	return rc.ServerURL, rc.Token, rc.RefreshToken, rc.Username
}

// saveRemoteToken encrypts the current remote session and persists it to disk under the app directory.
func (m model) saveRemoteToken() error {
	rc := struct {
		ServerURL    string `json:"server_url"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Username     string `json:"username,omitempty"`
	}{
		ServerURL:    m.remoteURL,
		Token:        m.remoteToken,
		RefreshToken: m.remoteRefreshToken,
		Username:     m.remoteUser,
	}

	data, err := json.Marshal(rc)
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(config.MachineSecret(), data)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(config.AppDir()+"/remote", encrypted, 0600)
}

// refreshAccessToken exchanges the stored refresh token for a new access token and persists it.
func (m model) refreshAccessToken() (model, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": m.remoteRefreshToken})
	resp, err := http.Post(apiURL(m.remoteURL, "/auth/refresh"), "application/json", bytes.NewReader(body))
	if err != nil {
		return m, fmt.Errorf("refresh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return m, kerr.CleanHTTPError("refresh token", resp.StatusCode, respBody)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return m, fmt.Errorf("parse refresh response: %w", err)
	}

	m.remoteToken = result.Token
	if err := m.saveRemoteToken(); err != nil {
		return m, fmt.Errorf("save refreshed token: %w", err)
	}
	return m, nil
}

// doHealthCheck returns a tea.Cmd that pings the server's /health endpoint and sends a [healthCheckMsg] back.
func doHealthCheck(url string) tea.Cmd {
	return func() tea.Msg {
		resp, err := http.Get(apiURL(url, "/health"))
		if err != nil {
			return healthCheckMsg{err: fmt.Sprintf("server unreachable: %v", err)}
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return healthCheckMsg{reachable: true}
		}
		return healthCheckMsg{err: fmt.Sprintf("server unhealthy (HTTP %d)", resp.StatusCode)}
	}
}

// doVerifyAccount returns a tea.Cmd that verifies the remote account is still valid (HEAD /vault) and attempts a token refresh on 401.
func doVerifyAccount(url, token, refreshToken string) tea.Cmd {
	return func() tea.Msg {
		req, _ := http.NewRequest("HEAD", apiURL(url, "/vault"), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return accountVerifyMsg{false, ""}
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
			return accountVerifyMsg{true, ""}
		}

		if resp.StatusCode == http.StatusUnauthorized && refreshToken != "" {
			body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
			refreshResp, err := http.Post(apiURL(url, "/auth/refresh"), "application/json", bytes.NewReader(body))
			if err != nil {
				return accountVerifyMsg{false, ""}
			}
			defer refreshResp.Body.Close()
			if refreshResp.StatusCode == http.StatusOK {
				var result struct {
					Token string `json:"token"`
				}
				if json.NewDecoder(refreshResp.Body).Decode(&result) == nil {
					return accountVerifyMsg{true, result.Token}
				}
			}
		}

		return accountVerifyMsg{false, ""}
	}
}

// apiURL constructs a full server API URL by appending /api/v1 to the given base.
func apiURL(base, path string) string {
	return base + "/api/v1" + path
}

// remoteRequest creates and executes an HTTP request with an optional Bearer token and JSON content-type for non-nil bodies.
func remoteRequest(method, url, token string, body []byte) (*http.Response, error) {
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

// remoteRegister creates a new account on the remote server with an invite code and returns the access and refresh tokens.
func remoteRegister(serverURL, username, password, inviteCode string) (string, string, error) {
	body, _ := json.Marshal(map[string]string{
		"username":    username,
		"password":    password,
		"invite_code": inviteCode,
	})

	resp, err := http.Post(apiURL(serverURL, "/auth/register"), "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", kerr.CleanHTTPError("register", resp.StatusCode, respBody)
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}
	return result.Token, result.RefreshToken, nil
}

// remoteLogin authenticates against the remote server and returns an access token and a refresh token.
func remoteLogin(serverURL, username, password string) (string, string, error) {
	reqBody, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := remoteRequest("POST", apiURL(serverURL, "/auth/login"), "", reqBody)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", "", kerr.CleanHTTPError("login", resp.StatusCode, respBody)
	}

	var result struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}
	return result.Token, result.RefreshToken, nil
}
