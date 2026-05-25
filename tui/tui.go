package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/config"
	"github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

type screen int

const (
	screenLock screen = iota
	screenList
	screenDetail
	screenForm
	screenRemote
)

type formMode int

const (
	formAdd formMode = iota
	formEdit
)

type entryItem struct {
	entry vault.Entry
}

func (i entryItem) Title() string { return i.entry.Name }
func (i entryItem) Description() string {
	updated := i.entry.Updated
	if len(updated) > 10 {
		updated = updated[:10]
	}
	if i.entry.Username != "" {
		return i.entry.Username + " · " + updated
	}
	return updated
}
func (i entryItem) FilterValue() string { return i.entry.Name + " " + i.entry.Username }

type model struct {
	screen screen
	width  int
	height int

	masterPassword []byte
	entries        []vault.Entry

	lockInput  textinput.Model
	lockErrMsg string

	entryList list.Model

	selectedIdx int

	formMode    formMode
	formInputs  []textinput.Model
	formFocused int
	formEditIdx int

	confirmDelete bool
	confirmMsg    string

	showPassword bool
	detailMsg    string

	searchInput textinput.Model
	showSearch  bool

	remoteURL             string
	remoteToken           string
	remoteRefreshToken    string
	remoteUser            string
	remoteMsg             string
	remoteInputs          []textinput.Model
	remoteFocused         int
	remoteConfirmDelVault bool
	remoteRegister        bool
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7c3aed")).
			Padding(0, 1)

	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748b"))

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ef4444"))

	keyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7c3aed")).
			Bold(true)

	fieldStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94a3b8"))

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#e2e8f0"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748b"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#22c55e"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0ea5e9"))
)

func Start() error {
	m := initialModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	for i := range m.masterPassword {
		m.masterPassword[i] = 0
	}
	for _, e := range m.entries {
		e.Zero()
	}
	config.ClearMachineSecret()
	return err
}

func initialModel() model {
	ti := textinput.New()
	ti.Placeholder = "master password"
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 40

	si := textinput.New()
	si.Placeholder = "search..."
	si.CharLimit = 64
	si.Width = 40

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("#7c3aed")).
		BorderForeground(lipgloss.Color("#7c3aed"))
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(lipgloss.Color("#a78bfa"))

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Title = fmt.Sprintf("%s vault", config.AppName)
	l.Styles.Title = titleStyle
	l.SetShowHelp(false)
	l.DisableQuitKeybindings()

	m := model{
		screen:      screenLock,
		lockInput:   ti,
		entryList:   l,
		searchInput: si,
	}

	m.remoteURL, m.remoteToken, m.remoteRefreshToken, m.remoteUser = loadRemoteToken()
	return m
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.entryList.SetSize(msg.Width, msg.Height-4)
		return m, nil

	case healthCheckMsg:
		if msg.err != "" {
			m.remoteMsg = errStyle.Render(msg.err)
		} else {
			m.remoteMsg = successStyle.Render("Server is reachable")
		}
		return m, nil

	case accountVerifyMsg:
		if msg.valid {
			if msg.token != "" {
				m.remoteToken = msg.token
				m.saveRemoteToken()
			}
		} else {
			m.remoteURL = ""
			m.remoteToken = ""
			m.remoteRefreshToken = ""
			m.remoteUser = ""
			os.Remove(config.AppDir() + "/remote")
		}
		return m, nil

	case tea.KeyMsg:
		if m.screen == screenLock {
			return m.updateLock(msg)
		}
		if m.confirmDelete {
			return m.updateConfirmDelete(msg)
		}
		switch m.screen {
		case screenList:
			return m.updateList(msg)
		case screenDetail:
			return m.updateDetail(msg)
		case screenForm:
			return m.updateForm(msg)
		case screenRemote:
			return m.updateRemote(msg)
		}
	}

	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case screenLock:
		return m.viewLock()
	case screenList:
		return m.viewList()
	case screenDetail:
		return m.viewDetail()
	case screenForm:
		return m.viewForm()
	case screenRemote:
		return m.viewRemote()
	}
	return ""
}

func (m model) updateLock(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.lockInput, cmd = m.lockInput.Update(msg)

	if msg.Type == tea.KeyEnter {
		pw := m.lockInput.Value()
		if pw == "" {
			m.lockErrMsg = "password cannot be empty"
			return m, nil
		}

		entries, err := vault.Load([]byte(pw))
		if err != nil {
			if err == kerr.ErrNoVault {
				m.lockErrMsg = "no vault found; run 'yako vault init' first"
			} else {
				m.lockErrMsg = err.Error()
			}
			m.lockInput.SetValue("")
			return m, nil
		}

		m.masterPassword = []byte(pw)
		m.entries = entries
		m.lockErrMsg = ""

		items := make([]list.Item, len(entries))
		for i, e := range entries {
			items[i] = entryItem{entry: e}
		}
		m.entryList.SetItems(items)
		m.screen = screenList
		if m.remoteToken != "" {
			return m, doVerifyAccount(m.remoteURL, m.remoteToken, m.remoteRefreshToken)
		}
		return m, nil
	}

	if msg.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}

	return m, cmd
}

func (m model) viewLock() string {
	var b strings.Builder
	b.WriteString("\n\n\n")
	b.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(titleStyle.Render(fmt.Sprintf("🔐 Welcome to %s!", config.AppName))))
	b.WriteString("\n\n")

	if m.lockErrMsg != "" {
		b.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(errStyle.Render(m.lockErrMsg)))
		b.WriteString("\n\n")
	}

	b.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(m.lockInput.View()))
	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(subtleStyle.Render("press Enter to unlock, Ctrl+C to quit")))

	return b.String()
}

func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		m.entryList.ResetFilter()
		if m.showSearch {
			m.showSearch = false
			m.entryList.SetFilteringEnabled(false)
			return m, nil
		}
		return m, nil

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "a":
			if !m.showSearch {
				return m.initForm(formAdd, 0), nil
			}
		case "q":
			if !m.showSearch {
				return m, tea.Quit
			}
		case "/":
			if !m.showSearch {
				m.showSearch = true
				m.searchInput.Focus()
				m.entryList.SetFilteringEnabled(true)
				return m, nil
			}
		case "d":
			if !m.showSearch {
				selected := m.entryList.Index()
				if selected >= 0 && selected < len(m.entries) {
					name := m.entries[selected].Name
					m.confirmDelete = true
					m.selectedIdx = selected
					m.confirmMsg = fmt.Sprintf("Delete %q? (y/n)", name)
					return m, nil
				}
			}
		case "r":
			if !m.showSearch {
				m.screen = screenRemote
				m.remoteInputs = nil
				if m.remoteURL != "" {
					m.remoteMsg = infoStyle.Render("Checking server...")
					return m, doHealthCheck(m.remoteURL)
				}
				return m, nil
			}
		}

	case tea.KeyEnter:
		if m.showSearch {
			m.showSearch = false
			m.entryList.SetFilteringEnabled(false)
			m.searchInput.Blur()
			return m, nil
		}
		selected := m.entryList.Index()
		if selected >= 0 && selected < len(m.entries) {
			m.selectedIdx = selected
			m.screen = screenDetail
			return m, nil
		}

	case tea.KeyBackspace, tea.KeyDelete:
		if m.showSearch {
			break
		}
		selected := m.entryList.Index()
		if selected >= 0 && selected < len(m.entries) {
			name := m.entries[selected].Name
			m.confirmDelete = true
			m.selectedIdx = selected
			m.confirmMsg = fmt.Sprintf("Delete %q? (y/n)", name)
			return m, nil
		}
	}

	if m.showSearch {
		_, cmd := m.entryList.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.entryList, cmd = m.entryList.Update(msg)
	return m, cmd
}

func (m model) viewList() string {
	helpText := helpStyle.Render(" [a] add  [/] search  [r] remote  [d] delete  [q] quit  [↑/↓]  [enter] view")

	confirm := ""
	if m.confirmDelete {
		confirm = "\n" + errStyle.Render(m.confirmMsg)
	}

	if m.showSearch {
		return lipgloss.JoinVertical(lipgloss.Top,
			m.entryList.View(),
			"\n",
			m.searchInput.View(),
			helpText,
			confirm,
		)
	}

	return lipgloss.JoinVertical(lipgloss.Top,
		m.entryList.View(),
		helpText,
		confirm,
	)
}

func (m model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.detailMsg = ""

	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		m.screen = screenList
		return m, nil

	case tea.KeyRunes:
		switch string(msg.Runes) {
		case "e":
			m.screen = screenForm
			m = m.initForm(formEdit, m.selectedIdx)
			return m, nil
		case "d":
			name := m.entries[m.selectedIdx].Name
			m.confirmDelete = true
			m.confirmMsg = fmt.Sprintf("Delete %q? (y/n)", name)
			return m, nil
		case "p":
			m.showPassword = !m.showPassword
			return m, nil
		case "c":
			pw := m.entries[m.selectedIdx].Password
			if err := clipboard.WriteAll(string(pw)); err != nil {
				m.detailMsg = errStyle.Render("copy failed")
			} else {
				m.detailMsg = successStyle.Render("Password copied")
				time.AfterFunc(45*time.Second, func() { clipboard.WriteAll("") })
			}
			return m, nil
		}
	}

	return m, nil
}

func (m model) viewDetail() string {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.entries) {
		return "no entry selected"
	}

	e := m.entries[m.selectedIdx]
	var b strings.Builder

	b.WriteString(titleStyle.Render("📋 " + e.Name))
	b.WriteString("\n\n")

	pwDisplay := string(e.Password)
	if !m.showPassword {
		if len(pwDisplay) > 0 {
			pwDisplay = strings.Repeat("•", len(e.Password))
		}
	}
	b.WriteString(fieldStyle.Render("Password:  "))
	b.WriteString(valueStyle.Render(pwDisplay))
	b.WriteString("\n")

	if e.Username != "" {
		b.WriteString(fieldStyle.Render("Username:  "))
		b.WriteString(valueStyle.Render(e.Username))
		b.WriteString("\n")
	}
	if e.URL != "" {
		b.WriteString(fieldStyle.Render("URL:       "))
		b.WriteString(valueStyle.Render(e.URL))
		b.WriteString("\n")
	}
	if e.Notes != "" {
		b.WriteString(fieldStyle.Render("Notes:     "))
		b.WriteString(valueStyle.Render(e.Notes))
		b.WriteString("\n")
	}

	if e.Updated != "" {
		updatedAt, err := time.Parse(time.RFC3339, e.Updated)
		if err == nil {
			label := kerr.TimeAgo(updatedAt)
			sty := successStyle
			if time.Since(updatedAt) > 30*24*time.Hour {
				sty = errStyle
			}
			b.WriteString(fieldStyle.Render("Updated:   "))
			b.WriteString(sty.Render(label))
			b.WriteString("\n")
		} else {
			b.WriteString(fieldStyle.Render("Updated:   "))
			b.WriteString(valueStyle.Render(e.Updated))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if m.confirmDelete {
		b.WriteString(errStyle.Render(m.confirmMsg))
		b.WriteString("\n\n")
	}
	if m.detailMsg != "" {
		b.WriteString(m.detailMsg)
		b.WriteString("\n")
	}
	b.WriteString(helpStyle.Render(" [c] copy  [p] show/hide  [e] edit  [d] delete  [esc] back"))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m model) initForm(mode formMode, entryIdx int) model {
	m.screen = screenForm
	m.formMode = mode
	m.formEditIdx = entryIdx

	var existing vault.Entry
	if mode == formEdit && entryIdx >= 0 && entryIdx < len(m.entries) {
		existing = m.entries[entryIdx]
	}

	var numFields int
	var placeholders, values []string
	var pwFieldIdx int

	if mode == formAdd {
		numFields = 5
		placeholders = []string{"entry name", "username", "password", "https://", "notes"}
		values = []string{"", "", "", "", ""}
		pwFieldIdx = 2
	} else {
		numFields = 4
		placeholders = []string{"username", "password", "https://", "notes"}
		values = []string{existing.Username, string(existing.Password), existing.URL, existing.Notes}
		pwFieldIdx = 1
	}

	inputs := make([]textinput.Model, numFields)
	for i := range inputs {
		ti := textinput.New()
		ti.Placeholder = placeholders[i]
		ti.SetValue(values[i])
		ti.CharLimit = 256
		ti.Width = 40
		if i == pwFieldIdx {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}

	m.formInputs = inputs
	m.formFocused = 0
	return m
}

func (m model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		if m.formMode == formAdd {
			m.screen = screenList
		} else {
			m.screen = screenDetail
		}
		return m, nil

	case tea.KeyTab:
		m.formInputs[m.formFocused].Blur()
		m.formFocused = (m.formFocused + 1) % len(m.formInputs)
		m.formInputs[m.formFocused].Focus()
		return m, nil

	case tea.KeyShiftTab:
		m.formInputs[m.formFocused].Blur()
		m.formFocused = (m.formFocused - 1 + len(m.formInputs)) % len(m.formInputs)
		m.formInputs[m.formFocused].Focus()
		return m, nil

	case tea.KeyEnter:
		if m.formMode == formAdd {
			name := m.formInputs[0].Value()
			if name == "" {
				break
			}
			if m.formInputs[2].Value() == "" {
				break
			}
			entry := vault.NewEntry(
				name,
				m.formInputs[1].Value(),
				m.formInputs[2].Value(),
				m.formInputs[3].Value(),
				m.formInputs[4].Value(),
			)
			m.entries = append(m.entries, entry)
		} else {
			if m.formInputs[1].Value() == "" {
				break
			}
			idx := m.formEditIdx
			m.entries[idx].Username = m.formInputs[0].Value()
			m.entries[idx].Password = []byte(m.formInputs[1].Value())
			m.entries[idx].URL = m.formInputs[2].Value()
			m.entries[idx].Notes = m.formInputs[3].Value()
			m.entries[idx].Updated = time.Now().UTC().Format(time.RFC3339)
		}

		if err := vault.Save(m.masterPassword, m.entries); err != nil {
			m.lockErrMsg = err.Error()
			m.screen = screenLock
			return m, nil
		}

		items := make([]list.Item, len(m.entries))
		for i, e := range m.entries {
			items[i] = entryItem{entry: e}
		}
		m.entryList.SetItems(items)

		if m.formMode == formAdd {
			m.screen = screenList
		} else {
			m.selectedIdx = m.formEditIdx
			m.screen = screenDetail
		}
		return m, nil

	case tea.KeyCtrlG:
		pwIdx := 2
		if m.formMode == formEdit {
			pwIdx = 1
		}
		pw, err := vault.GeneratePassword(24)
		if err == nil {
			m.formInputs[pwIdx].SetValue(pw)
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.formInputs[m.formFocused], cmd = m.formInputs[m.formFocused].Update(msg)
	return m, cmd
}

func (m model) viewForm() string {
	var b strings.Builder

	if m.formMode == formAdd {
		b.WriteString(titleStyle.Render("➕ Add Entry"))
	} else {
		b.WriteString(titleStyle.Render("✏️  Edit Entry"))
	}
	b.WriteString("\n\n")

	var labelNames []string
	if m.formMode == formAdd {
		labelNames = []string{"Name", "Username", "Password", "URL", "Notes"}
	} else {
		labelNames = []string{"Username", "Password", "URL", "Notes"}
	}
	for i := range m.formInputs {
		label := fieldStyle.Render(labelNames[i] + ":")
		input := m.formInputs[i].View()
		b.WriteString(fmt.Sprintf("%s %s\n", label, input))
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render(" [tab] next  [shift+tab] prev  [ctrl+g] generate  [enter] save  [esc] cancel"))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m model) updateConfirmDelete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyRunes:
		if string(msg.Runes) == "y" {
			m.entries = append(m.entries[:m.selectedIdx], m.entries[m.selectedIdx+1:]...)
			if err := vault.Save(m.masterPassword, m.entries); err != nil {
				m.lockErrMsg = err.Error()
				m.screen = screenLock
				return m, nil
			}
			items := make([]list.Item, len(m.entries))
			for i, e := range m.entries {
				items[i] = entryItem{entry: e}
			}
			m.entryList.SetItems(items)
			m.confirmDelete = false
			m.screen = screenList
			return m, nil
		}
		fallthrough
	case tea.KeyEnter, tea.KeyEscape:
		m.confirmDelete = false
		return m, nil
	}
	return m, nil
}

// ── Remote screen ──────────────────────────────────────────────────────

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

func (m model) updateRemote(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.remoteInputs != nil {
		return m.updateRemoteLogin(msg)
	}
	return m.updateRemoteHome(msg)
}

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
			if m.remoteToken == "" {
				m.remoteMsg = "not connected; login first"
				return m, nil
			}
			var pushErr error
			m, pushErr = m.remotePush()
			if pushErr != nil {
				m.remoteMsg = errStyle.Render(pushErr.Error())
			} else {
				m.remoteMsg = successStyle.Render("Vault pushed successfully")
			}
			return m, nil
		case "g":
			if m.remoteToken == "" {
				m.remoteMsg = "not connected; login first"
				return m, nil
			}
			var pullErr error
			m, pullErr = m.remotePull()
			if pullErr != nil {
				m.remoteMsg = errStyle.Render(pullErr.Error())
			} else {
				m.remoteMsg = successStyle.Render("Vault pulled successfully")
			}
			return m, nil
		case "o":
			if m.remoteToken != "" {
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
			}
			return m, nil
		case "d":
			if m.remoteToken == "" {
				m.remoteMsg = "not connected; login first"
				return m, nil
			}
			m.remoteConfirmDelVault = true
			m.remoteMsg = errStyle.Render("Delete vault from server? (y/n)")
			return m, nil
		case "y":
			if m.remoteConfirmDelVault {
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
		}
	}

	if m.remoteConfirmDelVault {
		m.remoteConfirmDelVault = false
		m.remoteMsg = ""
		return m, nil
	}

	return m, nil
}

func (m model) updateRemoteLogin(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		m.remoteInputs = nil
		m.remoteMsg = ""
		return m, nil

	case tea.KeyTab:
		m.remoteInputs[m.remoteFocused].Blur()
		m.remoteFocused = (m.remoteFocused + 1) % len(m.remoteInputs)
		m.remoteInputs[m.remoteFocused].Focus()
		return m, nil

	case tea.KeyShiftTab:
		m.remoteInputs[m.remoteFocused].Blur()
		m.remoteFocused = (m.remoteFocused - 1 + len(m.remoteInputs)) % len(m.remoteInputs)
		m.remoteInputs[m.remoteFocused].Focus()
		return m, nil

	case tea.KeyEnter:
		url := m.remoteInputs[0].Value()
		user := m.remoteInputs[1].Value()
		pass := m.remoteInputs[2].Value()
		if url == "" || user == "" || pass == "" {
			break
		}

		var (
			token        string
			refreshToken string
			err          error
		)
		if m.remoteRegister {
			code := m.remoteInputs[3].Value()
			if code == "" {
				break
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

	var cmd tea.Cmd
	m.remoteInputs[m.remoteFocused], cmd = m.remoteInputs[m.remoteFocused].Update(msg)
	return m, cmd
}

func (m model) viewRemote() string {
	if m.remoteInputs != nil {
		return m.viewRemoteLogin()
	}
	return m.viewRemoteHome()
}

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

func (m model) remotePush() (model, error) {
	data, err := os.ReadFile(config.VaultPath())
	if err != nil {
		return m, fmt.Errorf("read vault: %w", err)
	}

	resp, err := remoteRequest("PUT", apiURL(m.remoteURL, "/vault"), m.remoteToken, data)
	if err != nil {
		return m, fmt.Errorf("push: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized && m.remoteRefreshToken != "" {
		resp.Body.Close()
		m, err = m.refreshAccessToken()
		if err != nil {
			return m, err
		}
		resp, err = remoteRequest("PUT", apiURL(m.remoteURL, "/vault"), m.remoteToken, data)
		if err != nil {
			return m, fmt.Errorf("push: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return m, kerr.CleanHTTPError("push", resp.StatusCode, respBody)
	}
	return m, nil
}

func (m model) remotePull() (model, error) {
	localEntries := make([]vault.Entry, len(m.entries))
	copy(localEntries, m.entries)

	resp, err := remoteRequest("GET", apiURL(m.remoteURL, "/vault"), m.remoteToken, nil)
	if err != nil {
		return m, fmt.Errorf("pull: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized && m.remoteRefreshToken != "" {
		resp.Body.Close()
		m, err = m.refreshAccessToken()
		if err != nil {
			return m, err
		}
		resp, err = remoteRequest("GET", apiURL(m.remoteURL, "/vault"), m.remoteToken, nil)
		if err != nil {
			return m, fmt.Errorf("pull: %w", err)
		}
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
	items := make([]list.Item, len(merged))
	for i, e := range merged {
		items[i] = entryItem{entry: e}
	}
	m.entryList.SetItems(items)

	return m, nil
}

func (m model) remoteDeleteVault() (model, error) {
	resp, err := remoteRequest("DELETE", apiURL(m.remoteURL, "/account"), m.remoteToken, nil)
	if err != nil {
		return m, fmt.Errorf("delete account: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized && m.remoteRefreshToken != "" {
		resp.Body.Close()
		m, err = m.refreshAccessToken()
		if err != nil {
			return m, err
		}
		resp, err = remoteRequest("DELETE", apiURL(m.remoteURL, "/account"), m.remoteToken, nil)
		if err != nil {
			return m, fmt.Errorf("delete account: %w", err)
		}
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

type healthCheckMsg struct {
	reachable bool
	err       string
}

type accountVerifyMsg struct {
	valid bool
	token string // new token if refreshed
}

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

// ── HTTP helpers ───────────────────────────────────────────────────────

func apiURL(base, path string) string {
	return base + "/api/v1" + path
}

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
