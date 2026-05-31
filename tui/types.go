package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/vault"
)

// screen identifies which view the TUI is currently showing.
type screen int

const (
	screenLock   screen = iota // master-password unlock prompt
	screenList                 // entry list / folder view
	screenDetail               // single-entry detail
	screenForm                 // add/edit form
	screenRemote               // remote server management
)

// formMode distinguishes whether the form is creating a new entry or editing an existing one.
type formMode int

const (
	formAdd  formMode = iota // creating a brand-new entry
	formEdit                 // modifying an existing entry
)

// folderItem represents a clickable folder in the list view.
type folderItem struct {
	name  string
	count int
}

func (i folderItem) Title() string       { return "[ " + i.name + " ]" }
func (i folderItem) Description() string { return fmt.Sprintf("%d entries", i.count) }
func (i folderItem) FilterValue() string { return i.name }

// backItem is a special list item that navigates up one folder level.
type backItem struct{}

func (i backItem) Title() string       { return ".." }
func (i backItem) Description() string { return "back to main screen" }
func (i backItem) FilterValue() string { return "" }

// entryItem wraps a vault.Entry for display inside the Bubble Tea list component.
type entryItem struct {
	entry vault.Entry
}

func (i entryItem) Title() string { return i.entry.Name }
func (i entryItem) Description() string {
	updated := i.entry.Updated
	if len(updated) > 10 {
		updated = updated[:10]
	}
	var parts []string
	if i.entry.Username != "" {
		parts = append(parts, i.entry.Username)
	}
	parts = append(parts, updated)
	return strings.Join(parts, " · ")
}
func (i entryItem) FilterValue() string {
	return i.entry.Name + " " + i.entry.Username + " " + i.entry.Folder
}

// model holds the entire TUI state — screens, entries, form inputs, remote-session tokens, and ui flags.
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

	confirmDelete    bool
	confirmMsg       string
	deleteFolder     bool
	deleteFolderName string

	showPassword bool
	detailMsg    string

	searchInput textinput.Model
	showSearch  bool

	folderFilter string

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

// Shared lipgloss styles used across all TUI views for consistent theming.
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

// healthCheckMsg is sent back from [doHealthCheck] to update the remote-sync screen.
type healthCheckMsg struct {
	reachable bool
	err       string
}

// accountVerifyMsg is sent back from [doVerifyAccount] carrying the account state and an optional refreshed token.
type accountVerifyMsg struct {
	valid bool
	token string
}
