package tui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/config"
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
		screen:       screenLock,
		lockInput:    ti,
		entryList:    l,
		searchInput:  si,
		folderFilter: "",
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
