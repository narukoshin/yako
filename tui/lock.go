package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/config"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

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

		m = m.rebuildList()
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
