package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/kerr"
)

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
	if e.Folder != "" {
		b.WriteString(fieldStyle.Render("Folder:    "))
		b.WriteString(infoStyle.Render(e.Folder))
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
