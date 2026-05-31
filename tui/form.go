package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/vault"
)

// formFieldDef describes one field in the add/edit form: its label, placeholder, whether it's password-masked, and getter/setter accessors.
type formFieldDef struct {
	label       string
	placeholder string
	isPassword  bool
	addOnly     bool
	get         func(vault.Entry) string
	set         func(*vault.Entry, string)
}

// formFields defines the six entry fields: Name, Username, Password, URL, Notes, Folder.
var formFields = []formFieldDef{
	{label: "Name", placeholder: "entry name",
		get: func(e vault.Entry) string { return e.Name },
		set: func(e *vault.Entry, v string) { e.Name = v }},
	{label: "Username", placeholder: "username",
		get: func(e vault.Entry) string { return e.Username },
		set: func(e *vault.Entry, v string) { e.Username = v }},
	{label: "Password", placeholder: "password", isPassword: true,
		get: func(e vault.Entry) string { return string(e.Password) },
		set: func(e *vault.Entry, v string) { e.Password = []byte(v) }},
	{label: "URL", placeholder: "https://",
		get: func(e vault.Entry) string { return e.URL },
		set: func(e *vault.Entry, v string) { e.URL = v }},
	{label: "Notes", placeholder: "notes",
		get: func(e vault.Entry) string { return e.Notes },
		set: func(e *vault.Entry, v string) { e.Notes = v }},
	{label: "Folder", placeholder: "folder",
		get: func(e vault.Entry) string { return e.Folder },
		set: func(e *vault.Entry, v string) { e.Folder = v }},
}

// activeFormFields returns the form fields relevant to the current mode (add-only fields are excluded during edit).
func (m model) activeFormFields() []formFieldDef {
	var fields []formFieldDef
	for _, f := range formFields {
		if m.formMode == formEdit && f.addOnly {
			continue
		}
		fields = append(fields, f)
	}
	return fields
}

// initForm populates the form inputs with existing values (edit) or blanks (add) and focuses the first field.
func (m model) initForm(mode formMode, entryIdx int) model {
	m.screen = screenForm
	m.formMode = mode
	m.formEditIdx = entryIdx

	var existing vault.Entry
	if mode == formEdit && entryIdx >= 0 && entryIdx < len(m.entries) {
		existing = m.entries[entryIdx]
	}

	inputs := []textinput.Model{}
	inputIdx := 0
	for _, f := range formFields {
		if mode == formEdit && f.addOnly {
			continue
		}
		ti := textinput.New()
		ti.Placeholder = f.placeholder
		ti.CharLimit = 256
		ti.Width = 40
		if f.isPassword {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		if mode == formEdit {
			ti.SetValue(f.get(existing))
		} else if f.label == "Folder" && m.folderFilter != "" {
			ti.SetValue(m.folderFilter)
		}
		if inputIdx == 0 {
			ti.Focus()
		}
		inputs = append(inputs, ti)
		inputIdx++
	}

	m.formInputs = inputs
	m.formFocused = 0
	return m
}

// updateForm handles form navigation (tab/shift+tab), password generation (ctrl+g), save (enter), and cancel (esc).
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
		fields := m.activeFormFields()
		pwIdx := -1
		for i, f := range fields {
			if f.isPassword {
				pwIdx = i
				break
			}
		}

		if m.formMode == formAdd && m.formInputs[0].Value() == "" {
			break
		}
		if pwIdx >= 0 && m.formInputs[pwIdx].Value() == "" {
			break
		}

		if m.formMode == formAdd {
			entry := vault.Entry{}
			entry.Created = time.Now().UTC().Format(time.RFC3339)
			entry.Updated = entry.Created
			for i, f := range fields {
				f.set(&entry, m.formInputs[i].Value())
			}
			entry.ID = entry.Name
			m.entries = append(m.entries, entry)
		} else {
			idx := m.formEditIdx
			for i, f := range fields {
				f.set(&m.entries[idx], m.formInputs[i].Value())
			}
			m.entries[idx].Updated = time.Now().UTC().Format(time.RFC3339)
		}

		if err := vault.Save(m.masterPassword, m.entries); err != nil {
			m.lockErrMsg = err.Error()
			m.screen = screenLock
			return m, nil
		}

		for i, f := range fields {
			if f.isPassword {
				m.formInputs[i].SetValue("")
				m.formInputs[i].Reset()
				break
			}
		}

		m = m.rebuildList()

		if m.formMode == formAdd {
			m.screen = screenList
		} else {
			m.selectedIdx = m.formEditIdx
			m.screen = screenDetail
		}
		return m, nil

	case tea.KeyCtrlG:
		fields := m.activeFormFields()
		for i, f := range fields {
			if f.isPassword {
				pw, err := vault.GeneratePassword(24)
				if err == nil {
					m.formInputs[i].SetValue(pw)
				}
				break
			}
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.formInputs[m.formFocused], cmd = m.formInputs[m.formFocused].Update(msg)
	return m, cmd
}

// viewForm renders the form title (Add/Edit) and all input fields with their current values.
func (m model) viewForm() string {
	var b strings.Builder

	if m.formMode == formAdd {
		b.WriteString(titleStyle.Render("➕ Add Entry"))
	} else {
		b.WriteString(titleStyle.Render("✏️  Edit Entry"))
	}
	b.WriteString("\n\n")

	fields := m.activeFormFields()
	for i := range m.formInputs {
		label := fieldStyle.Render(fields[i].label + ":")
		input := m.formInputs[i].View()
		b.WriteString(fmt.Sprintf("%s %s\n", label, input))
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render(" [tab] next  [shift+tab] prev  [ctrl+g] generate  [enter] save  [esc] cancel"))

	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}
