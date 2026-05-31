package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/narukoshin/yako/v1/vault"
)

// updateList handles all key events on the list screen: add, search, folder navigation, remote sync, delete, and quitting.
func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit

	case tea.KeyEscape:
		if m.showSearch {
			m.showSearch = false
			m.searchInput.Blur()
			m.searchInput.SetValue("")
			m = m.rebuildList()
			return m, nil
		}
		if m.folderFilter != "" {
			m.folderFilter = ""
			m = m.rebuildList()
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
				m.searchInput.SetValue("")
				m = m.applySearchFilter()
				return m, nil
			}
		case "d":
			if !m.showSearch {
				items := m.entryList.Items()
				selected := m.entryList.Index()
				if selected >= 0 && selected < len(items) {
					m.confirmDelete = true
					switch item := items[selected].(type) {
					case entryItem:
						idx := m.findEntryIdx(item.entry.Name)
						if idx >= 0 {
							m.deleteFolder = false
							m.selectedIdx = idx
							m.confirmMsg = fmt.Sprintf("Delete %q? (y/n)", item.entry.Name)
							return m, nil
						}
					case folderItem:
						m.deleteFolder = true
						m.deleteFolderName = item.name
						m.confirmMsg = fmt.Sprintf("Delete folder %q and all its entries? (y/n)", item.name)
						return m, nil
					}
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
			m.searchInput.Blur()
			return m, nil
		}
		items := m.entryList.Items()
		selected := m.entryList.Index()
		if selected >= 0 && selected < len(items) {
			switch item := items[selected].(type) {
			case entryItem:
				idx := m.findEntryIdx(item.entry.Name)
				if idx >= 0 {
					m.selectedIdx = idx
					m.screen = screenDetail
					return m, nil
				}
			case folderItem:
				m.folderFilter = item.name
				m = m.rebuildList()
				return m, nil
			case backItem:
				m.folderFilter = ""
				m = m.rebuildList()
				return m, nil
			}
		}
	}

	if m.showSearch {
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		m.entryList, _ = m.entryList.Update(msg)
		m = m.applySearchFilter()
		return m, cmd
	}

	var cmd tea.Cmd
	m.entryList, cmd = m.entryList.Update(msg)
	return m, cmd
}

// viewList renders the entry/folder list with a help bar, optional folder indicator, optional search input, and optional delete confirmation.
func (m model) viewList() string {
	helpText := helpStyle.Render(" [a] add  [/] search  [r] remote  [d] delete  [q] quit  [↑/↓]  [enter] open")

	confirm := ""
	if m.confirmDelete {
		confirm = "\n" + errStyle.Render(m.confirmMsg)
	}

	folderBar := ""
	if m.folderFilter != "" {
		folderBar = infoStyle.Render("[ "+m.folderFilter+" ]") + "  " + subtleStyle.Render("[esc] back")
	}

	if m.showSearch {
		return lipgloss.JoinVertical(lipgloss.Top,
			m.entryList.View(),
			"\n",
			m.searchInput.View(),
			folderBar,
			helpText,
			confirm,
		)
	}

	return lipgloss.JoinVertical(lipgloss.Top,
		m.entryList.View(),
		folderBar,
		helpText,
		confirm,
	)
}

// buildItems constructs the list items: if a folder filter is active only entries in that folder are shown; otherwise folders are listed first then unfiled entries.
func (m model) buildItems() []list.Item {
	if m.folderFilter != "" {
		filtered := []vault.Entry{}
		for _, e := range m.entries {
			if e.Folder == m.folderFilter {
				filtered = append(filtered, e)
			}
		}
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Name < filtered[j].Name
		})
		items := make([]list.Item, len(filtered)+1)
		items[0] = backItem{}
		for i, e := range filtered {
			items[i+1] = entryItem{entry: e}
		}
		return items
	}

	folders := []string{}
	seen := map[string]bool{}
	for _, e := range m.entries {
		if e.Folder != "" && !seen[e.Folder] {
			seen[e.Folder] = true
			folders = append(folders, e.Folder)
		}
	}
	sort.Strings(folders)

	folderCounts := map[string]int{}
	for _, e := range m.entries {
		if e.Folder != "" {
			folderCounts[e.Folder]++
		}
	}

	items := []list.Item{}
	for _, f := range folders {
		items = append(items, folderItem{name: f, count: folderCounts[f]})
	}

	unfiled := []vault.Entry{}
	for _, e := range m.entries {
		if e.Folder == "" {
			unfiled = append(unfiled, e)
		}
	}
	sort.Slice(unfiled, func(i, j int) bool {
		return unfiled[i].Name < unfiled[j].Name
	})
	for _, e := range unfiled {
		items = append(items, entryItem{entry: e})
	}
	return items
}

// rebuildList refreshes the list widget from the current entry set, respecting any active search or folder filter.
func (m model) rebuildList() model {
	if m.showSearch {
		return m.applySearchFilter()
	}
	items := m.buildItems()
	m.entryList.SetItems(items)
	m.entryList.ResetFilter()
	return m
}

// applySearchFilter narrows the visible items to those whose FilterValue contains the search query (case-insensitive).
func (m model) applySearchFilter() model {
	query := strings.ToLower(strings.TrimSpace(m.searchInput.Value()))
	all := m.buildItems()

	if query == "" {
		m.entryList.SetItems(all)
		m.entryList.ResetFilter()
		return m
	}

	filtered := []list.Item{}
	for _, item := range all {
		fv := strings.ToLower(item.FilterValue())
		if strings.Contains(fv, query) {
			filtered = append(filtered, item)
		}
	}
	m.entryList.SetItems(filtered)
	m.entryList.ResetFilter()
	return m
}

// findEntryIdx returns the index of an entry by name, or -1 if not found.
func (m model) findEntryIdx(name string) int {
	for i, e := range m.entries {
		if e.Name == name {
			return i
		}
	}
	return -1
}

// updateConfirmDelete handles y/n confirmation for deleting an entry or an entire folder.
func (m model) updateConfirmDelete(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyRunes:
		if string(msg.Runes) == "y" {
			if m.deleteFolder {
				filtered := []vault.Entry{}
				for _, e := range m.entries {
					if e.Folder != m.deleteFolderName {
						filtered = append(filtered, e)
					}
				}
				m.entries = filtered
			} else {
				m.entries = append(m.entries[:m.selectedIdx], m.entries[m.selectedIdx+1:]...)
			}
			if err := vault.Save(m.masterPassword, m.entries); err != nil {
				m.lockErrMsg = err.Error()
				m.screen = screenLock
				return m, nil
			}
			m = m.rebuildList()
			m.confirmDelete = false
			m.deleteFolder = false
			m.screen = screenList
			return m, nil
		}
		fallthrough
	case tea.KeyEnter, tea.KeyEscape:
		m.confirmDelete = false
		m.deleteFolder = false
		return m, nil
	}
	return m, nil
}
