package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/iamgaru/netscan/internal/inventory"
	"github.com/iamgaru/netscan/internal/report"
	"github.com/iamgaru/netscan/internal/scanner"
)

type Done struct{ Inventory inventory.Inventory }
type tick time.Time
type Model struct {
	Target, Profile                                   string
	Events                                            <-chan scanner.Event
	Results                                           <-chan inventory.Inventory
	Cancel                                            context.CancelFunc
	Hosts                                             []inventory.Host
	Active                                            map[string]bool
	Phase                                             string
	Started                                           time.Time
	Total, Completed, Selected, Offset, Width, Height int
	Detail, Confirm, Finished, NoColor                bool
	Inventory                                         inventory.Inventory
}

func New(target, profile string, events <-chan scanner.Event, results <-chan inventory.Inventory, cancel context.CancelFunc, noColor bool) Model {
	return Model{Target: target, Profile: profile, Events: events, Results: results, Cancel: cancel, Active: map[string]bool{}, Phase: "discovery", Started: time.Now(), Width: 80, Height: 24, NoColor: noColor}
}
func (m Model) wait() tea.Cmd {
	return func() tea.Msg {
		select {
		case e, ok := <-m.Events:
			if !ok {
				return Done{<-m.Results}
			}
			return e
		}
	}
}
func pulse() tea.Cmd          { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tick(t) }) }
func (m Model) Init() tea.Cmd { return tea.Batch(m.wait(), pulse()) }
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case Done:
		m.Inventory = v.Inventory
		m.Finished = true
		return m, tea.Quit
	case tick:
		return m, pulse()
	case tea.WindowSizeMsg:
		m.Width = v.Width
		m.Height = v.Height
	case scanner.Event:
		if v.Phase != "diagnostic" {
			m.Phase = v.Phase
		}
		if v.Total > 0 {
			m.Total = v.Total
		}
		if v.Phase == "active" {
			m.Active[v.Host.IP] = true
		}
		if v.Phase == "completed" {
			delete(m.Active, v.Host.IP)
			m.Completed = v.Completed
		}
		if v.Host.IP != "" {
			found := false
			for i := range m.Hosts {
				if m.Hosts[i].IP == v.Host.IP {
					m.Hosts[i] = v.Host
					found = true
				}
			}
			if !found {
				m.Hosts = append(m.Hosts, v.Host)
			}
		}
		return m, m.wait()
	case tea.KeyMsg:
		key := v.String()
		if key == "ctrl+c" {
			m.Cancel()
			m.Phase = "cancelling"
			return m, nil
		}
		if m.Confirm {
			if key == "y" {
				m.Cancel()
				m.Phase = "cancelling"
				m.Confirm = false
			}
			if key == "n" || key == "esc" {
				m.Confirm = false
			}
			return m, nil
		}
		switch key {
		case "q":
			m.Confirm = true
		case "enter":
			m.Detail = true
			m.Offset = 0
		case "esc":
			m.Detail = false
			m.Offset = 0
		case "up", "k":
			if m.Detail {
				m.Offset = max(0, m.Offset-1)
			} else {
				m.Selected = max(0, m.Selected-1)
			}
		case "down", "j":
			if m.Detail && len(m.Hosts) > 0 {
				wrapped := lipgloss.NewStyle().Width(max(10, m.Width-2)).Render(report.HostText(m.Hosts[m.Selected]))
				m.Offset = min(m.Offset+1, max(0, len(strings.Split(wrapped, "\n"))-max(1, m.Height-9)))
			} else {
				m.Selected = min(max(0, len(m.Hosts)-1), m.Selected+1)
			}
		}
	}
	return m, nil
}
func (m Model) View() string {
	width := max(10, m.Width-2)
	bodyHeight := max(1, m.Height-9)
	header := fmt.Sprintf("NETSCAN  %s  [%s]", m.Target, m.Profile)
	if !m.NoColor {
		header = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).Render(header)
	}
	active := []string{}
	for ip := range m.Active {
		active = append(active, ip)
	}
	sort.Strings(active)
	failures, open := 0, 0
	for _, h := range m.Hosts {
		open += len(h.Ports)
		if h.Status == "failed" || h.Status == "partial" {
			failures++
		}
	}
	lines := []string{}
	if m.Detail && len(m.Hosts) > 0 {
		// Wrap details before paging so every service and script remains accessible.
		wrapped := lipgloss.NewStyle().Width(width).Render(report.HostText(m.Hosts[m.Selected]))
		lines = strings.Split(wrapped, "\n")
		offset := min(m.Offset, max(0, len(lines)-bodyHeight))
		lines = lines[offset:min(len(lines), offset+bodyHeight)]
	} else {
		start := max(0, m.Selected-bodyHeight+1)
		for i := start; i < min(len(m.Hosts), start+bodyHeight); i++ {
			h := m.Hosts[i]
			marker := " "
			if i == m.Selected {
				marker = ">"
			}
			name := strings.Join(h.Hostnames, ",")
			if name == "" {
				name = h.Vendor
			}
			if len(h.OSMatches) > 0 {
				name += " · " + h.OSMatches[0].Name
			}
			lines = append(lines, fmt.Sprintf("%s %-15s %-10s %d open  %s", marker, h.IP, h.Status, len(h.Ports), report.Clean(name)))
		}
	}
	for len(lines) < bodyHeight {
		lines = append(lines, "")
	}
	hint := "↑/↓ j/k select · Enter details · Esc back · q cancel"
	if m.Confirm {
		hint = "Cancel running scans? y / n"
	}
	view := fmt.Sprintf("%s\n%s · %s elapsed\nHosts: %d · Completed: %d/%d · Errors: %d · Open ports: %d\nActive: %s\n\n%s\n\n%s", header, m.Phase, time.Since(m.Started).Round(time.Second), m.Total, m.Completed, m.Total, failures, open, strings.Join(active, ", "), strings.Join(lines, "\n"), hint)
	return lipgloss.NewStyle().MaxWidth(max(10, m.Width)).Render(view)
}
