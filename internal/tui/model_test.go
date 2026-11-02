package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/iamgaru/netscan/internal/inventory"
	"github.com/iamgaru/netscan/internal/scanner"
)

func TestNavigationAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := New("10.0.0.0/24", "standard", nil, nil, cancel, true)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		v, _ := m.Update(scanner.Event{Phase: "completed", Host: inventory.Host{IP: ip, Status: "scanned"}, Total: 2})
		m = v.(Model)
	}
	v, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = v.(Model)
	if m.Selected != 1 {
		t.Fatal("navigation")
	}
	v, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = v.(Model)
	if !strings.Contains(m.View(), "10.0.0.2") || strings.Contains(m.View(), "\x1b") {
		t.Fatal("detail/color")
	}
	v, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	m = v.(Model)
	if ctx.Err() != nil || !m.Confirm {
		t.Fatal("cancelled without confirmation")
	}
	v, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	m = v.(Model)
	if ctx.Err() == nil {
		t.Fatal("did not cancel")
	}
}
