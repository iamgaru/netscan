package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestTerminalPreservesReport(t *testing.T) {
	inv := sample(t)
	var plain, coloured bytes.Buffer
	if err := Text(&plain, inv); err != nil {
		t.Fatal(err)
	}
	if err := Terminal(&coloured, inv, Palette{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(coloured.String(), "\x1b[1;36m10.0.3.10\x1b[0m") {
		t.Fatal("IP should stand out")
	}
	if got := ansi.Strip(coloured.String()); got != plain.String() {
		t.Fatalf("colour changed report text or alignment:\n%s", got)
	}
	coloured.Reset()
	if err := Terminal(&coloured, inv, Palette{}); err != nil {
		t.Fatal(err)
	}
	if coloured.String() != plain.String() {
		t.Fatal("disabled colours changed plain report")
	}
}

func TestUncertainServiceAndProgress(t *testing.T) {
	p := Palette{Enabled: true}
	line := "  6668/tcp  open  irc  (service confidence 3/10)"
	if got := p.Format(line); !strings.HasPrefix(got, "\x1b[33m") || ansi.Strip(got) != line {
		t.Fatal("low-confidence service should be amber")
	}
	for _, line := range []string{"Discovering 10.0.0.0/22…", "Inspecting 2 discovered hosts (4 workers)…", "[1/2] 10.0.2.192: scanned", "10.0.2.192  [partial]"} {
		got := p.Format(line)
		if !strings.Contains(got, "\x1b[") || ansi.Strip(got) != line {
			t.Fatalf("bad progress formatting: %q", got)
		}
	}
}
