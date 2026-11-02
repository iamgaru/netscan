package report

import (
	"bytes"
	"fmt"
	"github.com/iamgaru/netscan/internal/inventory"
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

// Use more hosts than fit on one screen, and names long enough to fill the
// rightmost column in the previous renderer.
func TestLongSummaryAvoidsTerminalWrapBoundary(t *testing.T) {
	inv := sample(t)
	original := inv.Hosts[0]
	inv.Hosts = nil
	for i := 1; i <= 24; i++ {
		h := original
		h.IP = fmt.Sprintf("10.0.2.%d", i)
		h.Status = "scanned"
		h.Error = ""
		h.OSMatches = []inventory.OSMatch{{Name: "Android 10 - 11 (Linux 4.9 - 4.14) very long fingerprint", Accuracy: 100}}
		inv.Hosts = append(inv.Hosts, h)
	}
	for _, columns := range []int{80, 100, 101, 102, 103, 120} {
		text, err := terminalText(inv, Palette{Enabled: true}, columns)
		if err != nil {
			t.Fatal(err)
		}
		text = ansi.Strip(text)
		for _, line := range strings.Split(text, "\n") {
			if ansi.StringWidth(line) >= columns {
				t.Fatalf("%d columns reaches wrap boundary: %q", columns, line)
			}
		}
		summary := text[strings.Index(text, "HOST SUMMARY\n"):]
		for _, h := range inv.Hosts {
			count := 0
			for _, line := range strings.Split(summary, "\n") {
				if strings.HasPrefix(line, h.IP+" ") {
					count++
					if !strings.Contains(line, "(100%)") {
						t.Fatalf("split host row at %d: %q", columns, line)
					}
				}
			}
			if count != 1 {
				t.Fatalf("expected one row for %s at width %d, got %d", h.IP, columns, count)
			}
		}
	}
}

func TestDiagnosticsWrapAtWords(t *testing.T) {
	inv := sample(t)
	inv.Errors = []string{"10.0.0.109: inspection timed out after 2m0s; results incomplete"}
	text, err := terminalText(inv, Palette{}, 40)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "incom\nplete") || strings.Contains(text, "resu\nlts") {
		t.Fatal("split diagnostic word")
	}
	for _, word := range []string{"inspection", "incomplete", "timed", "after"} {
		if !strings.Contains(text, word) {
			t.Fatalf("split %q", word)
		}
	}
}
