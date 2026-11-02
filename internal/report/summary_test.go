package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/iamgaru/netscan/internal/inventory"
)

func TestFinalSummary(t *testing.T) {
	inv := sample(t)
	inv.Hosts[0].OSMatches = append(inv.Hosts[0].OSMatches, inventory.OSMatch{Name: "Best estimate", Accuracy: 99})
	inv.Hosts = append(inv.Hosts,
		inventory.Host{IP: "10.0.3.11", Status: "failed"},
		inventory.Host{IP: "10.0.3.12", Status: "scanned"})
	var b bytes.Buffer
	if err := Text(&b, inv); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	index := strings.Index(text, "HOST SUMMARY")
	if index < strings.Index(text, "10.0.3.12  [scanned]") {
		t.Fatal("summary must follow all host details")
	}
	summary := text[index:]
	for _, want := range []string{"10.0.3.10", "10.0.3.11", "10.0.3.12", "Best estimate (99%)", "3+", "undetermined"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q", want)
		}
	}
	rows := strings.Split(SummaryText(inv), "\n")
	if fields := strings.Fields(rows[3]); len(fields) < 3 || fields[2] != "?" {
		t.Fatalf("failed scan must not imply zero open ports: %s", rows[3])
	}
	if fields := strings.Fields(rows[4]); len(fields) < 3 || fields[2] != "0" {
		t.Fatalf("successful empty scan: %s", rows[4])
	}
	coloured := (Palette{Enabled: true}).Format(summary)
	if ansi.Strip(coloured) != summary {
		t.Fatal("colours changed table alignment/content")
	}
	if !strings.Contains(coloured, "\x1b[31mfailed\x1b[0m") {
		t.Fatal("failed status lacks colour")
	}
}

func TestEmptySummary(t *testing.T) {
	if got := SummaryText(inventory.Inventory{}); !strings.Contains(got, "No hosts discovered as up.") {
		t.Fatal(got)
	}
}
