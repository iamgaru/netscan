package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/iamgaru/netscan/internal/inventory"
)

// SummaryText keeps the final overview compact; full metadata and every detected
// port remain in the preceding host sections.
func SummaryText(inv inventory.Inventory) string { return summaryText(inv, 0) }

func summaryText(inv inventory.Inventory, width int) string {
	var b bytes.Buffer
	fmt.Fprintln(&b, "HOST SUMMARY")
	if len(inv.Hosts) == 0 {
		fmt.Fprintln(&b, "No hosts discovered as up.")
		return b.String()
	}
	nameWidth, osWidth := 26, 37
	compact := width > 0 && width < 64
	if compact {
		nameWidth = max(1, width-2)
		osWidth = max(8, width-6)
	}
	if width >= 64 {
		available := width - 39 // IP, status, count, and four two-space separators.
		nameWidth = min(26, available*2/5)
		osWidth = min(37, available-nameWidth)
	}
	row := func(ip, status, ports, name, os string) {
		if compact {
			fmt.Fprintf(&b, "%s  [%s]  OPEN %s\n", ip, status, ports)
			fmt.Fprintf(&b, "  %s\n  OS: %s\n", name, os)
			return
		}
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s\n", pad(ip, 15), pad(status, 10), pad(ports, 6), pad(name, nameWidth), os)
	}
	if !compact {
		row("IP", "STATUS", "OPEN", "HOSTNAME / VENDOR", "TOP OS ESTIMATE")
	}
	incomplete := false
	for _, h := range inv.Hosts {
		name := strings.Join(h.Hostnames, ", ")
		if name == "" {
			name = h.Vendor
		} else if h.Vendor != "" {
			name += " / " + h.Vendor
		}
		if name == "" {
			name = "-"
		}
		os := "not detected"
		if len(h.OSMatches) > 0 {
			best := h.OSMatches[0]
			for _, match := range h.OSMatches[1:] {
				if match.Accuracy > best.Accuracy {
					best = match
				}
			}
			confidence := fmt.Sprintf(" (%d%%)", best.Accuracy)
			os = ansi.Truncate(Clean(best.Name), osWidth-ansi.StringWidth(confidence), "…") + confidence
		}
		ports := fmt.Sprint(len(h.Ports))
		if h.Status != "scanned" {
			incomplete = true
			if len(h.Ports) == 0 {
				ports = "?"
			} else {
				ports += "+"
			}
		}
		row(Clean(h.IP), Clean(h.Status), ports, ansi.Truncate(Clean(name), nameWidth, "…"), os)
	}
	if incomplete {
		fmt.Fprintln(&b, "OPEN: ? = undetermined; + = detected so far (scan incomplete).")
	}
	text := b.String()
	if width > 0 {
		text = ansi.Hardwrap(text, width, true)
	}
	return text
}

// Pad by terminal cells, not bytes or runes (vendors may contain wide Unicode).
func pad(s string, width int) string {
	s = ansi.Truncate(s, width, "…")
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidth(s)))
}
