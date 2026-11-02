package report

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/charmbracelet/x/ansi"
	"github.com/iamgaru/netscan/internal/inventory"
)

// SummaryText keeps the final overview compact; full metadata and every detected
// port remain in the preceding host sections.
func SummaryText(inv inventory.Inventory) string {
	var b bytes.Buffer
	fmt.Fprintln(&b, "HOST SUMMARY")
	if len(inv.Hosts) == 0 {
		fmt.Fprintln(&b, "No hosts discovered as up.")
		return b.String()
	}
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tSTATUS\tOPEN\tHOSTNAME / VENDOR\tTOP OS ESTIMATE")
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
			os = fmt.Sprintf("%s (%d%%)", ansi.Truncate(Clean(best.Name), 30, "…"), best.Accuracy)
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", Clean(h.IP), Clean(h.Status), ports, ansi.Truncate(Clean(name), 26, "…"), os)
	}
	w.Flush()
	if incomplete {
		fmt.Fprintln(&b, "OPEN: ? = undetermined; + = detected so far (scan incomplete).")
	}
	return b.String()
}
