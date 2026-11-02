package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/iamgaru/netscan/internal/inventory"
)

// Clean removes terminal control characters from untrusted Nmap text.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
func HostText(h inventory.Host) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s  [%s]\n", h.IP, h.Status)
	if len(h.Hostnames) > 0 {
		fmt.Fprintf(&b, "  Hostnames: %s\n", Clean(strings.Join(h.Hostnames, ", ")))
	}
	if h.MAC != "" {
		fmt.Fprintf(&b, "  MAC: %s  %s\n", Clean(h.MAC), Clean(h.Vendor))
	}
	for _, o := range h.OSMatches {
		fmt.Fprintf(&b, "  OS estimate: %s (%d%% accuracy)\n", Clean(o.Name), o.Accuracy)
	}
	if len(h.OSMatches) == 0 {
		fmt.Fprintln(&b, "  OS: not detected or not scanned")
	}
	if h.LatencyMicros > 0 {
		fmt.Fprintf(&b, "  Latency: %.2f ms\n", float64(h.LatencyMicros)/1000)
	}
	if h.Duration > 0 {
		fmt.Fprintf(&b, "  Inspection: %s\n", h.Duration.Round(1e6))
	}
	if h.Error != "" {
		fmt.Fprintf(&b, "  Scan incomplete: %s\n", Clean(h.Error))
	}
	if len(h.Ports) == 0 {
		if h.Status == "scanned" {
			fmt.Fprintln(&b, "  No open TCP ports found in scanned range")
		} else {
			fmt.Fprintln(&b, "  Scan incomplete; ports not determined")
		}
	} else {
		w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  PORT\tSTATE\tSERVICE\tVERSION")
		for _, p := range h.Ports {
			service := p.Service
			if service == "" {
				service = "unknown"
			}
			detail := strings.TrimSpace(strings.Join([]string{p.Product, p.Version, p.Extra}, " "))
			if p.Confidence != nil {
				detail += fmt.Sprintf(" (service confidence %d/10)", *p.Confidence)
			}
			fmt.Fprintf(w, "  %d/%s\t%s\t%s\t%s\n", p.Number, Clean(p.Protocol), Clean(p.State), Clean(service), Clean(detail))
			for _, s := range p.Scripts {
				fmt.Fprintf(w, "    NSE %s: %s\n", Clean(s.ID), Clean(s.Output))
			}
		}
		w.Flush()
	}
	states := make([]string, 0, len(h.OtherStates))
	for k := range h.OtherStates {
		states = append(states, k)
	}
	sort.Strings(states)
	for _, k := range states {
		fmt.Fprintf(&b, "  %s: %d ports\n", Clean(k), h.OtherStates[k])
	}
	for _, s := range h.Scripts {
		fmt.Fprintf(&b, "  NSE %s: %s\n", Clean(s.ID), Clean(s.Output))
	}
	return b.String()
}
func Text(w io.Writer, inv inventory.Inventory) error {
	return textReport(w, inv, 0)
}

func textReport(w io.Writer, inv inventory.Inventory, width int) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "NETSCAN  %s\nProfile: %s | TCP ports: %s\nStarted: %s | Elapsed: %s\nDiscovered up: %d\n\n", inv.CIDR, inv.Profile, inv.Ports, inv.StartedAt.Format("2006-01-02 15:04:05 MST"), inv.EndedAt.Sub(inv.StartedAt).Round(1e6), len(inv.Hosts))
	open, complete, partial := 0, 0, 0
	for _, h := range inv.Hosts {
		b.WriteString(HostText(h))
		b.WriteByte('\n')
		open += len(h.Ports)
		if h.Status == "scanned" {
			complete++
		} else {
			partial++
		}
	}
	b.WriteString(summaryText(inv, width))
	fmt.Fprintf(&b, "\nSummary: %d completed, %d partial/failed, %d open ports\n", complete, partial, open)
	for _, e := range inv.Errors {
		fmt.Fprintf(&b, "Error: %s\n", Clean(e))
	}
	if partial > 0 {
		fmt.Fprintln(&b, "For incomplete hosts, retry their IP with --host-timeout 240s or --profile quick.")
	}
	fmt.Fprintln(&b, "Nonresponding hosts were not discovered as up. Services are not process lists.")
	_, err := w.Write(b.Bytes())
	return err
}
func JSON(w io.Writer, inv inventory.Inventory) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(inv)
}

var page = template.Must(template.New("report").Funcs(template.FuncMap{"host": HostText}).Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>netscan inventory</title><style>body{font:16px system-ui;background:#101820;color:#e8f1f5;max-width:1100px;margin:2rem auto;padding:1rem}h1{color:#6ddbd2}input{padding:.7rem;width:90%;margin:1rem 0}details{background:#1c2a35;margin:.7rem 0;padding:1rem;border-radius:8px}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}.error{color:#ffbc80}</style><h1>NETSCAN · {{.CIDR}}</h1><p>{{.Profile}} · TCP ports: {{.Ports}} · {{len .Hosts}} discovered hosts</p><p>{{.StartedAt}} — {{.EndedAt}}</p>{{range .Errors}}<p class="error">{{.}}</p>{{end}}<label>Filter hosts <input id="filter" placeholder="IP, hostname, service, port…" type="search"></label>{{range .Hosts}}<details><summary>{{.IP}} · {{.Status}} · {{len .Ports}} open ports {{.Vendor}}</summary><pre>{{host .}}</pre></details>{{end}}<p>OS matches are estimates. Services are not process lists. Nonresponding hosts were not discovered as up.</p><script>document.getElementById('filter').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('details').forEach(d=>d.hidden=!d.textContent.toLowerCase().includes(q))});</script></html>`))

func HTML(w io.Writer, inv inventory.Inventory) error { return page.Execute(w, inv) }
func Save(dir, formats string, raw bool, inv inventory.Inventory) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	paths := []string{}
	writers := map[string]func(io.Writer, inventory.Inventory) error{"text": Text, "json": JSON, "html": HTML}
	for _, format := range strings.Split(formats, ",") {
		fn, ok := writers[format]
		if !ok {
			return paths, fmt.Errorf("unknown format %q", format)
		}
		ext := format
		if ext == "text" {
			ext = "txt"
		}
		var b bytes.Buffer
		if err := fn(&b, inv); err != nil {
			return paths, err
		}
		path := filepath.Join(dir, "report."+ext)
		if err := atomicWrite(path, b.Bytes()); err != nil {
			return paths, err
		}
		paths = append(paths, path)
	}
	if raw {
		for _, h := range inv.Hosts {
			if h.RawXML == "" {
				continue
			}
			path := filepath.Join(dir, h.IP+".xml")
			if err := atomicWrite(path, []byte(h.RawXML)); err != nil {
				return paths, err
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}
func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".netscan-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
