package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iamgaru/netscan/internal/cli"
	"github.com/iamgaru/netscan/internal/inventory"
	"github.com/iamgaru/netscan/internal/nmap"
)

type Event struct {
	Phase            string
	Host             inventory.Host
	Total, Completed int
	Diagnostic       string
}
type Scanner struct {
	Runner     Runner
	Privileged bool
}

func (s Scanner) Args(o cli.Options, ip string) []string {
	args := []string{"-n", "-Pn", "-oX", "-", "--host-timeout", duration(o.HostTimeout), "--max-retries", fmt.Sprint(o.Retries)}
	switch o.Profile {
	case "quick":
		args = append(args, "-sT")
	case "standard":
		args = append(args, "-sV", "--version-light")
		if s.Privileged {
			args = append(args, "-O")
		} else {
			args = append(args, "-sT")
		}
	case "aggressive":
		// -A enables privileged OS/traceroute only when Nmap has privileges.
		args = append(args, "-A", "--script-timeout", duration(o.ScriptTimeout))
		if !s.Privileged {
			args = append(args, "-sT")
		}
	}
	if o.Ports == "all" {
		args = append(args, "-p", "1-65535")
	} else if o.Ports != "default" {
		args = append(args, "-p", o.Ports)
	}
	return append(args, ip)
}
func duration(d time.Duration) string { return fmt.Sprintf("%dms", max(1, d.Milliseconds())) }
func (s Scanner) Run(ctx context.Context, o cli.Options, emit func(Event)) inventory.Inventory {
	if emit == nil {
		emit = func(Event) {}
	}
	inv := inventory.Inventory{CIDR: o.Target, Profile: o.Profile, Ports: o.Ports, StartedAt: time.Now(), Hosts: []inventory.Host{}}
	emit(Event{Phase: "discovery"})
	// Discovery also has a wall-clock bound, independent of network size.
	dctx, cancel := context.WithTimeout(ctx, o.HostTimeout)
	data, stderr, runErr := s.Runner.Run(dctx, []string{"-sn", "-n", "-oX", "-", o.Target})
	cancel()
	hosts, parseErr := nmap.Parse(bytes.NewReader(data))
	if len(stderr) > 0 {
		emit(Event{Phase: "diagnostic", Diagnostic: string(stderr)})
	}
	if runErr != nil || parseErr != nil {
		inv.Errors = append(inv.Errors, fmt.Sprintf("discovery failed: %s", errorsText(runErr, parseErr, stderr)))
		inv.EndedAt = time.Now()
		return inv
	}
	seen := map[string]bool{}
	prefix := netip.MustParsePrefix(o.Target)
	for _, h := range hosts {
		ip, err := netip.ParseAddr(h.IP)
		if err == nil && prefix.Contains(ip) && h.Status == "up" && !seen[h.IP] {
			seen[h.IP] = true
			h.Status = "discovered"
			h.Ports = []inventory.Port{}
			inv.Hosts = append(inv.Hosts, h)
		}
	}
	sort.Slice(inv.Hosts, func(i, j int) bool {
		return netip.MustParseAddr(inv.Hosts[i].IP).Less(netip.MustParseAddr(inv.Hosts[j].IP))
	})
	for _, h := range inv.Hosts {
		emit(Event{Phase: "discovered", Host: h, Total: len(inv.Hosts)})
	}
	emit(Event{Phase: "inspection", Total: len(inv.Hosts)})
	jobs := make(chan int)
	type result struct {
		index      int
		host       inventory.Host
		diagnostic string
	}
	results := make(chan result)
	var wg sync.WaitGroup
	for w := 0; w < min(o.Jobs, len(inv.Hosts)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				h := inv.Hosts[i]
				if ctx.Err() != nil {
					h.Status = "failed"
					h.Error = "cancelled before inspection"
					results <- result{i, h, ""}
					continue
				}
				emit(Event{Phase: "active", Host: h, Total: len(inv.Hosts)})
				start := time.Now()
				hctx, cancel := context.WithTimeout(ctx, o.HostTimeout)
				raw, diag, err := s.Runner.Run(hctx, s.Args(o, h.IP))
				cancel()
				parsed, pe := nmap.Parse(bytes.NewReader(raw))
				found := false
				for _, p := range parsed {
					if p.IP == h.IP {
						found = true
						if len(p.Hostnames) > 0 {
							h.Hostnames = p.Hostnames
						}
						if p.MAC != "" {
							h.MAC = p.MAC
							h.Vendor = p.Vendor
						}
						h.Ports = p.Ports
						h.OSMatches = p.OSMatches
						h.Scripts = p.Scripts
						h.OtherStates = p.OtherStates
						if p.LatencyMicros > 0 {
							h.LatencyMicros = p.LatencyMicros
						}
						if p.Error != "" && pe == nil {
							pe = fmt.Errorf("%s", p.Error)
						}
						if p.Status != "up" && pe == nil {
							pe = fmt.Errorf("inspection did not report host up")
						}
						break
					}
				}
				if !found && pe == nil {
					pe = fmt.Errorf("Nmap returned no host results; timeout possible, cause unconfirmed")
				}
				h.Duration = time.Since(start)
				h.RawXML = string(raw)
				h.Status = "scanned"
				if err != nil || pe != nil {
					h.Status = "failed"
					if found {
						h.Status = "partial"
					}
					switch {
					case errors.Is(err, context.DeadlineExceeded):
						h.Error = fmt.Sprintf("inspection timed out after %s; results incomplete", o.HostTimeout)
					case errors.Is(err, context.Canceled):
						h.Error = "inspection cancelled; results incomplete"
					default:
						h.Error = errorsText(err, pe, diag)
					}
				}
				results <- result{i, h, string(diag)}
			}
		}()
	}
	go func() {
		for i := range inv.Hosts {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	completed := 0
	for r := range results {
		inv.Hosts[r.index] = r.host
		completed++
		emit(Event{Phase: "completed", Host: r.host, Total: len(inv.Hosts), Completed: completed, Diagnostic: r.diagnostic})
	}
	if ctx.Err() != nil {
		inv.Errors = append(inv.Errors, "scan cancelled: "+ctx.Err().Error())
	}
	for _, h := range inv.Hosts {
		if h.Error != "" {
			inv.Errors = append(inv.Errors, h.IP+": "+h.Error)
		}
	}
	inv.EndedAt = time.Now()
	return inv
}
func errorsText(a, b error, diag []byte) string {
	parts := []string{}
	if a != nil {
		parts = append(parts, a.Error())
	}
	if b != nil {
		parts = append(parts, b.Error())
	}
	if len(diag) > 0 {
		parts = append(parts, strings.TrimSpace(string(diag)))
	}
	return strings.Join(parts, "; ")
}
