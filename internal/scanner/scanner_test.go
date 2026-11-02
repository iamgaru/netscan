package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iamgaru/netscan/internal/cli"
)

type fakeRunner struct {
	mu           sync.Mutex
	calls        [][]string
	active, peak int
	hang         bool
	discovery    []byte
}

func (f *fakeRunner) Run(ctx context.Context, args []string) ([]byte, []byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{}, args...))
	if args[0] == "-sn" {
		data := f.discovery
		f.mu.Unlock()
		return data, nil, nil
	}
	f.active++
	if f.active > f.peak {
		f.peak = f.active
	}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.active--; f.mu.Unlock() }()
	if f.hang {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-time.After(15 * time.Millisecond):
	}
	ip := args[len(args)-1]
	return []byte(fmt.Sprintf(`<nmaprun><host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="25565"><state state="open"/></port></ports></host></nmaprun>`, ip)), nil, nil
}
func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../../testdata/nmap/hosts.xml")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func options(t *testing.T) cli.Options {
	t.Helper()
	o, e := cli.Parse([]string{"--host-timeout", "100ms", "10.0.2.0/22"}, os.Stderr)
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func TestDiscoveryAndConcurrency(t *testing.T) {
	o := options(t)
	o.Jobs = 2
	f := &fakeRunner{discovery: fixture(t)}
	inv := (Scanner{Runner: f}).Run(context.Background(), o, nil)
	if len(inv.Errors) > 0 || len(inv.Hosts) != 2 {
		t.Fatalf("%+v", inv)
	}
	if inv.Hosts[0].IP != "10.0.0.9" || inv.Hosts[1].IP != "10.0.3.10" {
		t.Fatal("not numeric sorted")
	}
	if f.peak != 2 {
		t.Fatalf("peak %d", f.peak)
	}
	for _, c := range f.calls[1:] {
		if !strings.Contains(strings.Join(c, " "), "-Pn") || c[len(c)-1] == "10.0.0.2" {
			t.Fatalf("bad inspection: %v", c)
		}
	}
	if inv.Hosts[1].Vendor != "Example" {
		t.Fatal("lost discovery metadata")
	}
}
func TestTimeoutAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			o := options(t)
			o.Jobs = 1
			o.HostTimeout = 20 * time.Millisecond
			f := &fakeRunner{discovery: fixture(t), hang: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				cancel()
			}
			start := time.Now()
			inv := (Scanner{Runner: f}).Run(ctx, o, nil)
			if time.Since(start) > time.Second || len(inv.Errors) == 0 {
				t.Fatal("deadline/cancellation not respected")
			}
			for _, h := range inv.Hosts {
				if h.Status != "failed" {
					t.Fatalf("%+v", h)
				}
			}
			if f.peak > 1 {
				t.Fatal("exceeded jobs")
			}
		})
	}
}

type runnerFunc func(context.Context, []string) ([]byte, []byte, error)

func (f runnerFunc) Run(c context.Context, a []string) ([]byte, []byte, error) { return f(c, a) }
func TestPartialAndDiscoveryFailure(t *testing.T) {
	o := options(t)
	f := runnerFunc(func(_ context.Context, a []string) ([]byte, []byte, error) {
		if a[0] == "-sn" {
			return fixture(t), nil, nil
		}
		return []byte(fmt.Sprintf(`<nmaprun><host><status state="up"/><address addr="%s" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>`, a[len(a)-1])), []byte("probe failed"), fmt.Errorf("exit 1")
	})
	inv := (Scanner{Runner: f}).Run(context.Background(), o, nil)
	if len(inv.Errors) != 2 {
		t.Fatal(inv.Errors)
	}
	for _, h := range inv.Hosts {
		if h.Status != "partial" || len(h.Ports) != 1 || !strings.Contains(h.Error, "probe failed") {
			t.Fatalf("%+v", h)
		}
	}
	calls := 0
	broken := runnerFunc(func(context.Context, []string) ([]byte, []byte, error) { calls++; return []byte("<broken>"), nil, nil })
	inv = (Scanner{Runner: broken}).Run(context.Background(), o, nil)
	if calls != 1 || len(inv.Errors) != 1 {
		t.Fatal("inspected after failed discovery")
	}
}
func TestProfiles(t *testing.T) {
	o := options(t)
	for _, profile := range []string{"quick", "standard", "aggressive"} {
		o.Profile = profile
		for _, priv := range []bool{false, true} {
			args := strings.Join((Scanner{Privileged: priv}).Args(o, "10.0.0.1"), " ")
			if !strings.Contains(args, "--max-retries 2") || !strings.Contains(args, "--host-timeout 100ms") {
				t.Fatal(args)
			}
			if profile == "standard" && (strings.Contains(args, " -O") != priv) {
				t.Fatal(args)
			}
			if profile == "aggressive" && !strings.Contains(args, "-A --script-timeout") {
				t.Fatal(args)
			}
			if strings.Contains(args, "1-65535") {
				t.Fatal("implicit all ports")
			}
		}
	}
	o.Ports = "all"
	if !strings.Contains(strings.Join((Scanner{}).Args(o, "10.0.0.1"), " "), "-p 1-65535") {
		t.Fatal("all ports missing")
	}
}
func TestDedupAndScope(t *testing.T) {
	o := options(t)
	f := &fakeRunner{discovery: []byte(`<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/></host><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/></host><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host></nmaprun>`)}
	var events []Event
	var mu sync.Mutex
	inv := (Scanner{Runner: f}).Run(context.Background(), o, func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() })
	if len(inv.Hosts) != 1 || len(f.calls) != 2 {
		t.Fatal("dedup/scope broken")
	}
}
