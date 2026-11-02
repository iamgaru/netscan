package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamgaru/netscan/internal/inventory"
	"github.com/iamgaru/netscan/internal/nmap"
)

func sample(t *testing.T) inventory.Inventory {
	t.Helper()
	f, e := os.Open("../../testdata/nmap/hosts.xml")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	hosts, e := nmap.Parse(f)
	if e != nil {
		t.Fatal(e)
	}
	hosts = hosts[:1]
	hosts[0].Status = "partial"
	hosts[0].Error = "timeout"
	hosts[0].RawXML = "<nmaprun/>"
	return inventory.Inventory{CIDR: "10.0.0.0/22", Hosts: hosts, Errors: []string{"timeout"}}
}
func TestReports(t *testing.T) {
	inv := sample(t)
	var b bytes.Buffer
	if e := Text(&b, inv); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"22/tcp", "443/tcp", "25565/tcp", "Scan incomplete", "filtered: 997", "95%"} {
		if !strings.Contains(b.String(), s) {
			t.Fatalf("missing %s", s)
		}
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal("ANSI")
	}
	b.Reset()
	if e := JSON(&b, inv); e != nil {
		t.Fatal(e)
	}
	var decoded inventory.Inventory
	if e := json.Unmarshal(b.Bytes(), &decoded); e != nil {
		t.Fatal(e)
	}
	if len(decoded.Hosts[0].Ports) != 3 || decoded.Hosts[0].RawXML != "" {
		t.Fatal("bad JSON")
	}
	inv.Hosts[0].Hostnames = []string{"<script>alert('x')</script>"}
	b.Reset()
	if e := HTML(&b, inv); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.String(), "<script>alert") {
		t.Fatal("HTML injection")
	}
	if !strings.Contains(b.String(), "25565/tcp") {
		t.Fatal("HTML lost port")
	}
}
func TestSaveOptIn(t *testing.T) {
	inv := sample(t)
	paths, e := Save("", "text", false, inv)
	if e != nil || len(paths) != 0 {
		t.Fatal("default wrote files")
	}
	dir := filepath.Join(t.TempDir(), "reports")
	paths, e = Save(dir, "text,json,html", true, inv)
	if e != nil {
		t.Fatal(e)
	}
	if len(paths) != 4 {
		t.Fatal(paths)
	}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil || len(b) == 0 {
			t.Fatalf("%s %v", p, e)
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 4 {
		t.Fatal("temporary files leaked")
	}
}
func TestControlSanitization(t *testing.T) {
	if strings.Contains(Clean("host\x1b[31m\r\n"), "\x1b") {
		t.Fatal("unsafe terminal controls")
	}
}
