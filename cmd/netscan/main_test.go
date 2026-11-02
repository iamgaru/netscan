package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeNmap(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
 echo "Nmap version fixture"
 exit 0
fi
echo "fixture diagnostic" >&2
cat <<'XML'
<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="25565"><state state="open"/><service name="minecraft"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>
XML
`
	if err := os.WriteFile(filepath.Join(dir, "nmap"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
}
func TestCLIStaticAndJSON(t *testing.T) {
	fakeNmap(t)
	cwd := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	for _, jsonMode := range []bool{false, true} {
		args := []string{"--no-tui", "-v"}
		if jsonMode {
			args = append(args, "--json")
		}
		args = append(args, "10.0.0.1")
		var out, errout bytes.Buffer
		if code := run(args, &out, &errout); code != 0 {
			t.Fatalf("exit %d: %s", code, errout.String())
		}
		if !strings.Contains(errout.String(), "fixture diagnostic") || strings.Contains(out.String(), "fixture diagnostic") || strings.Contains(out.String(), "\x1b") {
			t.Fatal("stdout/stderr separation")
		}
		if jsonMode && !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON stdout")
		}
		if !jsonMode && !strings.Contains(out.String(), "25565/tcp") {
			t.Fatal("missing port")
		}
	}
	entries, err := os.ReadDir(cwd)
	if err != nil || len(entries) != 0 {
		t.Fatal("created output by default")
	}
}
func TestCLIOutputsAndErrors(t *testing.T) {
	fakeNmap(t)
	var out, errout bytes.Buffer
	dir := filepath.Join(t.TempDir(), "reports")
	code := run([]string{"-o", dir, "-f", "text,json,html", "-r", "10.0.0.1"}, &out, &errout)
	if code != 0 {
		t.Fatal(errout.String())
	}
	for _, name := range []string{"report.txt", "report.json", "report.html", "10.0.0.1.xml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "NETSCAN") {
		t.Fatal("no stdout with files")
	}
	if code := run([]string{"bad"}, &out, &errout); code != 2 {
		t.Fatal(code)
	}
	t.Setenv("PATH", t.TempDir())
	if code := run([]string{"10.0.0.1"}, &out, &errout); code != 1 {
		t.Fatal(code)
	}
	if !strings.Contains(errout.String(), "brew install nmap") {
		t.Fatal("missing install guidance")
	}
}
