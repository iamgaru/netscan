package cli

import (
	"io"
	"testing"
)

func TestOptions(t *testing.T) {
	o, e := Parse([]string{"10.0.2.0/22"}, io.Discard)
	if e != nil || o.Target != "10.0.0.0/22" || o.Output != "" || o.Jobs != 4 {
		t.Fatalf("%+v %v", o, e)
	}
	for _, flag := range []string{"-r", "-f=json"} {
		o, e = Parse([]string{flag, "10.0.0.1"}, io.Discard)
		if e != nil || o.Output != "./nmap-reports" || o.Target != "10.0.0.1/32" {
			t.Fatalf("%+v %v", o, e)
		}
	}
	for _, args := range [][]string{{"::1"}, {"bad"}, {"-j", "0", "10.0.0.1"}, {"--profile", "other", "10.0.0.1"}, {"--host-timeout", "0s", "10.0.0.1"}, {"-f", "pdf", "10.0.0.1"}} {
		if _, err := Parse(args, io.Discard); err == nil {
			t.Fatal(args)
		}
	}
}
func TestPorts(t *testing.T) {
	for _, s := range []string{"default", "all", "22,80,443,25565-25567", "1-65535"} {
		if e := ValidatePorts(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"", "0", "65536", "80-22", "1-2-3", "-sS", "+22", "T:22", "22,", " 22"} {
		if e := ValidatePorts(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
