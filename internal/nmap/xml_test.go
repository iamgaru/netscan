package nmap

import (
	"os"
	"strings"
	"testing"
)

func TestFixture(t *testing.T) {
	f, err := os.Open("../../testdata/nmap/hosts.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 3 || len(h[0].Ports) != 3 || h[0].Ports[2].Number != 25565 {
		t.Fatalf("ports lost: %+v", h)
	}
	if h[0].Vendor != "Example" || h[0].OSMatches[0].Accuracy != 95 || *h[0].Ports[0].Confidence != 10 || h[0].OtherStates["filtered"] != 997 {
		t.Fatalf("metadata lost: %+v", h[0])
	}
}
func TestInvalidAndPartial(t *testing.T) {
	for _, s := range []string{"", "<foo/>", "<nmaprun>"} {
		if _, err := Parse(strings.NewReader(s)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	h, err := Parse(strings.NewReader(`<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>`))
	if err == nil || len(h) != 1 {
		t.Fatal("expected retained partial host")
	}
}

func TestNmapTimeoutAndRunFailure(t *testing.T) {
	h, err := Parse(strings.NewReader(`<nmaprun><host timedout="true"><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>`))
	if err != nil || len(h) != 1 || h[0].Error == "" {
		t.Fatal("lost Nmap host timeout")
	}
	_, err = Parse(strings.NewReader(`<nmaprun><runstats><finished exit="error" errormsg="fixture failure"/></runstats></nmaprun>`))
	if err == nil || !strings.Contains(err.Error(), "fixture failure") {
		t.Fatal("lost run failure")
	}
}
