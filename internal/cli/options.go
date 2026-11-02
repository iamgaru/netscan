package cli

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Target, Profile, Ports, Output, Formats string
	Jobs, Retries                           int
	HostTimeout, ScriptTimeout              time.Duration
	NoTUI, Verbose, Raw, JSON               bool
}

func Parse(args []string, out io.Writer) (Options, error) {
	o := Options{}
	f := flag.NewFlagSet("netscan", flag.ContinueOnError)
	f.SetOutput(out)
	f.Usage = func() { fmt.Fprintln(out, "Usage: netscan [flags] <IPv4-CIDR-or-IP>"); f.PrintDefaults() }
	f.IntVar(&o.Jobs, "j", 4, "concurrent inspections")
	f.IntVar(&o.Jobs, "jobs", 4, "concurrent inspections")
	f.StringVar(&o.Profile, "profile", "standard", "quick|standard|aggressive")
	f.StringVar(&o.Ports, "p", "default", "default|all|22,80,443,25565-25567")
	f.StringVar(&o.Ports, "ports", "default", "TCP ports")
	f.DurationVar(&o.HostTimeout, "host-timeout", 120*time.Second, "per-host deadline")
	f.DurationVar(&o.ScriptTimeout, "script-timeout", 15*time.Second, "aggressive script timeout")
	f.IntVar(&o.Retries, "max-retries", 2, "Nmap retry limit")
	f.BoolVar(&o.NoTUI, "no-tui", false, "static report")
	f.BoolVar(&o.Verbose, "v", false, "diagnostics")
	f.BoolVar(&o.Verbose, "verbose", false, "diagnostics")
	f.StringVar(&o.Output, "o", "", "report directory")
	f.StringVar(&o.Output, "output", "", "report directory")
	f.StringVar(&o.Formats, "f", "text", "text,json,html")
	f.StringVar(&o.Formats, "format", "text", "text,json,html")
	f.BoolVar(&o.Raw, "r", false, "retain raw XML")
	f.BoolVar(&o.Raw, "raw", false, "retain raw XML")
	f.BoolVar(&o.JSON, "json", false, "JSON stdout")
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if f.NArg() != 1 {
		return o, fmt.Errorf("provide exactly one IPv4 CIDR or address (flags precede target)")
	}
	target := f.Arg(0)
	if !strings.Contains(target, "/") {
		target += "/32"
	}
	p, err := netip.ParsePrefix(target)
	if err != nil || !p.Addr().Is4() {
		return o, fmt.Errorf("invalid IPv4 target %q", f.Arg(0))
	}
	o.Target = p.Masked().String()
	if o.Jobs < 1 || o.Jobs > 256 {
		return o, fmt.Errorf("jobs must be between 1 and 256")
	}
	if o.HostTimeout <= 0 || o.ScriptTimeout <= 0 || o.Retries < 0 {
		return o, fmt.Errorf("timeouts must be positive and retries nonnegative")
	}
	if o.Profile != "quick" && o.Profile != "standard" && o.Profile != "aggressive" {
		return o, fmt.Errorf("unknown profile %q", o.Profile)
	}
	if err := ValidatePorts(o.Ports); err != nil {
		return o, err
	}
	for _, v := range strings.Split(o.Formats, ",") {
		if v != "text" && v != "json" && v != "html" {
			return o, fmt.Errorf("unknown output format %q", v)
		}
	}
	explicit := o.Raw
	f.Visit(func(f *flag.Flag) {
		if f.Name == "f" || f.Name == "format" || f.Name == "o" || f.Name == "output" {
			explicit = true
		}
	})
	if explicit && o.Output == "" {
		o.Output = "./nmap-reports"
	}
	return o, nil
}
func ValidatePorts(s string) error {
	if s == "default" || s == "all" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return fmt.Errorf("invalid port expression %q", s)
		}
		prev := 0
		for _, v := range ends {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 || n < prev || strings.Trim(v, "0123456789") != "" {
				return fmt.Errorf("invalid port expression %q", s)
			}
			prev = n
		}
	}
	return nil
}
