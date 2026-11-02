// Package nmap decodes Nmap XML without depending on human-readable output.
package nmap

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"sort"

	"github.com/iamgaru/netscan/internal/inventory"
)

type xmlHost struct {
	TimedOut string `xml:"timedout,attr"`
	Status   struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Address string `xml:"addr,attr"`
		Type    string `xml:"addrtype,attr"`
		Vendor  string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	OS      []inventory.OSMatch `xml:"os>osmatch"`
	Scripts []inventory.Script  `xml:"hostscript>script"`
	Times   struct {
		RTT int64 `xml:"srtt,attr"`
	} `xml:"times"`
	Ports []struct {
		Number   uint16 `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name       string `xml:"name,attr"`
			Product    string `xml:"product,attr"`
			Version    string `xml:"version,attr"`
			Extra      string `xml:"extrainfo,attr"`
			Confidence *int   `xml:"conf,attr"`
		} `xml:"service"`
		Scripts []inventory.Script `xml:"script"`
	} `xml:"ports>port"`
	Extra []struct {
		State string `xml:"state,attr"`
		Count int    `xml:"count,attr"`
	} `xml:"ports>extraports"`
}

// Parse retains complete hosts decoded before malformed/truncated XML.
func Parse(r io.Reader) ([]inventory.Host, error) {
	d := xml.NewDecoder(r)
	hosts := []inventory.Host{}
	root, finished := false, false
	for {
		t, err := d.Token()
		if err == io.EOF {
			if !root || !finished {
				return hosts, fmt.Errorf("incomplete Nmap XML")
			}
			return hosts, nil
		}
		if err != nil {
			return hosts, fmt.Errorf("decode Nmap XML: %w", err)
		}
		switch e := t.(type) {
		case xml.StartElement:
			if !root {
				if e.Name.Local != "nmaprun" {
					return hosts, fmt.Errorf("expected nmaprun XML root")
				}
				root = true
				continue
			}
			if finished {
				return hosts, fmt.Errorf("unexpected XML after nmaprun")
			}
			if e.Name.Local == "host" {
				var x xmlHost
				err := d.DecodeElement(&x, &e)
				h := convert(x)
				if h.IP != "" {
					hosts = append(hosts, h)
				}
				if err != nil {
					return hosts, fmt.Errorf("decode host XML: %w", err)
				}
			} else if e.Name.Local == "runstats" {
				var stats struct {
					Finished struct {
						Exit  string `xml:"exit,attr"`
						Error string `xml:"errormsg,attr"`
					} `xml:"finished"`
				}
				if err := d.DecodeElement(&stats, &e); err != nil {
					return hosts, err
				}
				if stats.Finished.Exit == "error" {
					return hosts, fmt.Errorf("Nmap: %s", stats.Finished.Error)
				}
			}
		case xml.EndElement:
			if e.Name.Local == "nmaprun" {
				finished = true
			}
		}
	}
}
func convert(x xmlHost) inventory.Host {
	h := inventory.Host{Status: x.Status.State, Ports: []inventory.Port{}, OtherStates: map[string]int{}, OSMatches: x.OS, Scripts: x.Scripts, LatencyMicros: x.Times.RTT}
	if x.TimedOut == "true" {
		h.Error = "Nmap host timeout"
	}
	for _, a := range x.Addresses {
		if a.Type == "ipv4" {
			if ip, err := netip.ParseAddr(a.Address); err == nil && ip.Is4() {
				h.IP = ip.String()
			}
		}
		if a.Type == "mac" {
			h.MAC, h.Vendor = a.Address, a.Vendor
		}
	}
	for _, n := range x.Hostnames {
		h.Hostnames = append(h.Hostnames, n.Name)
	}
	for _, p := range x.Ports {
		if p.State.State != "open" {
			h.OtherStates[p.State.State]++
			continue
		}
		h.Ports = append(h.Ports, inventory.Port{Number: p.Number, Protocol: p.Protocol, State: p.State.State, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, Extra: p.Service.Extra, Confidence: p.Service.Confidence, Scripts: p.Scripts})
	}
	for _, e := range x.Extra {
		h.OtherStates[e.State] += e.Count
	}
	sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Number < h.Ports[j].Number })
	return h
}
