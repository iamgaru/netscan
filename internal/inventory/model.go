package inventory

import "time"

type Inventory struct {
	CIDR      string    `json:"cidr"`
	Profile   string    `json:"profile"`
	Ports     string    `json:"port_range"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Hosts     []Host    `json:"hosts"`
	Errors    []string  `json:"errors,omitempty"`
}
type Host struct {
	IP            string         `json:"ip"`
	Hostnames     []string       `json:"hostnames,omitempty"`
	MAC           string         `json:"mac,omitempty"`
	Vendor        string         `json:"vendor,omitempty"`
	OSMatches     []OSMatch      `json:"os_matches,omitempty"`
	Ports         []Port         `json:"ports"`
	OtherStates   map[string]int `json:"other_states,omitempty"`
	Scripts       []Script       `json:"scripts,omitempty"`
	Status        string         `json:"status"`
	Error         string         `json:"error,omitempty"`
	LatencyMicros int64          `json:"latency_micros,omitempty"`
	Duration      time.Duration  `json:"duration_ns"`
	RawXML        string         `json:"-"`
}
type OSMatch struct {
	Name     string `xml:"name,attr" json:"name"`
	Accuracy int    `xml:"accuracy,attr" json:"accuracy"`
}
type Script struct {
	ID     string `xml:"id,attr" json:"id"`
	Output string `xml:"output,attr" json:"output"`
}
type Port struct {
	Number     uint16   `json:"number"`
	Protocol   string   `json:"protocol"`
	State      string   `json:"state"`
	Service    string   `json:"service,omitempty"`
	Product    string   `json:"product,omitempty"`
	Version    string   `json:"version,omitempty"`
	Extra      string   `json:"extra,omitempty"`
	Confidence *int     `json:"confidence,omitempty"`
	Scripts    []Script `json:"scripts,omitempty"`
}
