# netscan

A host-centric IPv4 network inventory CLI powered by installed Nmap. It discovers
responding hosts once, then inspects only those hosts with bounded concurrency.
Use it only on networks you are authorized to inspect.

## Install

Requires Go 1.23+, Make, and Nmap (macOS is the primary target). If Make is
missing on macOS, install the Command Line Tools with `xcode-select --install`.
From the repository directory:

    brew install go nmap
    make build
    ./netscan --help

`make` also builds by default. The executable is `netscan` in the repository
root; run it as `./netscan` from that directory. On macOS it has no `.exe`
extension. Building or running `--help` does not scan the network. Nmap must
remain installed to run scans; Go and Make are only needed to build.

To build without Make:

    go build -o netscan ./cmd/netscan

## Usage

Flags precede the one IPv4 address or CIDR:

    ./netscan --profile quick 10.0.0.0/24
    sudo ./netscan --no-tui -j 4 10.0.2.0/22
    ./netscan -p 22,80,443,25565-25567 10.0.0.0/24
    sudo ./netscan --profile aggressive -p all -j 2 -o ./reports -f text,json,html -r 10.0.2.0/22
    ./netscan --json 10.0.0.0/24 > inventory.json

10.0.2.0/22 normalizes to 10.0.0.0/22, including addresses through
10.0.3.255. A single address becomes /32. Nonresponding hosts are simply
not discovered as up; they are not proven offline.

| Option | Default / behavior |
| --- | --- |
| -j, --jobs | 4 inspections, allowed range 1–256 |
| --profile | standard; also quick, aggressive |
| -p, --ports | default: Nmap's 1,000 common TCP ports; all: 1–65535; or numeric list/ranges |
| --host-timeout | 120s per inspection; also bounds the discovery phase |
| --max-retries | 2 Nmap probe retries |
| --script-timeout | 15s per aggressive script |
| --no-tui | Force static output |
| -v, --verbose | Include captured Nmap diagnostics on stderr |
| -o, --output | Save reports in this directory |
| -f, --format | Comma-separated text,json,html; default text |
| -r, --raw | Retain per-host XML, including incomplete XML on failures |
| --json | JSON stdout; disables TUI |
| -h, --help | Usage |

Quick uses TCP connect scanning without version or OS probes. Standard enables
light service version probes and OS detection when running as root. Aggressive
uses Nmap -A (version detection, default NSE scripts, and privileged OS/traceroute)
with the script deadline. Aggressive does **not** imply all ports. There is no UDP
mode. All inspections use -Pn and disable DNS.

The program never invokes sudo. Without root, it uses connect scanning and warns
that OS detection/traceroute are unavailable. Privilege detection uses effective
UID; capability-based Nmap installations are not specially detected.

## Terminal and reports

TTY output uses Bubble Tea and Lip Gloss with live phase, counts, active hosts,
and elapsed time. Arrows or j/k select a host; Enter opens details, arrows scroll,
and Esc returns. Press q then y to cancel, or Ctrl-C immediately. The interface
uses the normal screen so the final report remains in scrollback. Pipes,
TERM=dumb, --no-tui, and JSON stdout use static mode. NO_COLOR disables TUI
color. Progress and saved paths go to stderr.

Example (abridged):

    NETSCAN  10.0.0.0/22
    Profile: standard | TCP ports: default
    Discovered up: 1

    10.0.3.10  [scanned]
      Hostnames: example
      MAC: AA:BB:CC:DD:EE:FF  Example
      OS estimate: Linux (95% accuracy)
      PORT       STATE  SERVICE    VERSION
      22/tcp     open   ssh        OpenSSH 9.8 (service confidence 10/10)
      443/tcp    open   https
      25565/tcp  open   minecraft  custom server
      filtered: 997 ports

    Summary: 1 completed, 0 partial/failed, 3 open ports

Every detected open port is retained, including ports adjacent to script entries.
Closed/filtered states are counted. Empty successful scans explicitly say no open
TCP ports were found in the scanned range; failed scans say results are incomplete.
OS fingerprints are estimates, and detected remote services are **not** running
process lists.

No report files or directories are created by default. Explicit -o, -f, or
-r enables output; -f/-r without -o uses ./nmap-reports. Reports are named
report.txt, report.json, report.html, and raw XML is named <IP>.xml.
Requested files replace existing files atomically; other files are left alone.
Raw discovery XML is not saved. HTML is self-contained, searchable, expandable,
and readable offline. JSON includes status, errors, port/service confidence,
scripts, timestamps, latency in microseconds, and duration in nanoseconds.

Exit status is 0 for completion (including zero discovered hosts), 2 for invalid
usage, and 1 for dependency, discovery, cancellation, inspection, or output errors.
Partial results are printed and persisted. A large network's discovery may need
a longer timeout. The per-host deadline is a wall-clock bound in addition to
Nmap's own timeout; total duration depends on host count and workers.

## Development and verification

    make check
    make race

`make check` runs `go test ./...`, `go vet ./...`, and builds `./netscan`.
Individual targets are `make test`, `make vet`, and `make build`. Use `make fmt`
to format Go sources, `make clean` to remove only the built executable, and
`make help` to list targets. Override the Go command if needed, for example
`make build GO=/opt/homebrew/bin/go`.

Tests use representative Nmap XML fixtures, fake runners, and a fake Nmap executable.
They do not scan a network or require installed Nmap. Live smoke tests require an
explicitly approved target. Reverse DNS, inventory diff, and UDP mode are deferred.
