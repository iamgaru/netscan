# netscan — Product Requirements & Coding-Agent Handoff

**Version:** 0.1 draft  
**Target:** macOS (Apple Silicon), Go CLI using installed Nmap  
**Status:** Ready for local implementation

## 1. Goal

Build a reliable, polished local-network inventory CLI that discovers responding hosts in a user-supplied IPv4 CIDR, inspects only those hosts, and displays a readable **host-centric** report in the terminal by default. Optional file output should include text, JSON, HTML, and raw Nmap XML. The program must finish predictably and never silently omit open ports because of text parsing.

The primary user environment is macOS with Go and Nmap installed. Example network: `10.0.2.0/22` (normalizes to `10.0.0.0/22`). This is an authorized local-network inventory utility, not an exploit scanner.

## 2. Product principles

1. **Stdout by default:** plain, attractive host-by-host output even when not using an interactive terminal.
2. **TUI when interactive:** polished live status, responsive progress, host list, and selectable details; fall back automatically for pipes and non-TTYs. A `--no-tui` flag must force static output.
3. **Never hide detected ports:** render every open port returned by the chosen scan; distinguish *not scanned*, *filtered*, and *not detected*.
4. **Bounded execution:** explicit per-host timeouts, bounded concurrency, clear failure/partial-result states, Ctrl-C cancellation.
5. **Nmap is the engine:** do not reimplement packet scanning. Parse `-oX` XML via Go `encoding/xml`, not greppable text or awk.
6. **Respect uncertainty:** OS fingerprints are estimates; hostname/MAC may be absent; service guesses are not process lists.
7. **No automatic directory creation unless requested by an output flag.**

## 3. Scope

### MVP (required)
- Accept one IPv4 CIDR or host address; validate via `net/netip`; display normalized network CIDR.
- Discover live hosts using `nmap -sn -n -oX - <CIDR>`, capturing stdout/stderr separately.
- Parse XML host status and addresses, including MAC/vendor when Nmap reports them.
- Inspect **only discovered-up hosts** with a bounded worker pool (`-j`, default 4). Avoid repeating discovery with `-Pn` on inspection scans.
- Default `standard` profile: Nmap's 1,000 common TCP ports, `-sV --version-light`, `-O` where privileges allow; optional traceroute and scripts only in aggressive profile.
- Profiles: `quick`, `standard` (default), `aggressive`; aggressive uses `-A` with safe operational timeouts. `-p all` requests full 1–65535 TCP range; `-p 22,80,443,25565-25567` accepts a validated Nmap port expression.
- Every open TCP port from XML appears in per-host details, with service name, product, version, extra info, and confidence when available. Other port states may be counted but not individually listed by default.
- Per-host timeout (`--host-timeout`, default 120s), worker concurrency (`-j`, default 4), retry limit (`--max-retries`, default 2), and script timeout in aggressive mode (`--script-timeout`, default 15s).
- Structured host inventory: IP, hostname(s), MAC, vendor, OS matches with accuracy, status, latency (if available), open ports, service details, scripts (aggressive), scan duration, errors/partial status.
- Terminal: polished static report to stdout by default, progress to stderr; interactive TUI on a TTY unless `--no-tui` is set. In TUI, show phases, live host count, completed/total, active host scans, elapsed time, scrollable host list, selectable host details, and clear errors.
- `-o DIR` saves formatted text report alongside stdout; `-f text,json,html` chooses formats (implies output directory, default `./nmap-reports` if `-o` omitted); `-r` retains per-host raw XML (also implies output directory). Explicit output flags may create directories; no files created otherwise.
- Exit statuses: 0 completed; nonzero invalid usage, dependency failure, discovery failure, or partial/failed host scans. Partial failures must be summarized and persisted in output.
- README with installation (`brew install nmap`), `go build`, usage, privileges, and sample output.

### Nice-to-have after MVP
- HTML report with summary, searchable/filterable host table, expandable per-host detail; self-contained and readable offline.
- Inventory diff between two JSON snapshots: added/removed hosts and changed ports/services.
- Optional reverse DNS (`--resolve`) with a timeout; default `-n` avoids slow DNS.
- `--json` shortcut for machine-readable stdout; no progress mixed into JSON.
- UDP scanning as an explicitly separate mode, never implied by `-p all`.

### Explicit non-goals
- No remote process enumeration; Nmap identifies services, not full process lists.
- No credential collection, SSH automation, vulnerability exploitation, or stealth/evasion.
- No claim that non-responding hosts are definitely offline; they are simply not discovered as up.

## 4. CLI contract

```text
netscan [flags] <IPv4-CIDR-or-IP>

  -j, --jobs N              concurrent host inspections (default 4)
      --profile NAME        quick|standard|aggressive (default standard)
  -p, --ports EXPR          default|all|22,80,443,25565-25567
      --host-timeout DUR    default 120s
      --script-timeout DUR  default 15s (aggressive)
      --max-retries N       default 2
      --no-tui              static stdout report
  -v, --verbose             progress and Nmap diagnostics on stderr
  -o, --output DIR          save reports, still print to stdout
  -f, --format LIST         text,json,html (requires/implies output directory)
  -r, --raw                 save raw per-host XML (implies output directory)
  -h, --help
```

Examples:

```bash
sudo netscan 10.0.2.0/22
sudo netscan --no-tui -j 4 10.0.2.0/22
sudo netscan --profile aggressive -p all -j 2 -o ./reports -f text,json,html -r 10.0.2.0/22
netscan --profile quick 10.0.0.0/24
```

**Design note:** `-p all` and `--profile aggressive` are independent. An aggressive scan does not automatically scan every TCP port. For `--format` without `-o`, choose and document one consistent rule (preferred: create `./nmap-reports` only because an output flag was explicitly requested).

## 5. Scan pipeline

1. Validate inputs, detect Nmap and version, check whether privileges are available; show warning if OS detection is unavailable. Do not prompt for sudo internally.
2. Run discovery once. Parse `nmaprun.host[].status.state == up` and gather addresses. Sort IPs numerically and deduplicate.
3. Enqueue discovered IPs. Use Go worker pool and `exec.CommandContext` for each inspection. Limit child-process concurrency. Use `-Pn` and `-oX -`; include `--host-timeout`, `--max-retries`, and profile-specific options. Capture stderr for diagnostics. Avoid interleaving Nmap stdout with UI output.
4. Parse each XML response and merge into host inventory. Store partial/error status if Nmap times out, exits nonzero, or returns invalid XML. Never mark such a host 'offline' just because inspection failed.
5. Publish progress events to TUI/stderr. Render complete report when scans finish. When saving, use atomic file writes where feasible.
6. On SIGINT, cancel running scans, restore terminal state, and provide a clear cancellation summary.

**Performance:** Default to 1,000 common TCP ports and `--version-light`; avoid launching `-A` against all hosts unless explicitly requested. The `--host-timeout` bounds each host scan, not the overall run; total time also depends on worker count.

## 6. Data model (suggested)

```go
type Inventory struct {
    CIDR      string    `json:"cidr"`
    StartedAt time.Time `json:"started_at"`
    EndedAt   time.Time `json:"ended_at"`
    Hosts     []Host    `json:"hosts"`
    Errors    []string  `json:"errors,omitempty"`
}

type Host struct {
    IP          string    `json:"ip"`
    Hostnames   []string  `json:"hostnames,omitempty"`
    MAC         string    `json:"mac,omitempty"`
    Vendor      string    `json:"vendor,omitempty"`
    OSMatches   []OSMatch `json:"os_matches,omitempty"`
    Ports       []Port    `json:"ports"`
    Status      string    `json:"status"` // discovered, scanned, partial, failed
    Error       string    `json:"error,omitempty"`
}

type OSMatch struct {
    Name     string `json:"name"`
    Accuracy int    `json:"accuracy"`
}

type Port struct {
    Number   uint16 `json:"number"`
    Protocol string `json:"protocol"`
    State    string `json:"state"`
    Service  string `json:"service,omitempty"`
    Product  string `json:"product,omitempty"`
    Version  string `json:"version,omitempty"`
    Extra    string `json:"extra,omitempty"`
}
```

Use real Nmap XML examples to refine this model (including hostscript/portscript data and OS confidence).

## 7. Terminal design

Suggested libraries:
- **Bubble Tea** (`github.com/charmbracelet/bubbletea`) for interactive TUI
- **Lip Gloss** (`github.com/charmbracelet/lipgloss`) for layout, colour, borders, responsive widths
- **Bubbles** (`github.com/charmbracelet/bubbles`) for progress, spinner, viewport, list/table as appropriate

Visual language: restrained dark-friendly cyan/teal accent, green for open/completed, amber for partial/timeouts, red for failures; no reliance on colour alone. Respect `NO_COLOR`, small terminal widths, and redirected output. Avoid alternate-screen mode if it interferes with preserving final report in scrollback; test this explicitly.

Interactive layout:
- Header: `NETSCAN`, target CIDR, profile, elapsed time.
- Summary: discovered live hosts, completed, active, partial/failed, open ports.
- Progress: discovery/inspection phases and per-host worker activity.
- Host list: IP, hostname/vendor, likely OS, open-port count, scan status.
- Host detail: metadata, OS match accuracy, table of **all** open ports, service/version, NSE details when present.
- Key hints: arrows/j/k navigate, Enter details, Esc back, q quit after cancellation confirmation during scan.

Static output:
- Header with network/time/host counts.
- One titled block per discovered host, numerically sorted.
- Clear columns: `PORT`, `STATE`, `SERVICE`, `VERSION`.
- Explicit `No open TCP ports found in scanned range` or `Scan incomplete` as appropriate.
- Final summary and file paths when saving.

## 8. Files and package layout

```text
netscan/
  go.mod
  cmd/netscan/main.go
  internal/cli/options.go
  internal/scanner/discovery.go
  internal/scanner/inspect.go
  internal/scanner/runner.go
  internal/nmap/xml.go
  internal/inventory/model.go
  internal/report/text.go
  internal/report/json.go
  internal/report/html.go
  internal/tui/model.go
  internal/tui/styles.go
  internal/scanner/*_test.go
  internal/nmap/*_test.go
  testdata/nmap/*.xml
  README.md
```

Keep interfaces simple; avoid overengineering or unnecessary dependency injection. Go 1.23+ is sufficient unless local tooling dictates otherwise.

## 9. Acceptance criteria

- `sudo netscan --no-tui 10.0.2.0/22` shows **only discovered-up hosts**, each with its own readable section.
- Nmap XML containing multiple open ports separated by NSE script entries results in **all** ports appearing in the report (regression test for the Bash AWK bug).
- Discovery of `10.0.2.0/22` can legitimately return hosts from `10.0.0.x` through `10.0.3.x`.
- A hung service probe cannot stall the scan indefinitely; timeout yields a visible partial/failed host status.
- Host inspections run concurrently but never exceed `-j` workers.
- Default run creates no output files or directories.
- `-o ./reports -f text,json,html -r` saves requested outputs while retaining human-readable stdout.
- Redirected stdout is clean (no ANSI escape sequences, spinners or progress messages).
- Missing Nmap and malformed CIDRs fail with actionable messages.
- Ctrl-C cancels child processes and restores terminal state.
- Tests run with `go test ./...`; use fixture XML and a fake command runner so tests do not require scanning a live network.
- README includes examples, privilege limitations, safe network scope and explicit distinction between remote services and running processes.

## 10. Coding-agent execution instructions

1. Inspect installed `go`, `nmap`, and current repository state. Do not overwrite existing work without checking.
2. Scaffold the module and implement XML parser and fixture tests **first**.
3. Implement discovery, worker pool, timeout/cancellation and static terminal report. Validate on fixture data.
4. Implement file outputs and CLI options; test stdout/stderr separation and no-files-by-default behaviour.
5. Add the interactive TUI and graceful non-TTY fallback.
6. Add self-contained HTML report if time permits; otherwise defer explicitly, but do not claim the flag works until implemented.
7. Run `gofmt`, `go vet ./...`, `go test ./...`, and `go build ./cmd/netscan`.
8. Run a small authorized smoke test on a user-selected CIDR only after confirming target. Avoid aggressive scans during automated tests.
9. Report implemented features, commands run, test results, known limitations and any deferred work. Do not commit, push or deploy without explicit approval.

## 11. Initial prompt for local coding agent

> Implement the `netscan` Go CLI from `netscan-PRD-handoff.md`. Prioritize a reliable, bounded, concurrent Nmap XML scanning pipeline and clean stdout report before building the Bubble Tea TUI. Use Lip Gloss/Bubbles for a polished interface. Preserve every detected open port. Make output files opt-in. Build fixture-based tests, run gofmt/vet/test/build, and summarize results. Do not create unrelated directories, overwrite existing files, commit, push, or perform network scans beyond a target I explicitly approve. Ask only when a design choice materially affects the acceptance criteria.
