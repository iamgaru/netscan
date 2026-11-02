package report

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"
	"github.com/mattn/go-isatty"

	"github.com/iamgaru/netscan/internal/inventory"
)

// Palette uses basic terminal colours, leaving the terminal's background intact.
// Enable it only for a TTY with colour support; persisted reports use Text.
type Palette struct{ Enabled bool }

func (p Palette) paint(code, text string) string {
	if !p.Enabled || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

var addressPattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b`)
var portPattern = regexp.MustCompile(`^\s+[0-9]+/(tcp|udp)\s`)
var confidencePattern = regexp.MustCompile(`\(service confidence ([0-9]+)/10\)`)

// Format adds colour after column layout, so escape sequences cannot affect
// tab stops. The visible text, including uncertain service guesses, is unchanged.
func (p Palette) Format(text string) string {
	if !p.Enabled {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Error:"), strings.HasPrefix(trimmed, "Scan incomplete"):
			line = p.paint("31", line)
		case strings.HasPrefix(trimmed, "OS estimate:"):
			line = p.paint("33", line)
		case strings.HasPrefix(trimmed, "Hostnames:"), strings.HasPrefix(trimmed, "MAC:"):
			line = p.paint("35", line)
		case strings.HasPrefix(trimmed, "PORT"), trimmed == "HOST SUMMARY", strings.HasPrefix(trimmed, "IP  "):
			line = p.paint("1;36", line)
		case portPattern.MatchString(line):
			// Low-confidence service names remain guesses, even on an open port.
			match := confidencePattern.FindStringSubmatch(line)
			code := "32"
			if len(match) > 1 && len(match[1]) == 1 && match[1] < "7" {
				code = "33"
			}
			line = p.paint(code, line)
		case strings.HasPrefix(trimmed, "filtered:"), strings.HasPrefix(trimmed, "open|filtered:"):
			line = p.paint("33", line)
		case strings.HasPrefix(trimmed, "Started:"), strings.HasPrefix(trimmed, "Latency:"),
			strings.HasPrefix(trimmed, "Inspection:"), strings.HasPrefix(trimmed, "closed:"),
			strings.HasPrefix(trimmed, "OS:"), strings.HasPrefix(trimmed, "Nonresponding"):
			line = p.paint("2", line)
		case strings.HasPrefix(trimmed, "NETSCAN"), strings.HasPrefix(trimmed, "Profile:"),
			strings.HasPrefix(trimmed, "Discovered up:"), strings.HasPrefix(trimmed, "Summary:"),
			strings.HasPrefix(trimmed, "Hosts:"), strings.HasPrefix(trimmed, "Inspecting"):
			line = p.paint("1;36", line)
		default:
			line = addressPattern.ReplaceAllStringFunc(line, func(ip string) string { return p.paint("1;36", ip) })
			for _, status := range []struct{ word, code string }{{"scanned", "32"}, {"partial", "33"}, {"failed", "31"}, {"discovered", "36"}} {
				// Status tokens are delimited in host headings, progress, and TUI rows.
				for _, suffix := range []string{"]", " ", ""} {
					if suffix == "" {
						if strings.HasSuffix(line, ": "+status.word) {
							line = strings.TrimSuffix(line, status.word) + p.paint(status.code, status.word)
						}
					} else {
						line = strings.ReplaceAll(line, "["+status.word+suffix, "["+p.paint(status.code, status.word)+suffix)
						line = strings.ReplaceAll(line, " "+status.word+suffix, " "+p.paint(status.code, status.word)+suffix)
					}
				}
			}
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// Terminal renders the same content as Text, with optional ANSI colour.
func Terminal(w io.Writer, inv inventory.Inventory, palette Palette) error {
	width := 0
	tty := false
	if f, ok := w.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		tty = true
		width, _, _ = term.GetSize(f.Fd())
	}
	text, err := terminalText(inv, palette, width)
	if err != nil {
		return err
	}
	if tty {
		// Explicit carriage returns keep rows aligned even if terminal output
		// newline translation is disabled after an interactive session.
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	_, err = fmt.Fprint(w, text)
	return err
}

// terminalText leaves the last terminal column unused. Printing into that
// column can set a terminal's pending-wrap flag, which affects scrollback/copy
// semantics even when a newline follows.
func terminalText(inv inventory.Inventory, palette Palette, columns int) (string, error) {
	width := 0
	if columns > 1 {
		width = columns - 1
	}
	var b bytes.Buffer
	if err := textReport(&b, inv, width); err != nil {
		return "", err
	}
	text := palette.Format(b.String())
	if width > 0 {
		// Prefer word boundaries for diagnostics, then split only oversized tokens.
		text = ansi.Hardwrap(ansi.Wordwrap(text, width, ""), width, true)
	}
	return text, nil
}
