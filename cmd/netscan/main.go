package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/iamgaru/netscan/internal/cli"
	"github.com/iamgaru/netscan/internal/inventory"
	"github.com/iamgaru/netscan/internal/report"
	"github.com/iamgaru/netscan/internal/scanner"
	"github.com/iamgaru/netscan/internal/tui"
	"github.com/mattn/go-isatty"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	o, err := cli.Parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "netscan:", err)
		return 2
	}
	path, err := exec.LookPath("nmap")
	if err != nil {
		fmt.Fprintln(stderr, "netscan: Nmap not found; install with: brew install nmap")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runner := scanner.CommandRunner{Path: path}
	vctx, vcancel := context.WithTimeout(ctx, 5*time.Second)
	version, diag, err := runner.Run(vctx, []string{"--version"})
	vcancel()
	if err != nil {
		fmt.Fprintf(stderr, "netscan: cannot run Nmap: %v %s\n", err, report.Clean(string(diag)))
		return 1
	}
	if o.Verbose {
		fmt.Fprintln(stderr, report.Clean(strings.TrimSpace(string(version))))
	}
	privileged := os.Geteuid() == 0
	if !privileged && o.Profile != "quick" {
		fmt.Fprintln(stderr, "Warning: OS detection and traceroute require elevated privileges; scanning services without them.")
	}
	s := scanner.Scanner{Runner: runner, Privileged: privileged}
	var inv inventory.Inventory
	interactive := !o.NoTUI && !o.JSON && stdout == os.Stdout && isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stdin.Fd()) && os.Getenv("TERM") != "dumb"
	if interactive {
		events := make(chan scanner.Event, 64)
		results := make(chan inventory.Inventory, 1)
		go func() {
			result := s.Run(ctx, o, func(e scanner.Event) { events <- e })
			results <- result
			close(events)
		}()
		model := tui.New(o.Target, o.Profile, events, results, cancel, os.Getenv("NO_COLOR") != "")
		p := tea.NewProgram(model, tea.WithOutput(stdout), tea.WithInput(os.Stdin), tea.WithoutSignalHandler())
		result, e := p.Run()
		if e != nil {
			cancel()
			// Drain progress so workers can finish even if terminal setup failed.
			for range events {
			}
			inv = <-results
			inv.Errors = append(inv.Errors, "interactive interface: "+e.Error())
		} else {
			inv = result.(tui.Model).Inventory
		}
	} else {
		var mu sync.Mutex
		inv = s.Run(ctx, o, func(e scanner.Event) {
			mu.Lock()
			defer mu.Unlock()
			switch e.Phase {
			case "discovery":
				fmt.Fprintf(stderr, "Discovering %s…\n", o.Target)
			case "inspection":
				fmt.Fprintf(stderr, "Inspecting %d discovered hosts (%d workers)…\n", e.Total, o.Jobs)
			case "completed":
				fmt.Fprintf(stderr, "[%d/%d] %s: %s\n", e.Completed, e.Total, e.Host.IP, e.Host.Status)
			}
			if o.Verbose && e.Diagnostic != "" {
				fmt.Fprintln(stderr, report.Clean(e.Diagnostic))
			}
		})
	}
	if o.JSON {
		err = report.JSON(stdout, inv)
	} else {
		err = report.Text(stdout, inv)
	}
	failed := len(inv.Errors) > 0
	if err != nil {
		fmt.Fprintln(stderr, "netscan: write stdout:", err)
		failed = true
	}
	paths, err := report.Save(o.Output, o.Formats, o.Raw, inv)
	if err != nil {
		fmt.Fprintln(stderr, "netscan: save reports:", err)
		failed = true
	}
	for _, p := range paths {
		fmt.Fprintln(stderr, "Saved:", p)
	}
	if failed {
		return 1
	}
	return 0
}
