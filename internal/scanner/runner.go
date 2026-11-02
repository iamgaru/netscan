package scanner

import (
	"bytes"
	"context"
	"os/exec"
)

type Runner interface {
	Run(context.Context, []string) ([]byte, []byte, error)
}
type CommandRunner struct{ Path string }

func (r CommandRunner) Run(ctx context.Context, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, r.Path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
