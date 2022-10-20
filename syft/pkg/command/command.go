package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

func NewCommand(ctx context.Context, name, dir string, stdout, stderr io.Writer, args ...string) (*exec.Cmd, error) {
	var binPath, err = exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is required for runtime: %w", name, err)
	}
	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = dir

	if stdout != nil {
		cmd.Stdout = stdout
	}

	if stderr != nil {
		cmd.Stderr = stderr
	}

	return cmd, nil
}

func RunCommand(ctx context.Context, name, dir string, args ...string) (io.Reader, error) {
	var stdout, stderr bytes.Buffer
	cmd, err := NewCommand(ctx, name, dir, &stdout, &stderr, args...)
	if err != nil {
		return nil, err
	}

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute %s, error: %w, stderr: %s", cmd.String(), err, stderr.String())
	}

	return &stdout, nil
}
