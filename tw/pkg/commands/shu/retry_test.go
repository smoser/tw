package shu

import (
	"context"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCommand(t *testing.T) {
	shellArgs := []string{"[[ 'x' == 'y' ]] || (echo \"bad\" >&2; exit 10)"} // NOTE: Add `set -x;` at the start to see what's going on.

	c := newCommand(context.Background(), true, shellArgs)

	err := c.Run()
	require.NotNil(t, err) // We're expecting an error here since exit >0

	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)

	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	code := status.ExitStatus()
	require.Equal(t, 10, code)
}
