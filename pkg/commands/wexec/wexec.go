package wexec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

type cfg struct{}

func Command() *cobra.Command {
	cfg := &cfg{}

	cmd := &cobra.Command{
		Use:   "wexec",
		Short: "Escape hatch to run an arbitrary script while respecting the shbang",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd, args)
		},
	}

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	clog.InfoContext(ctx, "running script", "path", args[0])

	path := args[0]

	fullPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	fi, err := os.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("failed to stat script: %w", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsRegular():
		// Make it executable if its not
		if err := os.Chmod(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to make script executable: %w", err)
		}

		command := exec.Command(fullPath)
		command.Stdout = cmd.OutOrStdout()
		command.Stderr = cmd.ErrOrStderr()

		err := command.Run()
		if err != nil {
			return fmt.Errorf("failed to run script: %w", err)
		}
	}

	return nil
}
