// echo is a simple command that echo's the arguments, its
// provided mainly as a simple example for creating a new
// testscript command
package echo

import (
	"fmt"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

type cfg struct{}

func Command() *cobra.Command {
	cfg := &cfg{}

	cmd := &cobra.Command{
		Use: "echo",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd, args)
		},
	}

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	clog.InfoContext(ctx, "log to stderr", "with", "attrs")
	fmt.Fprintln(cmd.OutOrStdout(), strings.Join(args, " "))
	return nil
}
