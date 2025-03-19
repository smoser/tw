package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/chainguard-dev/gosh/internal/control"
	"github.com/spf13/cobra"
)

func main() {
	ctx := context.Background()

	rootCmd := &cobra.Command{
		Use:   "gt",
		Short: "The gosh cli",
	}

	rootCmd.AddCommand(
		ctrlCommand(),
		assertCommand(),
	)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

type ctrlOpts struct {
	op       string
	addr     string
	testName string
	exitCode int
	message  string
}

func ctrlCommand() *cobra.Command {
	o := &ctrlOpts{}
	cmd := &cobra.Command{
		Use:     "ctrl",
		Aliases: []string{"c"},
		Short:   "Control operations",
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&o.op, "op", "", "Operation to perform")
	cmd.Flags().StringVar(&o.addr, "addr", "", "Path to the control socket")
	cmd.Flags().StringVar(&o.testName, "test-name", "", "Name of the test to run")
	cmd.Flags().IntVar(&o.exitCode, "exit-code", 0, "Exit code to use")
	cmd.Flags().StringVar(&o.message, "message", "", "Optional message to include with the command")

	cmd.MarkFlagRequired("op")
	cmd.MarkFlagRequired("addr")
	cmd.MarkFlagRequired("test-name")

	return cmd
}

func (o *ctrlOpts) Run(ctx context.Context) error {
	cli := control.NewClient(o.addr)
	return cli.Send(control.Command(o.op), o.testName, o.exitCode, o.message)
}

func assertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "assert",
		Aliases:      []string{"a"},
		Short:        "Common assertions",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		assertEqualsCommand(),
	)

	return cmd
}

func assertEqualsCommand() *cobra.Command {
	o := &assertEqualsOpts{}

	cmd := &cobra.Command{
		Use:          "equal",
		Aliases:      []string{"equals", "eq", "e"},
		Short:        "Assert equality",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(cmd.Context(), args[0], args[1])
		},
	}

	return cmd
}

type assertEqualsOpts struct{}

func (o *assertEqualsOpts) Run(ctx context.Context, expected, actual string) error {
	// TODO: We can use go-cmp for pretty diffs, but its a pretty large dependency and I'm not sure if its worht it yet
	if strings.Compare(expected, actual) != 0 {
		return fmt.Errorf("assertion failed: expected '%s' to equal '%s'", expected, actual)
	}

	return nil
}

type assertContainsOpts struct{}

func (o *assertContainsOpts) Run(ctx context.Context, expected, actual any) error {
	if !strings.Contains(actual.(string), expected.(string)) {
		return fmt.Errorf("assertion failed: expected '%s' to contain '%s'", actual, expected)
	}

	return nil
}
