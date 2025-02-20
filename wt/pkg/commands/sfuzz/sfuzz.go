package sfuzz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

const (
	DefaultTimeout = 30 * time.Second
)

var (
	DefaultCommonFlags = []string{"--version", "--help", "version", "-h", "-v", "-version", "-help", "-V"}
	DefaultBinDirs     = []string{"/bin", "/usr/bin", "/usr/local/bin"}
)

type cfg struct {
	Apk  string
	Bins []string
	Out  string
}

func Command() *cobra.Command {
	cfg := &cfg{}

	cmd := &cobra.Command{
		Use:   "sfuzz",
		Short: "A really simple, stupid binary fuzzer",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd, args)
		},
	}

	cmd.Flags().StringVarP(&cfg.Apk, "apk", "a", "", "apk name")
	cmd.Flags().StringSliceVarP(&cfg.Bins, "bin", "b", []string{}, "binaries to 'fuzz'")
	cmd.Flags().StringVarP(&cfg.Out, "out", "o", "sfuzz.out.json", "output file")

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	clog.InfoContext(ctx, "running sfuzz", "apk", c.Apk, "bins", c.Bins)

	// collection of commands to fuzz
	commands := []string{}

	if c.Apk != "" {
		clog.InfoContext(ctx, "looking for apk", "apk", c.Apk)

		a, err := apk.New()
		if err != nil {
			return fmt.Errorf("failed to create apk: %v", err)
		}

		pkgs, err := a.GetInstalled()
		if err != nil {
			return fmt.Errorf("failed to get installed packages: %v", err)
		}

		for _, pkg := range pkgs {
			if pkg.Name == c.Apk {
				clog.InfoContext(ctx, "found package", "pkg", pkg.Name)
				for _, f := range pkg.Files {
					p := "/" + f.Name

					ep, err := exec.LookPath(p)
					if err != nil {
						continue
					}

					// if its in a check directory
					for _, dir := range DefaultBinDirs {
						if strings.HasPrefix(ep, dir) {
							clog.InfoContext(ctx, "found executable", "exe", ep)
							commands = append(commands, ep)
							break
						}
					}
				}
			}
		}
	}

	if len(c.Bins) > 0 {
		clog.InfoContext(ctx, "using executables", "bins", c.Bins)
		commands = append(commands, c.Bins...)
	}

	thits := make([]success, 0)
	tfails := make([]error, 0)

	select {
	case <-ctx.Done():
	default:
		for _, cmd := range commands {
			chits, cerrs := fuzz(ctx, cmd, DefaultCommonFlags...)
			thits = append(thits, chits...)
			tfails = append(tfails, cerrs...)
		}
	}

	if len(thits) == 0 {
		clog.InfoContext(ctx, "all commands failed")
		for _, failure := range tfails {
			clog.InfoContextf(ctx, "--- %v", failure)
		}
		return fmt.Errorf("")
	}

	clog.InfoContextf(ctx, "found %d successes", len(thits))
	for _, success := range thits {
		clog.InfoContextf(ctx, "command '%s %s' exited with code %d", success.Command, success.Flag, success.ExitCode)
		clog.InfoContextf(ctx, "-- stdout: \n%s", success.stdout)
		clog.InfoContextf(ctx, "-- stderr: \n%v", success.stderr)
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(thits); err != nil {
		return fmt.Errorf("failed to encode json: %v", err)
	}

	return nil
}

type success struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Flag     string `json:"flag"`

	stdout string
	stderr string
}

func fuzz(ctx context.Context, command string, flags ...string) ([]success, []error) {
	var successes []success
	var failures []error

	for _, flag := range flags {
		cmd := exec.CommandContext(ctx, command, flag)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			failures = append(failures, err)
			continue
		}

		successes = append(successes, success{
			ExitCode: cmd.ProcessState.ExitCode(),
			stdout:   stdout.String(),
			stderr:   stderr.String(),
			Command:  command,
			Flag:     flag,
		})
		clog.InfoContextf(ctx, "--- [%s]: success hit with flag %q", command, flag)
	}

	return successes, failures
}
