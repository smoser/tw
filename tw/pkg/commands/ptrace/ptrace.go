//go:build linux
// +build linux

package ptrace

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
)

type cfg struct {
	filterSyscall string
	output        string
}

func Command() *cobra.Command {
	cfg := &cfg{}

	cmd := &cobra.Command{
		Use:   "ptrace [command] [args...]",
		Short: "Trace system calls made by a command",
		Long: `Trace system calls made by a command and its child processes.
This tool shows file operations, network activity, and process execution in real-time.`,
		Example: `  tw ptrace ls -la
  tw ptrace curl https://example.com
  tw ptrace go build ./...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd, args)
		},
	}

	cmd.Flags().StringVar(&cfg.filterSyscall, "filter", "", "Only show syscalls matching this filter (comma-separated list)")
	cmd.Flags().StringVarP(&cfg.output, "output", "o", "text", "Output format (text, json)")

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	startTime := time.Now()

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Create a context that will be canceled when we receive a signal
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			// Cancel the context when we receive a signal
			cancel()
		}
	}()

	// Create syscall filter if specified
	var filters []string
	if c.filterSyscall != "" {
		filters = strings.Split(c.filterSyscall, ",")
		for i, f := range filters {
			filters[i] = strings.TrimSpace(f)
		}
	}

	topts := TracerOpts{
		Args:     args,
		Filter:   filters,
		Stdout:   cmd.OutOrStdout(),
		Stderr:   cmd.ErrOrStderr(),
		SignalCh: signalCh,
	}

	if c.output == "json" {
		topts.Stdout = cmd.ErrOrStderr()
	}

	// Create tracer instance
	tracer, err := New(args, topts)
	if err != nil {
		return err
	}

	clog.InfoContextf(ctx, "tracing command: %s", strings.Join(args, " "))
	clog.InfoContextf(ctx, "press ctrl+c to stop tracing")

	if err := tracer.Start(ctx); err != nil {
		return err
	}

	report := tracer.Wait()

	switch c.output {
	case "text":
		fmt.Fprintf(os.Stdout, "\nTracing completed in %s\n", time.Since(startTime))
		fmt.Fprintf(os.Stdout, "Total syscalls: %d\n", report.TotalSyscalls)

		// Show file activity if requested
		// Show file system activity
		if len(report.FSActivity) > 0 {
			fmt.Fprintf(os.Stdout, "\nFile system activity:\n")
			fmt.Fprintf(os.Stdout, "%-50s %-10s %-10s\n", "Path", "Operations", "Processes")
			fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("-", 72))

			// Sort paths for consistent output
			paths := make([]string, 0, len(report.FSActivity))
			for path := range report.FSActivity {
				paths = append(paths, path)
			}
			sort.Strings(paths)

			for _, path := range paths {
				info := report.FSActivity[path]
				fmt.Fprintf(os.Stdout, "%-50s %-10d %-10d\n",
					truncatePath(path, 50),
					info.OpsAll,
					len(info.Pids))
			}
		} else {
			fmt.Fprintf(os.Stdout, "\nNo file system activity detected\n")
		}

		// Show syscall statistics
		if len(report.SyscallStats) > 0 {
			fmt.Fprintf(os.Stdout, "\nSyscall statistics:\n")
			fmt.Fprintf(os.Stdout, "%-20s %-10s\n", "Syscall", "Count")
			fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("-", 32))

			// Get syscall names and sort for consistent output
			type syscallInfo struct {
				num   uint32
				count uint64
				name  string
			}

			syscalls := make([]syscallInfo, 0, len(report.SyscallStats))
			for num, count := range report.SyscallStats {
				name := getSyscallName(num)
				syscalls = append(syscalls, syscallInfo{num: num, count: count, name: name})
			}

			// Sort by count (descending)
			sort.Slice(syscalls, func(i, j int) bool {
				return syscalls[i].count > syscalls[j].count
			})

			// Show top 10 syscalls
			limit := 10
			if len(syscalls) < limit {
				limit = len(syscalls)
			}

			for i := 0; i < limit; i++ {
				fmt.Fprintf(os.Stdout, "%-20s %-10d\n", syscalls[i].name, syscalls[i].count)
			}
		}

	case "json":
		// Write some slimmed down version of the report, we don't want to just
		// blindly serialize since its a ton of variable stuff

		if len(report.FSActivity) > 0 {
			paths := make([]string, 0, len(report.FSActivity))
			for path := range report.FSActivity {
				paths = append(paths, path)
			}

			var out struct {
				Args          []string          `json:"args"`
				FilesAccessed map[string]uint64 `json:"files_accessed"`
			}
			out.Args = tracer.args
			out.FilesAccessed = make(map[string]uint64, len(paths))

			for _, path := range paths {
				info := report.FSActivity[path]
				out.FilesAccessed[path] = info.OpsAll
			}

			b, err := json.MarshalIndent(out, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal report: %v", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", b)
		}

	default:
		return fmt.Errorf("invalid output format: %s", c.output)
	}

	return nil
}
