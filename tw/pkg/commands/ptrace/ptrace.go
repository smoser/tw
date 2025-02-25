//go:build linux
// +build linux

package ptrace

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type cfg struct {
	verbose       bool
	summarize     bool
	showReturns   bool
	filterSyscall string
	showCategory  bool
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
  tw ptrace --verbose go build ./...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cfg.Run(cmd, args)
		},
	}

	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "v", false, "Show more detailed syscall information")
	cmd.Flags().BoolVarP(&cfg.summarize, "summarize", "s", true, "Show summary statistics at the end")
	cmd.Flags().BoolVar(&cfg.showReturns, "show-returns", false, "Show syscall return values")
	cmd.Flags().StringVar(&cfg.filterSyscall, "filter", "", "Only show syscalls matching this filter (comma-separated list)")
	cmd.Flags().BoolVar(&cfg.showCategory, "categorize", false, "Group syscalls by category in summary")

	return cmd
}

func (c *cfg) Run(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	ctx := cmd.Context()
	startTime := time.Now()

	tracer, err := New(args, TracerOpts{
		Args: args,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Tracing command: %s\n", strings.Join(args, " "))
	fmt.Fprintf(os.Stdout, "Press Ctrl+C to stop tracing\n\n")

	if err := tracer.Start(ctx); err != nil {
		return err
	}

	// Create statistics trackers
	stats := make(map[string]int)
	fileOps := make(map[string]struct{})
	execOps := make(map[string]struct{})
	networkOps := make(map[string]struct{})
	memoryOps := make(map[string]struct{})
	processOps := make(map[string]struct{})
	signalOps := make(map[string]struct{})
	timeOps := make(map[string]struct{})
	securityOps := make(map[string]struct{})
	ipcOps := make(map[string]struct{})

	// Create syscall filter if specified
	var filters []string
	if c.filterSyscall != "" {
		filters = strings.Split(c.filterSyscall, ",")
		for i, f := range filters {
			filters[i] = strings.TrimSpace(f)
		}
	}

	// Set up a done channel to signal event processing completion
	eventsDone := make(chan struct{})

	go func() {
		defer close(eventsDone)
		fmt.Fprintf(os.Stderr, "DEBUG: Starting event processing goroutine\n")
		eventCount := 0

		for {
			select {
			case e, ok := <-tracer.Events():
				if !ok {
					// Channel closed, we're done
					fmt.Fprintf(os.Stderr, "DEBUG: Events channel closed, exiting event processor\n")
					return
				}
				eventCount++
				fmt.Fprintf(os.Stderr, "DEBUG: Received event #%d: %s (pid=%d) type=%v\n",
					eventCount, e.SyscallName, e.Pid, e.Type)

				// Skip if filtering is enabled and this syscall doesn't match
				if len(filters) > 0 {
					match := false
					for _, f := range filters {
						if strings.Contains(e.SyscallName, f) {
							match = true
							break
						}
					}
					if !match {
						fmt.Fprintf(os.Stderr, "DEBUG: Filtering out %s (doesn't match filters)\n", e.SyscallName)
						continue
					}
				}

				// Skip return events if not requested
				if !c.showReturns && strings.HasSuffix(e.SyscallName, "-return") {
					fmt.Fprintf(os.Stderr, "DEBUG: Skipping return event %s\n", e.SyscallName)
					continue
				}

				// Track statistics for summary
				prevCount, _ := stats[e.SyscallName]
				stats[e.SyscallName]++
				fmt.Fprintf(os.Stderr, "DEBUG: Incremented stats for %s: %d -> %d\n",
					e.SyscallName, prevCount, stats[e.SyscallName])

				// Track operations by category
				if !strings.HasSuffix(e.SyscallName, "-return") {
					// Track file operations
					if IsFileOpSyscall(e.Syscall) {
						if e.Path != "" {
							fileOps[e.Path] = struct{}{}
							fmt.Fprintf(os.Stderr, "DEBUG: Added file operation: %s\n", e.Path)
						} else {
							fmt.Fprintf(os.Stderr, "DEBUG: File operation with empty path for %s\n", e.SyscallName)
						}
					} else if e.Type == EventExec {
						if e.Path != "" {
							execOps[e.Path] = struct{}{}
							fmt.Fprintf(os.Stderr, "DEBUG: Added exec operation: %s\n", e.Path)
						}
					}

					// Track network operations
					if IsNetworkSyscall(e.Syscall) {
						networkOps[e.Path] = struct{}{}
						fmt.Fprintf(os.Stderr, "DEBUG: Added network operation: %s\n", e.Path)
					}

					// Track by category for extended classification
					if IsMemorySyscall(e.Syscall) {
						memoryOps[e.SyscallName] = struct{}{}
					}
					if IsProcessSyscall(e.Syscall) {
						processOps[e.SyscallName] = struct{}{}
					}
					if IsSignalSyscall(e.Syscall) {
						signalOps[e.SyscallName] = struct{}{}
					}
					if IsTimeSyscall(e.Syscall) {
						timeOps[e.SyscallName] = struct{}{}
					}
					if IsSecuritySyscall(e.Syscall) {
						securityOps[e.SyscallName] = struct{}{}
					}
					if IsIpcSyscall(e.Syscall) {
						ipcOps[e.SyscallName] = struct{}{}
					}
				}

				// Format and print event
				var eventStr string

				if c.verbose {
					var category string
					if IsFileOpSyscall(e.Syscall) {
						category = "file"
					} else if IsNetworkSyscall(e.Syscall) {
						category = "net"
					} else if IsExecSyscall(e.Syscall) {
						category = "exec"
					} else if IsMemorySyscall(e.Syscall) {
						category = "mem"
					} else if IsProcessSyscall(e.Syscall) {
						category = "proc"
					} else if IsSignalSyscall(e.Syscall) {
						category = "sig"
					} else if IsTimeSyscall(e.Syscall) {
						category = "time"
					} else if IsSecuritySyscall(e.Syscall) {
						category = "sec"
					} else if IsIpcSyscall(e.Syscall) {
						category = "ipc"
					} else {
						category = "misc"
					}

					if e.ReturnVal != 0 {
						if c.showCategory {
							eventStr = fmt.Sprintf("[%d][%s] %s: %s (retval=%d)",
								e.Pid, category, e.SyscallName, e.Path, e.ReturnVal)
						} else {
							eventStr = fmt.Sprintf("[%d] %s: %s (retval=%d)",
								e.Pid, e.SyscallName, e.Path, e.ReturnVal)
						}
					} else {
						if c.showCategory {
							eventStr = fmt.Sprintf("[%d][%s] %s: %s",
								e.Pid, category, e.SyscallName, e.Path)
						} else {
							eventStr = fmt.Sprintf("[%d] %s: %s",
								e.Pid, e.SyscallName, e.Path)
						}
					}
				} else {
					// More concise format
					if strings.HasSuffix(e.SyscallName, "-return") {
						eventStr = fmt.Sprintf("└─ %s → %s",
							strings.TrimSuffix(e.SyscallName, "-return"), e.Path)
					} else {
						eventStr = fmt.Sprintf("┌─ %s: %s", e.SyscallName, e.Path)
					}
				}

				fmt.Fprintln(os.Stdout, eventStr)
			}
		}
	}()

	<-tracer.Wait()

	// Wait for tracer to finish, but also monitor the context
	select {
	case <-eventsDone:
		fmt.Fprintf(os.Stderr, "DEBUG: Events channel closed, exiting event processor\n")
	case <-ctx.Done():
		// Context was canceled
		fmt.Fprintf(os.Stderr, "DEBUG: Context canceled, stopping tracer\n")
		tracer.Stop()
	}

	// Print summary if requested
	if c.summarize {
		duration := time.Since(startTime)

		fmt.Fprintf(os.Stdout, "\n=== Summary ===\n")
		fmt.Fprintf(os.Stdout, "Command completed in: %v\n", duration)

		// Print top syscalls by frequency
		fmt.Fprintf(os.Stdout, "\nTop syscalls:\n")
		type syscallCount struct {
			name  string
			count int
		}
		var counts []syscallCount
		for name, count := range stats {
			if !strings.HasSuffix(name, "-return") {
				counts = append(counts, syscallCount{name, count})
			}
		}
		sort.Slice(counts, func(i, j int) bool {
			return counts[i].count > counts[j].count
		})

		// Print top 10 or fewer
		limit := 10
		if len(counts) < limit {
			limit = len(counts)
		}
		for i := 0; i < limit; i++ {
			fmt.Fprintf(os.Stdout, "  %-15s: %d\n", counts[i].name, counts[i].count)
		}

		// Print categorized operations if requested
		if c.showCategory {
			printCategoryMap := func(title string, operations map[string]struct{}) {
				if len(operations) > 0 {
					fmt.Fprintf(os.Stdout, "\n%s (%d):\n", title, len(operations))
					items := make([]string, 0, len(operations))
					for op := range operations {
						items = append(items, op)
					}
					sort.Strings(items)
					for _, item := range items {
						fmt.Fprintf(os.Stdout, "  - %s\n", item)
					}
				}
			}

			printCategoryMap("Memory operations", memoryOps)
			printCategoryMap("Process operations", processOps)
			printCategoryMap("Signal operations", signalOps)
			printCategoryMap("Time operations", timeOps)
			printCategoryMap("Security operations", securityOps)
			printCategoryMap("IPC operations", ipcOps)
		}

		// Print file operations summary
		if len(fileOps) > 0 {
			fmt.Fprintf(os.Stdout, "\nFile operations (%d):\n", len(fileOps))
			paths := make([]string, 0, len(fileOps))
			for path := range fileOps {
				paths = append(paths, path)
			}
			sort.Strings(paths)

			// Print limited number of accessed files
			limit := 15
			if len(paths) < limit {
				limit = len(paths)
			}
			for i := 0; i < limit; i++ {
				fmt.Fprintf(os.Stdout, "  - %s\n", paths[i])
			}
			if len(paths) > limit {
				fmt.Fprintf(os.Stdout, "  ... and %d more\n", len(paths)-limit)
			}
		}

		// Print executed commands summary
		if len(execOps) > 0 {
			fmt.Fprintf(os.Stdout, "\nExecuted commands (%d):\n", len(execOps))
			execs := make([]string, 0, len(execOps))
			for path := range execOps {
				execs = append(execs, path)
			}
			sort.Strings(execs)

			for _, exec := range execs {
				fmt.Fprintf(os.Stdout, "  - %s\n", exec)
			}
		}

		// Print network operations summary
		if len(networkOps) > 0 {
			fmt.Fprintf(os.Stdout, "\nNetwork operations (%d):\n", len(networkOps))
			nets := make([]string, 0, len(networkOps))
			for op := range networkOps {
				nets = append(nets, op)
			}
			sort.Strings(nets)

			for _, net := range nets {
				fmt.Fprintf(os.Stdout, "  - %s\n", net)
			}
		}
	}

	return nil
}
