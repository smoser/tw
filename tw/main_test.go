package main_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tw/pkg/commands/kgrep"
	"github.com/chainguard-dev/tw/pkg/commands/kimages"
	"github.com/chainguard-dev/tw/pkg/commands/sfuzz"
	"github.com/chainguard-dev/tw/pkg/commands/shu"
	"github.com/chainguard-dev/tw/pkg/commands/wassert"
	"github.com/rogpeppe/go-internal/testscript"
	"github.com/spf13/cobra"
)

var (
	script = flag.String("script", "", "path to script to run, will take precedence over dir")
	dir    = flag.String("dir", "", "path to directory with scripts to run")
	update = flag.Bool("update", false, "update relevant golden files")
)

func TestMain(m *testing.M) {
	cmds := commands()

	// First check if we're being called as a multicall
	ename := filepath.Base(os.Args[0])
	if cmd, ok := cmds[ename]; ok {
		if err := cmd.Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// If its not a multicall, then just build the regular command hierarchy
	cmd := &cobra.Command{
		Use:          "tw",
		SilenceUsage: true,
	}

	for _, c := range cmds {
		cmd.AddCommand(c)
	}

	// Add the special test subcommand
	cmd.AddCommand(
		&cobra.Command{
			Use:                "test",
			DisableFlagParsing: true,
			Run: func(cmd *cobra.Command, args []string) {
				// Parse test flags after removing "test" from args
				// This allows `tw test --script foo` to work like `go test --args --script foo`
				os.Args = append([]string{os.Args[0]}, args...)
				flag.Parse()
				os.Exit(m.Run())
			},
		},
	)

	// Add a helper command for creating the multicall symlinks
	cmd.AddCommand(
		&cobra.Command{
			Use:    "list-multicalls",
			Hidden: true,
			Run: func(cmd *cobra.Command, args []string) {
				names := make([]string, 0)
				for _, c := range cmds {
					names = append(names, c.Name())
				}
				sort.Strings(names)
				fmt.Fprint(cmd.OutOrStdout(), strings.Join(names, " "))
			},
		},
	)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func commands() map[string]*cobra.Command {
	return map[string]*cobra.Command{
		"sfuzz":   sfuzz.Command(),
		"kgrep":   kgrep.Command(),
		"kimages": kimages.Command(),
		"wassert": wassert.Command(),
		"shu":     shu.Command(),
	}
}

func TestScript(t *testing.T) {
	files := []string{}
	if *script != "" {
		files = append(files, *script)
	} else if *dir != "" {
	} else {
		clog.FatalContext(context.Background(), "script or dir flag is required")
		os.Exit(1)
	}

	// All tests spawned will share the same parent context from the test
	ctx := t.Context()

	tscmds := map[string]func(ts *testscript.TestScript, neg bool, args []string){}
	for n, cmd := range commands() {
		tscmds[n] = RegisterCmd(ctx, cmd)
	}

	testscript.Run(t, testscript.Params{
		Files:         files,
		Dir:           *dir,
		UpdateScripts: *update,
		Setup: func(e *testscript.Env) error {
			return os.Chdir(e.WorkDir)
		},
		Cmds: tscmds,
	})
}

func RegisterCmd(ctx context.Context, cmd *cobra.Command) func(ts *testscript.TestScript, neg bool, args []string) {
	return func(ts *testscript.TestScript, neg bool, args []string) {
		ctx = clog.WithLogger(ctx, clog.New(NewTestScriptLogger(ts).Handler()))
		cmd.SetArgs(args)
		cmd.SetOut(ts.Stdout())
		cmd.SetErr(ts.Stderr())

		// Throw an error only if the command is expected to fail
		err := cmd.ExecuteContext(ctx)
		if neg {
			if err == nil {
				ts.Fatalf("expected command to fail but it didn't")
			}
		} else {
			if err != nil {
				ts.Fatalf("failed to execute command: %v", err)
			}
		}
	}
}

type TestScriptHandler struct {
	ts *testscript.TestScript
}

func NewTestScriptLogger(ts *testscript.TestScript) *slog.Logger {
	return slog.New(&TestScriptHandler{ts: ts})
}

func (h *TestScriptHandler) Handle(ctx context.Context, rec slog.Record) error {
	var sb strings.Builder
	sb.WriteString(rec.Message)

	rec.Attrs(func(a slog.Attr) bool {
		sb.WriteString(fmt.Sprintf(" %s=%v", a.Key, a.Value))
		return true
	})

	_, err := fmt.Fprintf(h.ts.Stderr(), "%s\n", sb.String())
	return err
}

func (h *TestScriptHandler) WithAttrs(attrs []slog.Attr) slog.Handler           { return h }
func (h *TestScriptHandler) WithGroup(name string) slog.Handler                 { return h }
func (h *TestScriptHandler) Enabled(ctx context.Context, level slog.Level) bool { return true }
