package main_test

import (
	"bytes"
	"context"
	"embed"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/chainguard-dev/gosh/internal/control"
	"github.com/chainguard-dev/gosh/internal/decorator"
	"github.com/chainguard-dev/gosh/internal/sh"
	"mvdan.cc/sh/v3/syntax"
)

const (
	TestPrefix = "gt_"
)

//go:embed framework.sh.tpl
var frameworkFS embed.FS

var traceFile = flag.String("trace-file", "", "path to file to write trace data to")

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestShell(t *testing.T) {
	if len(flag.Args()) == 0 {
		fmt.Println("no path to script provided")
		os.Exit(1)
	}

	scriptPath := flag.Args()[0]

	tdir, err := os.MkdirTemp("", "gosh-")
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewRunner(tdir, scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	tp, err := traceProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tp.Shutdown(ctx)
	}()

	ctx, span := tp.Tracer("goshr").Start(t.Context(), t.Name())
	t.Cleanup(func() { span.End() })

	t.Run(r.Name, func(t *testing.T) {
		if err := r.Run(ctx, t); err != nil {
			t.Fatal(err)
		}
	})
}

type Runner struct {
	Name           string
	ScriptPath     string
	TestFns        map[string]*sh.TestFn
	OrderedTestFns []string
	WorkDir        string

	prog       *syntax.File
	decorators []*decorator.Decorator
}

func NewRunner(wdir, scriptPath string) (*Runner, error) {
	r := &Runner{
		ScriptPath:     scriptPath,
		TestFns:        make(map[string]*sh.TestFn),
		OrderedTestFns: make([]string, 0),
		WorkDir:        wdir,

		decorators: make([]*decorator.Decorator, 0),
	}

	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, err
	}

	r.Name = filepath.Base(scriptPath)
	r.prog, err = syntax.NewParser(syntax.KeepComments(true)).Parse(bytes.NewBuffer(raw), r.Name)
	if err != nil {
		return nil, err
	}

	var tfnerr error
	var cstmt *syntax.Stmt

	syntax.Walk(r.prog, func(n syntax.Node) bool {
		if n == nil {
			return true
		}

		if stmt, ok := n.(*syntax.Stmt); ok {
			cstmt = stmt
		}

		fn, ok := n.(*syntax.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Value, TestPrefix) {
			return true
		}

		// Extract annotations from comments
		decorations := make([]decorator.Decoration, 0)
		if cstmt != nil && cstmt.Cmd == fn {
			for _, comment := range cstmt.Comments {
				text := comment.Text
				if strings.HasPrefix(strings.TrimSpace(text), "@gt") {
					d, err := decorator.NewDecoration(comment)
					if err != nil {
						tfnerr = fmt.Errorf("at function '%s': %v", fn.Name.Value, err)
						return false
					}
					decorations = append(decorations, d)
				}
			}
		}

		if len(decorations) > 0 {
			d, err := decorator.New(fn, decorations...)
			if err != nil {
				tfnerr = err
				return false
			}
			r.decorators = append(r.decorators, d)
		}

		tfn, err := sh.NewTestFn(fn, r.WorkDir)
		if err != nil {
			tfnerr = err
			return false
		}

		r.TestFns[fn.Name.Value] = tfn
		r.OrderedTestFns = append(r.OrderedTestFns, fn.Name.Value)
		return true
	})
	if tfnerr != nil {
		return nil, tfnerr
	}

	return r, nil
}

func (r *Runner) Run(ctx context.Context, t *testing.T) error {
	ctx, span := otel.Tracer("goshr").Start(ctx, t.Name())
	t.Cleanup(func() { span.End() })

	wpath, err := r.render()
	if err != nil {
		return err
	}

	t.Logf("rendered wrapped script to: %s", wpath)

	cs := control.NewServer(func(msg control.Message) error {
		tfn, ok := r.TestFns[msg.TestName]
		if !ok {
			return fmt.Errorf("unknown test: %s", msg.TestName)
		}

		switch msg.Command {
		case control.CommandStart:
			go t.Run(msg.TestName, func(subt *testing.T) {
				if err := tfn.Run(ctx, subt); err != nil {
					subt.Errorf("failed to run test: %v", err)
				}
			})

			return nil
		case control.CommandStop:
			return tfn.End(msg.ExitCode)
		case control.CommandSkip:
			t.Run(tfn.Name, func(t *testing.T) {
				_, span := otel.Tracer("goshr").Start(ctx, t.Name())
				t.Cleanup(func() { span.End() })

				t.Skipf("[%s] skipped: %s", tfn.Name, msg.Message)
			})
			return nil
		}

		return fmt.Errorf("unknown command: %s", msg.Command)
	})

	if err := cs.Start(); err != nil {
		return err
	}
	defer cs.Stop()

	cmd := exec.CommandContext(ctx, wpath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GOSH_CONTROL_ADDR="+cs.Addr())

	if err := cmd.Run(); err != nil {
		// The wrapper script doesn't use set -e, so all errors are internal errors and should be floated as such
		return fmt.Errorf("error running test script: %w", err)
	}

	return nil
}

// render will render the wrapped script
func (r *Runner) render() (string, error) {
	tpl := template.New("framework.sh.tpl").Funcs(template.FuncMap{
		"loadScript": func() (string, error) {
			f, err := os.Open(r.ScriptPath)
			if err != nil {
				return "", err
			}
			defer f.Close()

			for _, d := range r.decorators {
				if err := d.Decorate(); err != nil {
					return "", err
				}
			}

			var buf bytes.Buffer
			if err := syntax.NewPrinter().Print(&buf, r.prog); err != nil {
				return "", err
			}

			return buf.String(), nil
		},
	})

	var err error
	tpl, err = tpl.ParseFS(frameworkFS, "framework.sh.tpl")
	if err != nil {
		return "", err
	}

	wrapped, err := os.Create(filepath.Join(r.WorkDir, "wgosh.sh"))
	if err != nil {
		return "", err
	}
	defer wrapped.Close()

	if err := tpl.Execute(wrapped, r); err != nil {
		return "", err
	}

	if err := os.Chmod(wrapped.Name(), 0755); err != nil {
		return "", err
	}

	return wrapped.Name(), nil
}

func traceProvider() (*sdktrace.TracerProvider, error) {
	w := io.Discard

	if *traceFile != "" {
		f, err := os.Create(*traceFile)
		if err != nil {
			return nil, err
		}
		w = f
	}

	exporter, err := stdouttrace.New(stdouttrace.WithWriter(w))
	if err != nil {
		return nil, fmt.Errorf("error creating stdout trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("gosh-runner"),
		)),
	)

	otel.SetTracerProvider(tp)

	return tp, nil
}
