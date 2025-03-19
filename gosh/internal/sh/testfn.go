package sh

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/gosh/internal/pipe"
	"go.opentelemetry.io/otel"
	"mvdan.cc/sh/v3/syntax"
)

type TestStatus int

const (
	TestStatusNotStarted TestStatus = iota
	TestStatusRunning
	TestStatusPassed
	TestStatusFailed
)

// TestFn represents a pipable shell test function
type TestFn struct {
	Name       string
	Status     TestStatus
	StdoutPipe *pipe.Pipe
	StderrPipe *pipe.Pipe

	exitCode chan int
}

// NewTestFn returns a new TestFn with the necessary named pipes created
func NewTestFn(decl *syntax.FuncDecl, workdir string) (*TestFn, error) {
	name := decl.Name.Value

	outp, err := pipe.New(filepath.Join(workdir, name+".stdout.pipe"))
	if err != nil {
		return nil, err
	}

	errp, err := pipe.New(filepath.Join(workdir, name+".stderr.pipe"))
	if err != nil {
		return nil, err
	}

	return &TestFn{
		Name:       name,
		Status:     TestStatusNotStarted,
		StdoutPipe: outp,
		StderrPipe: errp,

		exitCode: make(chan int),
	}, nil
}

// Run signals to the shell to begin, and blocks until the shell signals completion
func (f *TestFn) Run(ctx context.Context, t *testing.T) error {
	ctx, span := otel.Tracer("goshr").Start(ctx, t.Name())
	t.Cleanup(func() { span.End() })

	if f.Status != TestStatusNotStarted {
		return fmt.Errorf("TestFn %s is already running", f.Name)
	}
	f.Status = TestStatusRunning

	t.Cleanup(func() {
		if err := f.StdoutPipe.Close(); err != nil {
			t.Logf("closing stderr pipe: %v", err)
		}

		if err := f.StderrPipe.Close(); err != nil {
			t.Logf("closing stderr pipe: %v", err)
		}
	})

	go scanPipe(f.StdoutPipe, func(line string) { fmt.Fprintln(os.Stdout, line) })
	go scanPipe(f.StderrPipe, func(line string) { fmt.Fprintln(os.Stderr, line) })

	select {
	case code := <-f.exitCode:
		if code == 0 {
			t.Logf("[%s] finished successfully", f.Name)
			f.Status = TestStatusPassed
			return nil
		}

		t.Errorf("[%s] finished with error code %d", f.Name, code)
		f.Status = TestStatusFailed
		return fmt.Errorf("test finished with error code %d", code)

	case <-ctx.Done():
		t.Logf("[%s] context cancelled", f.Name)
		f.Status = TestStatusFailed
		return ctx.Err()

	case <-t.Context().Done():
		t.Logf("[%s] test context cancelled", f.Name)
		f.Status = TestStatusFailed
		return t.Context().Err()
	}
}

func (f *TestFn) End(exitCode int) error {
	if f.Status != TestStatusRunning {
		return fmt.Errorf("TestFn %s is not running", f.Name)
	}

	f.exitCode <- exitCode
	return nil
}

func scanPipe(p *pipe.Pipe, fn func(string)) error {
	r, err := p.Open()
	if err != nil {
		return fmt.Errorf("opening pipe: %v", err)
	}

	s := bufio.NewScanner(r)
	for s.Scan() {
		fn(s.Text())
	}

	if err := s.Err(); err != nil {
		return fmt.Errorf("reading from pipe: %v", err)
	}
	return nil
}
