package sh_test

import (
	"context"
	"testing"
	"time"

	"github.com/chainguard-dev/gosh/internal/sh"
	"github.com/google/go-cmp/cmp"
	"mvdan.cc/sh/v3/syntax"
)

func TestTestFn_Run(t *testing.T) {
	tempDir := t.TempDir()

	// Helper function to create a test function
	createTestFn := func(name string) *sh.TestFn {
		lit := &syntax.Lit{Value: name}
		decl := &syntax.FuncDecl{Name: lit}

		fn, err := sh.NewTestFn(decl, tempDir)
		if err != nil {
			t.Fatalf("Failed to create TestFn: %v", err)
		}
		return fn
	}

	t.Run("rejects already running function", func(t *testing.T) {
		fn := createTestFn("already_running")
		fn.Status = sh.TestStatusRunning

		err := fn.Run(context.Background(), t)

		if err == nil {
			t.Fatal("Expected error for already running function, got nil")
		}

		want := "TestFn already_running is already running"
		if diff := cmp.Diff(want, err.Error()); diff != "" {
			t.Errorf("Error message mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("successful completion", func(t *testing.T) {
		fn := createTestFn("success_test")

		// Run in a separate goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- fn.Run(context.Background(), t)
		}()

		// Give time for goroutine to start
		time.Sleep(100 * time.Millisecond)

		// Send successful exit code
		if err := fn.End(0); err != nil {
			t.Fatalf("Failed to end test: %v", err)
		}

		// Check result
		select {
		case err := <-errCh:
			if diff := cmp.Diff(nil, err); diff != "" {
				t.Errorf("Error mismatch (-want +got):\n%s", diff)
			}

			wantStatus := sh.TestStatusPassed
			if diff := cmp.Diff(wantStatus, fn.Status); diff != "" {
				t.Errorf("Status mismatch (-want +got):\n%s", diff)
			}
		case <-time.After(time.Second):
			t.Fatal("Timed out waiting for Run to complete")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		fn := createTestFn("context_cancel_test")
		ctx, cancel := context.WithCancel(context.Background())

		// Run in a separate goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- fn.Run(ctx, t)
		}()

		// Give time for goroutine to start
		time.Sleep(100 * time.Millisecond)

		// Cancel the context
		cancel()

		// Check result
		select {
		case err := <-errCh:
			if err == nil {
				t.Error("Expected context cancellation error, got nil")
			} else if diff := cmp.Diff(context.Canceled.Error(), err.Error()); diff != "" {
				t.Errorf("Error message mismatch (-want +got):\n%s", diff)
			}

			wantStatus := sh.TestStatusFailed
			if diff := cmp.Diff(wantStatus, fn.Status); diff != "" {
				t.Errorf("Status mismatch (-want +got):\n%s", diff)
			}
		case <-time.After(time.Second):
			t.Fatal("Timed out waiting for Run to complete")
		}
	})
}
