//go:build linux
// +build linux

package main_test

import "github.com/chainguard-dev/tw/pkg/commands/ptrace"

func init() {
	cmds["ptrace"] = ptrace.Command()
}
