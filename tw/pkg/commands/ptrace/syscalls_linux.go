//go:build linux
// +build linux

package ptrace

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sys/unix"
)

const (
	cwdFD = unix.AT_FDCWD // AT_FDCWD = -0x64
)

// SyscallType defines types of syscalls we handle
type SyscallType string

const (
	CheckFileType SyscallType = "check_file" // Syscalls that check file existence (stat, access)
	OpenFileType  SyscallType = "open_file"  // Syscalls that open files (open, openat)
	ExecType      SyscallType = "exec"       // Syscalls that execute programs (execve, execveat)
)

// BaseSyscallHandler provides common functionality for syscall handlers
type BaseSyscallHandler struct {
	num         uint32
	name        string
	syscallType SyscallType
	stringParam int // Position of string param (0=none, 1=first, 2=second)
}

func (h *BaseSyscallHandler) SyscallNumber() int {
	return int(h.num)
}

func (h *BaseSyscallHandler) SyscallName() string {
	return h.name
}

func (h *BaseSyscallHandler) SyscallType() SyscallType {
	return h.syscallType
}

// OnCall extracts pathParam from syscall arguments
func (h *BaseSyscallHandler) OnCall(pid int, regs syscall.PtraceRegs, state *SyscallState) {
	var pth, dir string
	var fd int

	switch h.stringParam {
	case 0:
		// No string parameter
		return
	case 1:
		// First parameter is a path string
		pth = getStringParam(pid, getFirstParam(regs))
	case 2:
		// First parameter is a file descriptor, second is a path string
		fd = getIntParam(pid, getFirstParam(regs))

		// Handle AT_FDCWD specially
		if fd == cwdFD { // cwdFD = unix.AT_FDCWD
			dir, _ = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		} else if fd > 2 { // Skip stdin/stdout/stderr
			dir, _ = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		}

		pth = getStringParam(pid, getSecondParam(regs))
	}

	// Handle path resolution
	if len(pth) == 0 {
		// Empty path handling
		if dir != "" {
			// Empty path with directory fd
			pth = dir
		} else if fd == cwdFD {
			// Empty path with AT_FDCWD
			cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			pth = cwd
		}
	} else if pth[0] != '/' {
		// Relative path handling
		if dir != "" {
			// Relative to directory fd
			pth = path.Join(dir, pth)
		} else if fd == cwdFD {
			// Relative to current working directory
			cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
			if cwd != "" {
				pth = path.Join(cwd, pth)
			}
		}
	}

	// Some syscalls like readlinkat can have empty path with non-AT_FDCWD fd
	// In those cases, we want to use the fd's target as the path
	if pth == "" && fd > 2 {
		fdPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		if err == nil && fdPath != "" {
			pth = fdPath
		}
	}

	// Clean the path and store it
	if pth != "" {
		state.pathParam = filepath.Clean(pth)
	}
}

// OnReturn handles syscall return
func (h *BaseSyscallHandler) OnReturn(pid int, regs syscall.PtraceRegs, state *SyscallState) {
	// Default implementation does nothing
}

// Helper function to get string parameter from process memory
func getStringParam(pid int, ptr uint64) string {
	if ptr == 0 {
		return ""
	}

	var out [256]byte
	var data []byte
	for {
		count, err := syscall.PtracePeekData(pid, uintptr(ptr), out[:])
		if err != nil && err != syscall.EIO {
			clog.Errorf("Error reading string from pid %d at %x: %v", pid, ptr, err)
			return ""
		}

		if count <= 0 {
			break
		}

		idx := bytes.IndexByte(out[:count], 0)
		var foundNull bool
		if idx == -1 {
			idx = count
			ptr += uint64(count)
		} else {
			foundNull = true
		}

		data = append(data, out[:idx]...)
		if foundNull {
			return string(data)
		}
	}

	return string(data)
}

// Helper function to get integer parameter from syscall
func getIntParam(pid int, ptr uint64) int {
	return int(int32(ptr))
}

//-------- Specific handler types --------//

// FileCheckHandler handles syscalls that check file existence (stat, access, etc.)
type FileCheckHandler struct {
	BaseSyscallHandler
}

func NewFileCheckHandler(num uint32, name string, stringParam int) *FileCheckHandler {
	return &FileCheckHandler{
		BaseSyscallHandler: BaseSyscallHandler{
			num:         num,
			name:        name,
			syscallType: CheckFileType,
			stringParam: stringParam,
		},
	}
}

func (h *FileCheckHandler) OKReturnStatus(retVal uint64) bool {
	return int32(retVal) == 0 // For check calls, 0 is success
}

// FileOpenHandler handles syscalls that open files (open, openat, etc.)
type FileOpenHandler struct {
	BaseSyscallHandler
}

func NewFileOpenHandler(num uint32, name string, stringParam int) *FileOpenHandler {
	return &FileOpenHandler{
		BaseSyscallHandler: BaseSyscallHandler{
			num:         num,
			name:        name,
			syscallType: OpenFileType,
			stringParam: stringParam,
		},
	}
}

func (h *FileOpenHandler) OKReturnStatus(retVal uint64) bool {
	fd := int32(retVal)
	return fd >= 0 // For open-type calls, non-negative FD is success
}

// ExecHandler handles syscalls that execute programs (execve, execveat)
type ExecHandler struct {
	BaseSyscallHandler
}

func NewExecHandler(num uint32, name string, stringParam int) *ExecHandler {
	return &ExecHandler{
		BaseSyscallHandler: BaseSyscallHandler{
			num:         num,
			name:        name,
			syscallType: ExecType,
			stringParam: stringParam,
		},
	}
}

func (h *ExecHandler) OKReturnStatus(retVal uint64) bool {
	// For exec calls, success means the call doesn't return (new program takes over)
	// So if we get a return value, it generally means it failed
	fd := int(int32(retVal))
	return fd >= 0
}

// shouldSkipPath determines if a path should be excluded from tracking
func shouldSkipPath(path string) bool {
	// Skip common system paths and special files
	if path == "" || path == "." || path == "/" {
		return true
	}

	// Skip procfs
	if strings.HasPrefix(path, "/proc/") || path == "/proc" {
		return true
	}

	// Skip sysfs
	if strings.HasPrefix(path, "/sys/") || path == "/sys" {
		return true
	}

	// Skip devfs
	if strings.HasPrefix(path, "/dev/") || path == "/dev" {
		return true
	}

	return false
}

// truncatePath shortens a path to fit in maxLen characters
// It preserves the beginning and end of the path, removing the middle if needed
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}

	// Keep the first part and the last part, add ellipsis in between
	firstPart := maxLen / 2
	lastPart := maxLen - firstPart - 3 // for the "..."
	return path[:firstPart] + "..." + path[len(path)-lastPart:]
}
