//go:build linux
// +build linux

package ptrace

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-radix"
	"github.com/chainguard-dev/clog"
	"golang.org/x/sys/unix"
)

// AT_FDCWD is the "current working directory" file descriptor
const AT_FDCWD = -100

// handleSyscall is a shared implementation for handling syscalls across
// architectures
func handleSyscall(t *Tracer, pid int) {
	// Register this tracer for this PID before we access registers
	// This ensures other threads know we're handling this PID
	processRegistry.Set(pid, t)

	// Try to get the registers with better error handling
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		clog.Debugf("Failed to get registers for PID %d: %v", pid, err)

		// Handle common errors specially
		if strings.Contains(err.Error(), "no such process") {
			// Process terminated while we were handling it
			clog.Infof("Process %d no longer exists, cleaning up", pid)
			t.statesMu.Lock()
			delete(t.states, pid)
			t.statesMu.Unlock()

			processRegistry.Delete(pid)

			select {
			case t.events <- Event{
				Type: EventExit,
				Pid:  pid,
				Path: fmt.Sprintf("process %d terminated", pid),
			}:
				clog.Debugf("sent termination event for %d", pid)
			default:
				clog.Warnf("Event channel full, dropping termination event for pid=%d", pid)
			}
		} else {
			// For other errors, try to continue the process to avoid hanging
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				// If this also fails with "no such process", the process is gone
				if strings.Contains(err.Error(), "no such process") {
					clog.Infof("Process %d terminated during error handling, cleaning up", pid)
					t.statesMu.Lock()
					delete(t.states, pid)
					t.statesMu.Unlock()
					processRegistry.Delete(pid)
				} else {
					clog.Warnf("Failed to continue process after register error: %v", err)
				}
			}
		}
		return
	}

	// Use the architecture handler to get the syscall number
	syscallNum := archHandler.GetSyscallNumber(regs)

	// Get syscall name (doesn't require locking the state)
	syscallName := getSyscallName(syscallNum)

	// We already registered this tracer for this PID when we called processRegistry.Set

	clog.Debugf("SYSCALL: %s | syscallNum: %d | pid: %d", syscallName, syscallNum, pid)

	// Get processor for this syscall if available
	processor := GetSyscallProcessor(syscallNum)

	// Acquire state lock to access the pid's state
	t.statesMu.Lock()

	// Make sure we have a state for this PID
	state, exists := t.states[pid]
	if !exists {
		// Create new state for this PID since it doesn't exist
		state = &syscallState{
			pid:          pid,
			callNum:      syscallNum,
			expectReturn: true,
			gotCallNum:   true,
			fdTable:      make(map[int]FD),
			childPids:    make(map[int]bool),
			startTime:    time.Now(),
		}
		t.states[pid] = state
		clog.Debugf("Created new state for PID %d", pid)
		t.statesMu.Unlock()

		// Handle syscall entry for a new process
		if processor != nil {
			clog.Debugf("Calling OnCall for %s (syscallNum=%d) pid=%d",
				processor.SyscallName(), syscallNum, pid)

			// Make a copy to work with
			stateCopy := *state
			processor.OnCall(pid, regs, &stateCopy)

			// Update state with processor results
			t.statesMu.Lock()
			if state, ok := t.states[pid]; ok {
				state.pathParam = stateCopy.pathParam
				state.pathParamErr = stateCopy.pathParamErr
				state.dirfd = stateCopy.dirfd
			}

			// Get values needed for event before releasing lock
			var eventPath string
			var dirfd int
			if st, ok := t.states[pid]; ok {
				eventPath = st.pathParam
				dirfd = st.dirfd
			}
			t.statesMu.Unlock()

			// Generate event for syscalls that do this on call rather than return
			if processor.EventOnCall() {
				if dirfd != 0 && dirfd != AT_FDCWD {
					eventPath = t.resolvePath(pid, eventPath, dirfd)
				}

				// Send event non-blocking to avoid deadlocks
				select {
				case t.events <- Event{
					Type:        EventSyscall,
					Syscall:     syscallNum,
					SyscallName: syscallName,
					Pid:         pid,
					Path:        eventPath,
				}:
					// Event sent successfully
					clog.Debugf("Sent event for %s (pid=%d)", syscallName, pid)
				default:
					// Channel is full, log warning and continue
					clog.Warnf("Event channel full, dropping event for syscall %s", syscallName)
				}
			}
		} else {
			// Re-acquire lock for the fallback handler
			t.statesMu.Lock()
			if st, ok := t.states[pid]; ok {
				state = st
			}
			t.statesMu.Unlock()

			// Fallback for syscalls without processors
			handleSyscallEnter(t, pid, syscallNum, syscallName, regs, state)
		}
	} else if state.expectReturn {
		// This is syscall exit
		retVal := archHandler.CallReturnValue(regs)

		// Update state for syscall return
		state.retVal = retVal
		state.gotRetVal = true

		// Make copies of needed values before modifying state
		eventPath := state.pathParam
		dirfd := state.dirfd
		callNum := state.callNum
		pathParamErr := state.pathParamErr

		// Reset state for next syscall
		state.expectReturn = false
		state.callNum = 0
		state.pathParam = ""
		state.pathParamErr = nil
		state.dirfd = 0

		// Release lock after updating state
		t.statesMu.Unlock()

		// Handle syscall exit
		if processor != nil {
			clog.Debugf("Calling OnReturn for %s (syscallNum=%d) pid=%d",
				processor.SyscallName(), syscallNum, pid)

			// Create a working copy with needed values restored
			stateCopy := syscallState{
				pid:          pid,
				callNum:      callNum,
				retVal:       retVal,
				gotRetVal:    true,
				pathParam:    eventPath,
				pathParamErr: pathParamErr,
				dirfd:        dirfd,
				fdTable:      make(map[int]FD), // Create a new map to avoid modifying the original
			}

			// Copy relevant parts of fdTable if needed by processor
			t.statesMu.RLock()
			if st, ok := t.states[pid]; ok {
				for k, v := range st.fdTable {
					stateCopy.fdTable[k] = v
				}
			}
			t.statesMu.RUnlock()

			// Call processor with our copy
			processor.OnReturn(pid, regs, &stateCopy)

			// Send event if needed
			if !processor.EventOnCall() && pathParamErr == nil {
				if dirfd != 0 && dirfd != AT_FDCWD {
					eventPath = t.resolvePath(pid, eventPath, dirfd)
				}

				// Non-blocking send to avoid deadlocks
				select {
				case t.events <- Event{
					Type:        EventSyscall,
					Syscall:     callNum,
					SyscallName: syscallName + "-return",
					Pid:         pid,
					Path:        eventPath,
					ReturnVal:   int64(retVal),
				}:
					// Event sent successfully
					clog.Debugf("Sent return event for %s (pid=%d)", syscallName, pid)
				default:
					// Channel is full, log warning and continue
					clog.Warnf("Event channel full, dropping return event for syscall %s", syscallName)
				}
			}

			// Check if processor updated fdTable and merge changes back if needed
			// This avoids losing file descriptor information
			t.statesMu.Lock()
			if st, ok := t.states[pid]; ok {
				// Merge any new fds processor might have added
				for fdNum, fdInfo := range stateCopy.fdTable {
					if _, exists := st.fdTable[fdNum]; !exists {
						st.fdTable[fdNum] = fdInfo
					}
				}
			}
			t.statesMu.Unlock()
		} else {
			// Get a fresh copy of state for the fallback handler
			t.statesMu.Lock()
			if st, ok := t.states[pid]; ok {
				// Restore needed values in the state
				st.callNum = callNum
				st.retVal = retVal
				st.gotRetVal = true
				state = st
			}
			t.statesMu.Unlock()

			// Fallback for syscalls without processors
			handleSyscallExit(t, pid, regs, state, syscallName)
		}
	} else {
		// This is a new syscall after a completed one
		state.callNum = syscallNum
		state.expectReturn = true
		state.gotCallNum = true
		state.gotRetVal = false
		t.statesMu.Unlock()

		// Call recursively to handle the new syscall
		// This is safe because we updated the state before releasing the lock
		handleSyscall(t, pid)
	}
}

// handleSyscallEnter handles the common syscall entry logic
func handleSyscallEnter(t *Tracer, pid int, syscallNum uint32, syscallName string, regs unix.PtraceRegs, state *syscallState) {
	// Function to safely send events with non-blocking behavior
	sendEvent := func(event Event) {
		select {
		case t.events <- event:
			// Event sent successfully
			clog.Debugf("Sent event for %s (pid=%d)", event.SyscallName, event.Pid)
		default:
			// Channel is full, log warning and continue
			clog.Warnf("Event channel full, dropping event for syscall %s", event.SyscallName)
		}
	}

	switch syscallNum {
	case unix.SYS_READ, unix.SYS_PREAD64:
		fd := archHandler.CallFirstParam(regs)
		bufSize := archHandler.CallThirdParam(regs)

		// Try to get the file path associated with this fd
		path := fmt.Sprintf("fd: %d", fd)

		// Create a safe copy of the fdTable to avoid locking during event processing
		fdPath := ""
		t.statesMu.RLock()
		if state != nil {
			if fdInfo, ok := state.fdTable[int(fd)]; ok {
				fdPath = fdInfo.Path
			}
		}
		t.statesMu.RUnlock()

		if fdPath != "" {
			path = fmt.Sprintf("fd: %d (%s)", fd, fdPath)
		}

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        fmt.Sprintf("%s, size: %d bytes", path, bufSize),
		})

	case unix.SYS_WRITE, unix.SYS_PWRITE64:
		fd := archHandler.CallFirstParam(regs)
		bufSize := archHandler.CallThirdParam(regs)

		// Try to get the file path associated with this fd
		path := fmt.Sprintf("fd: %d", fd)

		// Get FD info safely
		fdPath := ""
		t.statesMu.RLock()
		if state != nil && state.fdTable != nil {
			if fdInfo, ok := state.fdTable[int(fd)]; ok {
				fdPath = fdInfo.Path
			}
		}
		t.statesMu.RUnlock()

		if fdPath != "" {
			path = fmt.Sprintf("fd: %d (%s)", fd, fdPath)
		}

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        fmt.Sprintf("%s, size: %d bytes", path, bufSize),
		})

	case unix.SYS_CLOSE:
		fd := archHandler.CallFirstParam(regs)

		// Try to get the file path associated with this fd
		path := fmt.Sprintf("fd: %d", fd)
		fdPath := ""

		t.statesMu.Lock()
		if state != nil && state.fdTable != nil {
			if fdInfo, ok := state.fdTable[int(fd)]; ok {
				fdPath = fdInfo.Path
				// Store the fd being closed for use in return
				state.pathParam = fdInfo.Path
			}
		}
		t.statesMu.Unlock()

		if fdPath != "" {
			path = fmt.Sprintf("fd: %d (%s)", fd, fdPath)
		}

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        path,
		})

	case unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN:
		domain := archHandler.CallFirstParam(regs)
		sockType := archHandler.CallSecondParam(regs)
		protocol := archHandler.CallThirdParam(regs)

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        fmt.Sprintf("domain: %d, type: %d, protocol: %d", domain, sockType, protocol),
		})

	case unix.SYS_ACCEPT, unix.SYS_ACCEPT4:
		sockfd := archHandler.CallFirstParam(regs)

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        fmt.Sprintf("sockfd: %d", sockfd),
		})

	case unix.SYS_MMAP:
		length := archHandler.CallSecondParam(regs)
		prot := archHandler.CallThirdParam(regs)
		flags := archHandler.CallFourthParam(regs)

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     syscallNum,
			SyscallName: syscallName,
			Pid:         pid,
			Path:        fmt.Sprintf("length: %d, prot: 0x%x, flags: 0x%x", length, prot, flags),
		})

	case unix.SYS_CHDIR:
		pathAddr := archHandler.CallFirstParam(regs)
		if path, err := getStringParam(pid, pathAddr); err == nil && path != "" {
			// Update state in a single lock acquisition
			t.statesMu.Lock()
			if state != nil {
				state.pathParam = path

				// Update the process's current working directory
				if filepath.IsAbs(path) {
					state.cwd = path
				} else {
					// Make sure cwd is initialized
					if state.cwd == "" {
						// Try to get cwd from /proc if available
						if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
							state.cwd = cwd
						} else {
							// Default to current directory
							if wd, err := os.Getwd(); err == nil {
								state.cwd = wd
							} else {
								state.cwd = "/"
							}
						}
					}
					state.cwd = filepath.Clean(filepath.Join(state.cwd, path))
				}
			}
			t.statesMu.Unlock()

			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     syscallNum,
				SyscallName: syscallName,
				Pid:         pid,
				Path:        path,
			})
		}
	}
}

// handleSyscallExit handles the common syscall exit logic
func handleSyscallExit(t *Tracer, pid int, regs unix.PtraceRegs, state *syscallState, syscallName string) {
	// Function to safely send events with non-blocking behavior
	sendEvent := func(event Event) {
		select {
		case t.events <- event:
			// Event sent successfully
			clog.Debugf("Sent return event for %s (pid=%d)", event.SyscallName, event.Pid)
		default:
			// Channel is full, log warning and continue
			clog.Warnf("Event channel full, dropping return event for syscall %s", event.SyscallName)
		}
	}

	// Safely get values we need from state
	var callNum uint32
	var pathParam string

	// We need to be careful as state could be null if process terminated
	if state != nil {
		t.statesMu.RLock()
		callNum = state.callNum
		pathParam = state.pathParam
		t.statesMu.RUnlock()
	} else {
		// If state is null, use syscall number from regs
		callNum = archHandler.GetSyscallNumber(regs)
	}

	retVal := archHandler.CallReturnValue(regs)
	sretVal := int64(retVal)

	switch callNum {
	case unix.SYS_READ, unix.SYS_PREAD64, unix.SYS_WRITE, unix.SYS_PWRITE64:
		if sretVal >= 0 {
			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     callNum,
				SyscallName: getSyscallName(callNum) + "-return",
				Pid:         pid,
				Path:        fmt.Sprintf("returned %d bytes", sretVal),
				ReturnVal:   sretVal,
			})
		} else {
			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     callNum,
				SyscallName: getSyscallName(callNum) + "-return",
				Pid:         pid,
				Path:        fmt.Sprintf("error: %d", -sretVal),
				ReturnVal:   sretVal,
			})
		}

	case unix.SYS_CLOSE:
		fdVal := archHandler.CallFirstParam(regs)
		// Remove from file descriptor table if successful
		if sretVal == 0 && pathParam != "" && state != nil {
			t.statesMu.Lock()
			if state.fdTable != nil {
				delete(state.fdTable, int(fdVal))
			}
			t.statesMu.Unlock()
		}

		sendEvent(Event{
			Type:        EventSyscall,
			Syscall:     callNum,
			SyscallName: getSyscallName(callNum) + "-return",
			Pid:         pid,
			Path:        fmt.Sprintf("returned %d", sretVal),
			ReturnVal:   sretVal,
		})

	case unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_SOCKET:
		if sretVal >= 0 {
			// For socket() specifically, add the file descriptor
			if callNum == unix.SYS_SOCKET {
				t.statesMu.Lock()
				if state != nil && state.fdTable != nil {
					state.fdTable[int(sretVal)] = FD{
						Path:     fmt.Sprintf("<socket:%d>", sretVal),
						Type:     "socket",
						OpenTime: time.Now(),
					}
				}
				t.statesMu.Unlock()
			}

			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     callNum,
				SyscallName: getSyscallName(callNum) + "-return",
				Pid:         pid,
				Path:        fmt.Sprintf("success: fd %d", sretVal),
				ReturnVal:   sretVal,
			})
		} else {
			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     callNum,
				SyscallName: getSyscallName(callNum) + "-return",
				Pid:         pid,
				Path:        fmt.Sprintf("error: %d", -sretVal),
				ReturnVal:   sretVal,
			})
		}

	case unix.SYS_DUP, unix.SYS_DUP3:
		// Handle file descriptor duplication
		if sretVal >= 0 {
			// Get the source fd
			srcFd := int(archHandler.CallFirstParam(regs))
			newFd := int(sretVal)

			// Copy file descriptor info if available
			t.statesMu.Lock()
			if state != nil && state.fdTable != nil {
				if srcFdInfo, ok := state.fdTable[srcFd]; ok {
					state.fdTable[newFd] = FD{
						Path:     srcFdInfo.Path,
						Type:     srcFdInfo.Type,
						OpenTime: time.Now(),
					}
				}
			}
			t.statesMu.Unlock()

			sendEvent(Event{
				Type:        EventSyscall,
				Syscall:     callNum,
				SyscallName: getSyscallName(callNum) + "-return",
				Pid:         pid,
				Path:        fmt.Sprintf("dup %d -> %d", srcFd, newFd),
				ReturnVal:   sretVal,
			})
		}
	}
}

type Event struct {
	Type        EventType
	Syscall     uint32
	SyscallName string
	Pid         int
	Path        string
	ReturnVal   int64
}

type SyscallEvent struct {
	Regs     unix.PtraceRegs
	Sysno    int
	Args     SyscallArgument
	Ret      [2]SyscallArgument
	Errno    unix.Errno
	Duration time.Duration
}

type SyscallArguments [6]SyscallArgument

type SyscallArgument struct {
	Value uintptr
}

type EventType int

const (
	EventSyscall EventType = iota
	EventFork
	EventExec
	EventExit
)

// FSActivity represents information about file system activity
type FSActivity struct {
	Ops           int              // Total operations on this path
	OpsRead       int              // Read operations
	OpsWrite      int              // Write operations
	OpsExec       int              // Execution operations
	OpsCheckFile  int              // File check operations (stat, access, etc.)
	OpsOpenFile   int              // File open operations
	Pids          map[int]struct{} // Set of PIDs that accessed this path
	Syscalls      map[int]struct{} // Set of syscalls used to access this path
	IsSubdir      bool             // Whether this path is a subdirectory of another tracked path
	LastOperation time.Time        // Last time this path was accessed
}

// FSActivityType categorizes the types of file system operations
type FSActivityType string

const (
	// Operation type constants
	FSActivityTypeRead      FSActivityType = "read"
	FSActivityTypeWrite     FSActivityType = "write"
	FSActivityTypeExec      FSActivityType = "exec"
	FSActivityTypeCheckFile FSActivityType = "check"
	FSActivityTypeOpenFile  FSActivityType = "open"
)

// FSActivityTracker tracks file system activity using a radix tree for efficient
// path-based lookups and prefix searching
type FSActivityTracker struct {
	tree         *radix.Tree
	includeNew   bool                // Whether to include new paths not in origPaths
	origPaths    map[string]struct{} // Original paths to track
	skipPrefixes []string            // Path prefixes to skip (e.g., /proc/, /sys/, /dev/)
	mu           sync.RWMutex        // For thread-safe access to the tree
}

// NewFSActivityTracker creates a new file system activity tracker
func NewFSActivityTracker() *FSActivityTracker {
	return &FSActivityTracker{
		tree:         radix.New(),
		includeNew:   true, // Default to including all paths
		origPaths:    make(map[string]struct{}),
		skipPrefixes: []string{"/proc/", "/sys/", "/dev/"},
	}
}

// SetPathFiltering configures whether to include only original paths or all new paths
func (f *FSActivityTracker) SetPathFiltering(includeNew bool, origPaths map[string]struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.includeNew = includeNew
	f.origPaths = origPaths
}

// ShouldTrackPath determines if a path should be tracked based on filtering rules
func (f *FSActivityTracker) ShouldTrackPath(path string) bool {
	// Skip if path is in skip prefixes
	for _, prefix := range f.skipPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	// Skip "." since it's not useful
	if path == "." {
		return false
	}

	// If including all new paths, accept all non-skipped paths
	if f.includeNew {
		return true
	}

	// Otherwise, check if it's in original paths
	f.mu.RLock()
	_, ok := f.origPaths[path]
	f.mu.RUnlock()
	return ok
}

// AddActivity records file system activity for a path
func (f *FSActivityTracker) AddActivity(path string, pid int, syscallNum int, opType FSActivityType) {
	// Clean and normalize the path
	path = filepath.Clean(path)

	// Check if we should track this path
	if !f.ShouldTrackPath(path) {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Get or create activity record
	raw, found := f.tree.Get(path)
	var activity *FSActivity
	if !found {
		activity = &FSActivity{
			Pids:     make(map[int]struct{}),
			Syscalls: make(map[int]struct{}),
		}
	} else {
		activity = raw.(*FSActivity)
	}

	// Update activity information
	activity.Ops++
	activity.Pids[pid] = struct{}{}
	activity.Syscalls[syscallNum] = struct{}{}
	activity.LastOperation = time.Now()

	// Update operation type counts
	switch opType {
	case FSActivityTypeRead:
		activity.OpsRead++
	case FSActivityTypeWrite:
		activity.OpsWrite++
	case FSActivityTypeExec:
		activity.OpsExec++
	case FSActivityTypeCheckFile:
		activity.OpsCheckFile++
	case FSActivityTypeOpenFile:
		activity.OpsOpenFile++
	}

	// Store the updated activity
	f.tree.Insert(path, activity)
}

// GetActivityMap returns a map of all file system activity
// with subdirectory information calculated, filtering out subdirectories
func (f *FSActivityTracker) GetActivityMap() map[string]*FSActivity {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Mark subdirectories
	f.tree.Walk(func(key string, value interface{}) bool {
		value.(*FSActivity).IsSubdir = false // Reset first

		// Check if this key is a prefix of any other keys
		f.tree.WalkPrefix(key, func(subkey string, subvalue interface{}) bool {
			if subkey != key && filepath.Dir(subkey) == key {
				subvalue.(*FSActivity).IsSubdir = true
			}
			return false
		})
		return false
	})

	// Build the result map, excluding subdirectories
	result := make(map[string]*FSActivity)
	f.tree.Walk(func(key string, value interface{}) bool {
		activity := value.(*FSActivity)
		if !activity.IsSubdir {
			result[key] = activity
		}
		return false
	})

	return result
}

type Tracer struct {
	args            []string
	cmd             *exec.Cmd
	events          chan Event
	done            chan struct{}
	running         bool
	statesMu        sync.RWMutex
	states          map[int]*syscallState
	fsTracker       *FSActivityTracker
	opts            TracerOpts
	collectorDoneCh chan int
}

type TracerOpts struct {
	Name string
	Args []string
}

// GetFileSystemActivity returns the file system activity tracked by this tracer
func (t *Tracer) GetFileSystemActivity() map[string]*FSActivity {
	return t.fsTracker.GetActivityMap()
}

func New(args []string, opts TracerOpts) (*Tracer, error) {
	return &Tracer{
		args:            args,
		events:          make(chan Event, 10000),
		done:            make(chan struct{}),
		running:         false,
		states:          make(map[int]*syscallState),
		fsTracker:       NewFSActivityTracker(),
		collectorDoneCh: make(chan int, 2),
		opts:            opts,
	}, nil
}

func (t *Tracer) Start(ctx context.Context) error {
	if t.running {
		return fmt.Errorf("tracer is already running")
	}
	t.running = true

	cmd := exec.CommandContext(ctx, t.args[0], t.args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace:  true,
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		t.running = false
		return fmt.Errorf("failed to start command: %w", err)
	}

	t.cmd = cmd
	mainPid := cmd.Process.Pid
	clog.Infof("Started process with PID %d", mainPid)

	// Wait for the first TRAP which indicates the process is stopped and ready to be traced
	var ws unix.WaitStatus
	pid, err := unix.Wait4(mainPid, &ws, 0, nil)
	if err != nil {
		t.running = false
		return fmt.Errorf("failed to wait for initial trap: %w", err)
	}

	clog.Infof("Process initial status: pid=%d, status=%v (Exited=%v, Signaled=%v, Stopped=%v, StopSignal=%v, TrapCause=%v)",
		pid, ws, ws.Exited(), ws.Signaled(), ws.Stopped(), ws.StopSignal(), ws.TrapCause())

	if !ws.Stopped() {
		t.running = false
		return fmt.Errorf("process not stopped after start (pid=%d, status=%v)", pid, ws)
	}

	clog.Infof("Process stopped for tracing (pid=%d, signal=%v)", pid, ws.StopSignal())

	// Configure tracing options
	const ptOpts = unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_TRACEEXIT |
		unix.PTRACE_O_EXITKILL

	if err := unix.PtraceSetOptions(mainPid, ptOpts); err != nil {
		t.running = false
		return fmt.Errorf("failed to set ptrace options: %w", err)
	}

	// Verify the process is still alive
	if err := unix.Kill(mainPid, 0); err != nil {
		t.running = false
		return fmt.Errorf("process died after setting ptrace options: %w", err)
	}

	// Initialize the tracer's state map with the first process
	cwd, _ := os.Getwd()
	initialState := &syscallState{
		pid:       mainPid,
		cwd:       cwd,
		fdTable:   make(map[int]FD),
		childPids: make(map[int]bool),
		startTime: time.Now(),
		started:   true, // Mark as started immediately
	}

	t.statesMu.Lock()
	t.states[mainPid] = initialState
	t.statesMu.Unlock()

	go t.processEvents(ctx)

	if err := unix.PtraceSyscall(mainPid, 0); err != nil {
		t.running = false
		return fmt.Errorf("failed to set initial syscall trace: %w", err)
	}

	// Start the tracing goroutine
	go t.trace(ctx, cmd)
	return nil
}

func (t *Tracer) Wait() <-chan struct{} {
	return t.done
}

func (t *Tracer) Events() <-chan Event {
	return t.events
}

func (t *Tracer) Stop() {
	t.running = false
}

// syscallState tracks the state of a syscall being processed
type syscallState struct {
	pid          int          // Process ID
	callNum      uint32       // System call number
	retVal       uint64       // Return value from syscall
	expectReturn bool         // Whether we're expecting a return from this syscall
	gotCallNum   bool         // Whether we've gotten the syscall number
	gotRetVal    bool         // Whether we've gotten the return value
	started      bool         // Whether the process has started
	exiting      bool         // Whether the process is exiting
	pathParam    string       // Path parameter for syscalls that operate on paths
	pathParamErr error        // Error when retrieving path parameter
	dirfd        int          // Tracks directory file descriptor for *at syscalls
	cwd          string       // Current working directory of the process
	fdTable      map[int]FD   // Maps file descriptors to their paths
	parentPid    int          // Parent process ID
	childPids    map[int]bool // Child process IDs
	startTime    time.Time    // Process start time
}

// FD represents a file descriptor and its associated information
type FD struct {
	Path     string // The path this file descriptor refers to
	Type     string // Type of file descriptor (regular, socket, pipe, etc)
	OpenTime time.Time
}

func (t *Tracer) trace(ctx context.Context, cmd *exec.Cmd) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Correctly handle cleanup but avoid sleep-based synchronization
	defer func() {
		clog.InfoContext(ctx, "Trace function exiting")
		close(t.events)
		close(t.done)
	}()

	// Get current working directory at the start
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/" // Default to root if we can't get current directory
		clog.ErrorContextf(ctx, "failed to get current working directory: %v", err)
	}

	// Process group handling
	mainPid := cmd.Process.Pid
	pgid, err := unix.Getpgid(mainPid)
	if err != nil {
		clog.ErrorContextf(ctx, "failed to get process group ID: %v", err)
		// Continue anyway, we'll just track individual processes
	} else {
		clog.InfoContextf(ctx, "tracking process group ID: %d", pgid)
	}

	// Initialize state tracking based on your implementation
	mainExiting := false
	_ = mainExiting
	waitFor := mainPid
	callSig := 0 // No signal initially

	// Initialize process state similar to your implementation
	t.statesMu.Lock()
	if _, exists := t.states[mainPid]; !exists {
		// In case it wasn't initialized yet
		t.states[mainPid] = &syscallState{
			pid:       mainPid,
			cwd:       cwd,
			fdTable:   make(map[int]FD),
			childPids: make(map[int]bool),
			startTime: time.Now(),
			started:   true,
		}
	}
	t.statesMu.Unlock()

	for {
		select {
		case <-ctx.Done():
			clog.InfoContext(ctx, "context done, exiting tracer")
			return
		default:
			// Continue with syscall tracing, matching your implementation style
			clog.DebugContextf(ctx, "trace syscall (pid=%v sig=%v)", waitFor, callSig)
			err := unix.PtraceSyscall(waitFor, callSig)
			if err != nil {
				if strings.Contains(err.Error(), "no such process") {
					// Process might have terminated very quickly
					clog.Debugf("PtraceSyscall: Process %d no longer exists", waitFor)

					// If this was the main process and we're just starting
					if waitFor == mainPid {
						clog.Warnf("Main process %d terminated very quickly after initial stop", mainPid)

						// Check if process actually exists via /proc
						_, procErr := os.Stat(fmt.Sprintf("/proc/%d", mainPid))
						if procErr != nil && os.IsNotExist(procErr) {
							clog.Infof("Confirmed main process %d no longer exists", mainPid)
							// Report exit
							select {
							case t.events <- Event{
								Type:        EventExit,
								Pid:         mainPid,
								SyscallName: "exit",
								Path:        fmt.Sprintf("process %d exited very quickly", mainPid),
							}:
							default:
								clog.Warnf("Failed to send exit event, channel full")
							}

							select {
							case t.done <- struct{}{}:
							default:
							}
							return
						}
					}

					// Try waiting for any process instead
					waitFor = -1
					continue
				} else {
					clog.ErrorContextf(ctx, "failed to syscall ptrace syscall: %v", err)
				}
			}
			callSig = 0 // Reset signal after use

			// Wait for syscall or other ptrace events
			var ws unix.WaitStatus
			wpid, err := unix.Wait4(waitFor, &ws, unix.WALL, nil)

			// Additional debug for first loop iteration
			if waitFor == mainPid {
				clog.Debugf("First wait4 after stop - result: pid=%d, error=%v, status=%v",
					wpid, err, ws)
			}

			if err != nil {
				if err == unix.ECHILD {
					clog.InfoContext(ctx, "no more child processes")
					return
				}
				clog.Warnf("wait4 error: %v (errno=%d)", err, err.(syscall.Errno))

				// If this was the first wait for main PID, handle specially
				if waitFor == mainPid {
					clog.Warnf("Error waiting for main PID on first trace iteration")
					// Check if process exists
					_, procErr := os.Stat(fmt.Sprintf("/proc/%d", mainPid))
					if procErr != nil && os.IsNotExist(procErr) {
						clog.Infof("Main process %d no longer exists after first start", mainPid)
						// Report exit and terminate
						t.events <- Event{
							Type:        EventExit,
							Pid:         mainPid,
							SyscallName: "exit",
							Path:        "main process exited immediately",
						}
						select {
						case t.done <- struct{}{}:
						default:
						}
						return
					}
				}
				waitFor = -1
				continue
			}

			// Debug output for event type
			eventType := "unknown"
			if ws.Exited() {
				eventType = "exited"
			} else if ws.Signaled() {
				eventType = "signaled"
			} else if ws.Stopped() {
				eventType = "stopped"
			}
			clog.DebugContextf(ctx, "wait4 => pid=%d event=%s status=%d", wpid, eventType, ws)

			// Handle the event based on type
			if ws.Exited() {
				// Process exited normally
				exitStatus := ws.ExitStatus()
				clog.InfoContextf(ctx, "process %d exited with status: %d", wpid, exitStatus)

				// Clean up from registry and state tracking
				processRegistry.Delete(wpid)

				// Clean up our states map
				t.statesMu.Lock()
				// Update parent to remove this child if known
				if state, exists := t.states[wpid]; exists && state.parentPid != 0 {
					if parentState, parentExists := t.states[state.parentPid]; parentExists {
						delete(parentState.childPids, wpid)
					}
				}

				// Remove the process from our tracked states
				delete(t.states, wpid)

				// Check if this was the main process
				if wpid == mainPid {
					mainExiting = true
					clog.InfoContext(ctx, "main process exited")
				}

				// Exit if no more processes to track
				hasProcesses := len(t.states) > 0
				t.statesMu.Unlock()

				if !hasProcesses {
					clog.InfoContext(ctx, "all processes exited, stopping tracer")
					return
				}

				waitFor = -1 // Wait for any process
				continue
			}

			if ws.Signaled() {
				// Process terminated by signal
				signum := ws.Signal()
				clog.InfoContextf(ctx, "process %d terminated by signal: %v", wpid, signum)

				// Clean up state
				processRegistry.Delete(wpid)

				t.statesMu.Lock()
				delete(t.states, wpid)

				if wpid == mainPid {
					mainExiting = true
				}

				hasProcesses := len(t.states) > 0
				t.statesMu.Unlock()

				if !hasProcesses {
					clog.InfoContext(ctx, "all processes exited, stopping tracer")
					return
				}

				waitFor = -1
				continue
			}

			if ws.Stopped() {
				sig := ws.StopSignal()
				trapCause := ws.TrapCause()

				// Handle different stop causes
				if (sig == unix.SIGTRAP) && ((trapCause&0xff) == unix.PTRACE_EVENT_CLONE ||
					(trapCause&0xff) == unix.PTRACE_EVENT_FORK ||
					(trapCause&0xff) == unix.PTRACE_EVENT_VFORK) {

					// Handle new process creation
					newPid, err := unix.PtraceGetEventMsg(wpid)
					if err != nil {
						clog.ErrorContextf(ctx, "failed to get event message for clone/fork: %v", err)
					} else {
						newPidInt := int(newPid)
						clog.InfoContextf(ctx, "new process created: parent=%d child=%d", wpid, newPidInt)

						// Create state for the new process
						t.statesMu.Lock()
						if parentState, exists := t.states[wpid]; exists {
							// Copy parent's state for child
							childState := &syscallState{
								pid:       newPidInt,
								parentPid: wpid,
								cwd:       parentState.cwd,
								fdTable:   make(map[int]FD),
								childPids: make(map[int]bool),
								startTime: time.Now(),
							}

							// Copy FDs from parent
							for fd, info := range parentState.fdTable {
								childState.fdTable[fd] = info
							}

							// Add to tracking
							t.states[newPidInt] = childState

							// Add to parent's children
							parentState.childPids[newPidInt] = true
						} else {
							// Parent not found, create minimal state
							t.states[newPidInt] = &syscallState{
								pid:       newPidInt,
								parentPid: wpid,
								fdTable:   make(map[int]FD),
								childPids: make(map[int]bool),
								startTime: time.Now(),
							}
						}
						t.statesMu.Unlock()
					}

					// Continue process
					if err := unix.PtraceSyscall(wpid, 0); err != nil {
						clog.ErrorContextf(ctx, "failed to continue process after clone/fork: %v", err)
					}

					waitFor = -1 // Wait for any process
					continue
				}

				// Handle exec events
				if (sig == unix.SIGTRAP) && ((trapCause & 0xff) == unix.PTRACE_EVENT_EXEC) {
					clog.InfoContextf(ctx, "process %d executed a new program", wpid)

					// Update state for exec'd process
					t.statesMu.Lock()
					if state, exists := t.states[wpid]; exists {
						// Reset file descriptors except stdin/stdout/stderr
						newFdTable := make(map[int]FD)
						for fd := 0; fd <= 2; fd++ {
							if oldFd, hasOld := state.fdTable[fd]; hasOld {
								newFdTable[fd] = oldFd
							}
						}
						state.fdTable = newFdTable

						// Try to update working directory
						if procCwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", wpid)); err == nil {
							state.cwd = procCwd
						}
					}
					t.statesMu.Unlock()

					// Continue process
					if err := unix.PtraceSyscall(wpid, 0); err != nil {
						clog.ErrorContextf(ctx, "failed to continue process after exec: %v", err)
					}

					waitFor = -1
					continue
				}

				// Handle exit notifications
				if (sig == unix.SIGTRAP) && ((trapCause & 0xff) == unix.PTRACE_EVENT_EXIT) {
					t.statesMu.Lock()
					if state, exists := t.states[wpid]; exists {
						state.exiting = true
					}
					t.statesMu.Unlock()

					clog.InfoContextf(ctx, "process %d is about to exit", wpid)

					if wpid == mainPid {
						mainExiting = true
						clog.InfoContext(ctx, "main process is about to exit")
					}

					// Continue the process to let it exit
					if err := unix.PtraceSyscall(wpid, 0); err != nil {
						clog.ErrorContextf(ctx, "failed to continue exiting process: %v", err)
					}

					waitFor = -1
					continue
				}

				// Handle syscall stop
				if sig == unix.SIGTRAP|0x80 {
					// Process syscall
					handleSyscall(t, wpid)

					// Continue with syscall tracing
					if err := unix.PtraceSyscall(wpid, 0); err != nil {
						if strings.Contains(err.Error(), "no such process") {
							// Process might have terminated between wait4 and here
							clog.DebugContextf(ctx, "process no longer exists pid=%v", wpid)
						} else {
							clog.ErrorContextf(ctx, "failed to continue process after syscall: %v", err)
						}
					}

					waitFor = -1
					continue
				}

				// Forward other stop signals to the process
				callSig = int(sig)
				if err := unix.PtraceSyscall(wpid, callSig); err != nil {
					clog.ErrorContextf(ctx, "failed to continue process with signal: %v", err)
				}

				waitFor = -1
				continue
			}
		}
	}
}

// Add an event processor function that handles events and completion
func (t *Tracer) processEvents(ctx context.Context) {
	defer func() {
		clog.InfoContext(ctx, "Event processor exiting")
	}()

	for {
		select {
		case <-ctx.Done():
			clog.InfoContext(ctx, "Context cancelled, stopping event processor")
			return

		case event, ok := <-t.events:
			if !ok {
				clog.InfoContext(ctx, "Event channel closed")
				return
			}

			// Process the event
			clog.DebugContextf(ctx, "Processing event: %s (pid=%d path=%s)",
				event.SyscallName, event.Pid, event.Path)

			// Handle special event types
			if event.Type == EventExit {
				clog.InfoContextf(ctx, "Process exit event: %d", event.Pid)

				// Check if this is the main process
				if event.Pid == t.cmd.Process.Pid {
					clog.InfoContext(ctx, "Main process exited")
					return
				}
			}
		}
	}
}

func getStringParam(pid int, addr uint64) (string, error) {
	// Start with a smaller buffer for efficiency
	buf := make([]byte, 256)
	_, err := unix.PtracePeekData(pid, uintptr(addr), buf)
	if err != nil {
		return "", fmt.Errorf("error reading string parameter: %w", err)
	}

	// Find null terminator
	end := bytes.IndexByte(buf, 0)
	if end == -1 {
		// If not found in the small buffer, try a larger one
		buf = make([]byte, 4096)
		_, err := unix.PtracePeekData(pid, uintptr(addr), buf)
		if err != nil {
			return "", fmt.Errorf("error reading string parameter with larger buffer: %w", err)
		}

		end = bytes.IndexByte(buf, 0)
		if end == -1 {
			// If still not found, this might be an invalid string pointer
			return "", fmt.Errorf("unable to find null terminator in string at 0x%x", addr)
		}
	}

	return string(buf[:end]), nil
}

// fdName returns a human-readable name for common file descriptors
func fdName(fd int) string {
	switch fd {
	case 0:
		return "STDIN"
	case 1:
		return "STDOUT"
	case 2:
		return "STDERR"
	case AT_FDCWD:
		return "AT_FDCWD"
	}
	return ""
}

// resolvePath resolves a path based on the process state
// It handles relative paths, AT_FDCWD, and absolute paths
func (t *Tracer) resolvePath(pid int, path string, dirfd int) string {
	// If it's an absolute path, just return it regardless of state
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	// First check if the process exists before trying to access it
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		if os.IsNotExist(err) {
			// Process is already gone, just clean the path and return
			clog.Debugf("Process %d no longer exists when resolving path %s, using best effort", pid, path)
			return filepath.Clean(path)
		}
	}

	// Get state safely
	t.statesMu.RLock()
	state, ok := t.states[pid]

	// Make local copies of needed values under lock
	var cwd, fdPath string
	var parentPid int

	if ok && state != nil {
		cwd = state.cwd
		parentPid = state.parentPid

		// If path is empty and dirfd is valid, try to get fd path
		if path == "" && dirfd > 0 && state.fdTable != nil {
			if fd, fdOk := state.fdTable[dirfd]; fdOk {
				fdPath = fd.Path
			}
		} else if dirfd != AT_FDCWD && state.fdTable != nil {
			// Try to get file descriptor path for non-AT_FDCWD
			if fd, fdOk := state.fdTable[dirfd]; fdOk {
				fdPath = fd.Path
			}
		}
	}
	t.statesMu.RUnlock()

	// If we don't have state for this pid or cwd is empty, try to determine from /proc
	if !ok || cwd == "" {
		// Double-check process exists before accessing /proc
		_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		if err != nil {
			if os.IsNotExist(err) {
				// Process is gone, just clean the path and return
				clog.Debugf("Process %d no longer exists when trying to get cwd, using best effort", pid)
				return filepath.Clean(path)
			}
		}

		procCwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			// Cache in our state for future use
			if ok {
				t.statesMu.Lock()
				if st, exists := t.states[pid]; exists && st != nil {
					st.cwd = procCwd
				}
				t.statesMu.Unlock()
			}

			// For relative paths, join with cwd
			if !filepath.IsAbs(path) && path != "" {
				return filepath.Clean(filepath.Join(procCwd, path))
			}
			cwd = procCwd
		}

		// If no cwd found and path is relative, use current directory as fallback
		if cwd == "" && !filepath.IsAbs(path) && path != "" {
			wd, err := os.Getwd()
			if err == nil {
				return filepath.Clean(filepath.Join(wd, path))
			}
			// Ultimate fallback
			return filepath.Clean(path)
		}
	}

	// Handle empty paths specially, some syscalls use empty path to operate on the dirfd itself
	if path == "" && dirfd > 0 {
		if fdPath != "" {
			return fdPath
		}

		// Try to resolve from /proc if not in our fd table
		dirPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
		if err == nil {
			// Cache for future use
			t.statesMu.Lock()
			if st, exists := t.states[pid]; exists && st != nil && st.fdTable != nil {
				st.fdTable[dirfd] = FD{
					Path:     dirPath,
					Type:     "regular",
					OpenTime: time.Now(),
				}
			}
			t.statesMu.Unlock()
			return dirPath
		}

		// Fall back to a placeholder
		return fmt.Sprintf("<fd:%d>", dirfd)
	}

	// Special case for AT_FDCWD (-100), use the process's cwd
	if dirfd == AT_FDCWD || dirfd == 0 {
		// Use most up-to-date cwd
		if cwd != "" {
			return filepath.Clean(filepath.Join(cwd, path))
		}

		// Check if process still exists
		_, procErr := os.Stat(fmt.Sprintf("/proc/%d", pid))
		if procErr != nil && os.IsNotExist(procErr) {
			// Process is gone, clean the path and return best effort
			clog.Debugf("Process %d no longer exists when getting cwd, using best effort", pid)
			return filepath.Clean(path)
		}

		// Try to get cwd from /proc as a fallback
		procCwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			// Update our cached cwd
			t.statesMu.Lock()
			if st, exists := t.states[pid]; exists && st != nil {
				st.cwd = procCwd
			}
			t.statesMu.Unlock()
			return filepath.Clean(filepath.Join(procCwd, path))
		}

		// Ultimate fallback - current process working directory
		wd, err := os.Getwd()
		if err == nil {
			return filepath.Clean(filepath.Join(wd, path))
		}

		// If everything fails, just clean the path
		return filepath.Clean(path)
	}

	// For non-AT_FDCWD cases, check if we have fdPath
	if fdPath != "" {
		return filepath.Clean(filepath.Join(fdPath, path))
	}

	// First check if the process still exists
	_, procErr := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if procErr != nil {
		if os.IsNotExist(procErr) {
			// Process is gone, just clean the path and return
			clog.Debugf("Process %d no longer exists when trying to get fd=%d, using best effort", pid, dirfd)
			return filepath.Clean(path)
		}
	}

	// If we don't know the file descriptor, try to read it from /proc
	dirPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	if err == nil {
		// Cache this file descriptor for future use
		t.statesMu.Lock()
		if st, exists := t.states[pid]; exists && st != nil && st.fdTable != nil {
			st.fdTable[dirfd] = FD{
				Path:     dirPath,
				Type:     "unknown",
				OpenTime: time.Now(),
			}
		}
		t.statesMu.Unlock()
		return filepath.Clean(filepath.Join(dirPath, path))
	}

	// If we still can't resolve it but have a parent process,
	// check if the parent has this fd (might be inherited)
	if parentPid > 0 {
		var parentFdPath string
		t.statesMu.RLock()
		if parentState, ok := t.states[parentPid]; ok && parentState != nil && parentState.fdTable != nil {
			if parentFd, ok := parentState.fdTable[dirfd]; ok {
				parentFdPath = parentFd.Path
			}
		}
		t.statesMu.RUnlock()

		if parentFdPath != "" {
			// Copy to this process's fd table
			t.statesMu.Lock()
			if st, exists := t.states[pid]; exists && st != nil && st.fdTable != nil {
				st.fdTable[dirfd] = FD{
					Path:     parentFdPath,
					Type:     "inherited",
					OpenTime: time.Now(),
				}
			}
			t.statesMu.Unlock()
			return filepath.Clean(filepath.Join(parentFdPath, path))
		}
	}

	// If all else fails, just join with the cwd (best effort)
	clog.Infof("unable to resolve fd %d for pid %d, falling back to cwd", dirfd, pid)
	if cwd != "" {
		return filepath.Clean(filepath.Join(cwd, path))
	}
	return filepath.Clean(path)
}
