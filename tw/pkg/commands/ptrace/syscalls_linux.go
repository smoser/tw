// Package ptrace provides system call tracing functionality
package ptrace

import (
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Package-level variables initialized only once during init
// These are effectively read-only after initialization, so no mutex needed
var (
	// Map of syscall numbers to their names
	syscallNames = map[uint32]string{}

	// Map of syscall numbers to their processors
	syscallProcessors = map[uint32]SyscallProcessor{}
)

// ProcessRegistry manages the mapping between PIDs and their Tracers
// This encapsulates the global state that was previously using syscallTracersMu
type ProcessRegistry struct {
	mu      sync.RWMutex
	tracers map[int]*Tracer
}

// Get returns the tracer for a given PID
func (r *ProcessRegistry) Get(pid int) (*Tracer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tracers[pid]
	return t, ok
}

// Set associates a tracer with a PID
func (r *ProcessRegistry) Set(pid int, tracer *Tracer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tracers[pid] = tracer
}

// Delete removes a PID from the registry
func (r *ProcessRegistry) Delete(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tracers, pid)
}

// NewProcessRegistry creates a new process registry
func NewProcessRegistry() *ProcessRegistry {
	return &ProcessRegistry{
		tracers: make(map[int]*Tracer),
	}
}

// Global process registry - the only global state we really need
var processRegistry = NewProcessRegistry()

// Common system calls that have universal numbers across architectures
// These are syscalls that have the same number on all architectures we support
// Architecture-specific syscall numbers should be defined in their respective files
const (
// Common syscalls with consistent numbers across architectures
// We use unix.SYS_* constants from x/sys/unix for actual values in the code

// More modern syscalls that are more consistent across architectures
// We rely on the unix package to provide the correct numbers per architecture
)

// Specific syscall processor implementations
type openSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *openSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	// For open syscall, the first parameter is the path
	pathAddr := archHandler.CallFirstParam(regs)
	path, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		return
	}

	// Store path in state for use in OnReturn
	state.pathParam = path
}

func (p *openSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	// On return, check if the open was successful and track file activity
	retVal := archHandler.CallReturnValue(regs)
	if p.OKReturnStatus(retVal) {
		fdNum := int(retVal) // The return value is the file descriptor

		// Add to file descriptor table
		t, ok := processRegistry.Get(pid)

		if ok && state.pathParam != "" {
			// Add to FD table for this process
			state.fdTable[fdNum] = FD{
				Path:     state.pathParam,
				Type:     "regular", // Assume regular file for now
				OpenTime: time.Now(),
			}

			// Track file system activity
			t.fsTracker.AddActivity(state.pathParam, pid, int(p.num), FSActivityTypeOpenFile)
		}
	}
}

type openatSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *openatSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	fmt.Fprintf(os.Stdout, "OPENAT SYSCALL DETECTED pid=%d\n", pid)
	// For openat, first param is dirfd, second is path
	dirfd := int(int32(archHandler.CallFirstParam(regs)))
	pathAddr := archHandler.CallSecondParam(regs)
	rawPath, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		fmt.Fprintf(os.Stdout, "ERROR getting path: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "OPENAT: dirfd=%d, rawPath=%s\n", dirfd, rawPath)

	// Store in state for use in OnReturn
	state.dirfd = dirfd
	state.pathParam = rawPath

	// Generate event immediately instead of waiting for return
	t, ok := processRegistry.Get(pid)

	if ok {
		// Resolve the path if needed
		eventPath := rawPath
		if dirfd != 0 && dirfd != AT_FDCWD {
			eventPath = t.resolvePath(pid, rawPath, dirfd)
		}

		t.events <- Event{
			Type:        EventSyscall,
			Syscall:     p.SyscallNumber(),
			SyscallName: p.SyscallName(),
			Pid:         pid,
			Path:        fmt.Sprintf("opening: %s", eventPath),
		}

		// Also directly track file system activity
		t.fsTracker.AddActivity(eventPath, pid, int(p.SyscallNumber()), FSActivityTypeOpenFile)
	}
}

func (p *openatSyscallProcessor) EventOnCall() bool {
	// Generate events on syscall entry rather than exit
	return true
}

func (p *openatSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	retVal := archHandler.CallReturnValue(regs)
	if p.OKReturnStatus(retVal) {
		fdNum := int(retVal)

		// Resolve the full path
		t, ok := processRegistry.Get(pid)

		if ok && state.pathParam != "" {
			resolvedPath := t.resolvePath(pid, state.pathParam, state.dirfd)

			// Add to FD table
			state.fdTable[fdNum] = FD{
				Path:     resolvedPath,
				Type:     "regular",
				OpenTime: time.Now(),
			}

			// Track file system activity
			t.fsTracker.AddActivity(resolvedPath, pid, int(p.num), FSActivityTypeOpenFile)
		}
	}
}

type statSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *statSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	// For stat, first param is path
	pathAddr := archHandler.CallFirstParam(regs)
	path, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		return
	}

	state.pathParam = path
}

func (p *statSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	retVal := archHandler.CallReturnValue(regs)
	if p.OKReturnStatus(retVal) {
		// Track file access
		t, ok := processRegistry.Get(pid)

		if ok && state.pathParam != "" {
			t.fsTracker.AddActivity(state.pathParam, pid, int(p.num), FSActivityTypeCheckFile)
		}
	}
}

type fstatatSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *fstatatSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	// For newfstatat/fstatat, first param is dirfd, second is path
	dirfd := int(int32(archHandler.CallFirstParam(regs)))
	pathAddr := archHandler.CallSecondParam(regs)
	rawPath, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		return
	}

	state.dirfd = dirfd
	state.pathParam = rawPath
}

func (p *fstatatSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	retVal := archHandler.CallReturnValue(regs)
	if p.OKReturnStatus(retVal) {
		// Resolve the full path
		t, ok := processRegistry.Get(pid)

		if ok && state.pathParam != "" {
			resolvedPath := t.resolvePath(pid, state.pathParam, state.dirfd)

			// Track file access
			t.fsTracker.AddActivity(resolvedPath, pid, int(p.num), FSActivityTypeCheckFile)
		}
	}
}

type execveSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *execveSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	// For execve, first param is path
	pathAddr := archHandler.CallFirstParam(regs)
	path, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		return
	}

	state.pathParam = path
}

func (p *execveSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	// execve typically doesn't return on success (process image is replaced)
	// So we need to handle this differently. Let's record the attempt regardless.
	t, ok := processRegistry.Get(pid)

	if ok && state.pathParam != "" {
		t.fsTracker.AddActivity(state.pathParam, pid, int(p.num), FSActivityTypeExec)
	}
}

func (p *execveSyscallProcessor) EventOnCall() bool {
	// Generate an event when the syscall is called, don't wait for return
	return true
}

type execveatSyscallProcessor struct {
	*baseSyscallProcessor
}

func (p *execveatSyscallProcessor) OnCall(pid int, regs unix.PtraceRegs, state *syscallState) {
	// For execveat, first param is dirfd, second is path
	dirfd := int(int32(archHandler.CallFirstParam(regs)))
	pathAddr := archHandler.CallSecondParam(regs)
	rawPath, err := getStringParam(pid, pathAddr)
	if err != nil {
		// Record the error but continue
		state.pathParamErr = err
		return
	}

	state.dirfd = dirfd
	state.pathParam = rawPath
}

func (p *execveatSyscallProcessor) OnReturn(pid int, regs unix.PtraceRegs, state *syscallState) {
	// If there was an error retrieving the path, skip processing
	if state.pathParamErr != nil || state.pathParam == "" {
		return
	}

	// Like execve, this typically doesn't return on success
	t, ok := processRegistry.Get(pid)

	if ok && state.pathParam != "" {
		resolvedPath := t.resolvePath(pid, state.pathParam, state.dirfd)
		t.fsTracker.AddActivity(resolvedPath, pid, int(p.num), FSActivityTypeExec)
	}
}

func (p *execveatSyscallProcessor) EventOnCall() bool {
	return true
}

// We now use processRegistry instead of a global map with a mutex

// initSyscallNames initializes the cross-platform syscall names map
// This is called from the package init function to populate
// the syscallNames map with syscalls that are common across architectures
func initSyscallNames() {
	// No locks needed since this only happens during init
	// and before any goroutines are started

	// Build our cross-platform syscall name map
	// using the actual syscall numbers from the unix package
	// These should work on both architectures
	syscallNames[unix.SYS_READ] = "read"
	syscallNames[unix.SYS_WRITE] = "write"
	syscallNames[unix.SYS_CLOSE] = "close"
	syscallNames[unix.SYS_FSTAT] = "fstat"
	syscallNames[unix.SYS_LSEEK] = "lseek"
	syscallNames[unix.SYS_MMAP] = "mmap"
	syscallNames[unix.SYS_MPROTECT] = "mprotect"
	syscallNames[unix.SYS_MUNMAP] = "munmap"
	syscallNames[unix.SYS_BRK] = "brk"
	syscallNames[unix.SYS_RT_SIGACTION] = "rt_sigaction"
	syscallNames[unix.SYS_RT_SIGPROCMASK] = "rt_sigprocmask"
	syscallNames[unix.SYS_RT_SIGRETURN] = "rt_sigreturn"
	syscallNames[unix.SYS_IOCTL] = "ioctl"
	syscallNames[unix.SYS_PREAD64] = "pread64"
	syscallNames[unix.SYS_PWRITE64] = "pwrite64"
	syscallNames[unix.SYS_READV] = "readv"
	syscallNames[unix.SYS_WRITEV] = "writev"
	// syscallNames[unix.SYS_ACCESS] = "access"
	// syscallNames[unix.SYS_PIPE] = "pipe"
	// syscallNames[unix.SYS_SELECT] = "select"
	syscallNames[unix.SYS_SCHED_YIELD] = "sched_yield"
	syscallNames[unix.SYS_MREMAP] = "mremap"
	syscallNames[unix.SYS_MSYNC] = "msync"
	syscallNames[unix.SYS_MINCORE] = "mincore"
	syscallNames[unix.SYS_MADVISE] = "madvise"
	syscallNames[unix.SYS_DUP] = "dup"
	syscallNames[unix.SYS_NANOSLEEP] = "nanosleep"
	syscallNames[unix.SYS_GETITIMER] = "getitimer"
	syscallNames[unix.SYS_SETITIMER] = "setitimer"
	syscallNames[unix.SYS_GETPID] = "getpid"
	syscallNames[unix.SYS_SENDFILE] = "sendfile"
	syscallNames[unix.SYS_SOCKET] = "socket"
	syscallNames[unix.SYS_CONNECT] = "connect"
	syscallNames[unix.SYS_ACCEPT] = "accept"
	syscallNames[unix.SYS_SENDTO] = "sendto"
	syscallNames[unix.SYS_RECVFROM] = "recvfrom"
	syscallNames[unix.SYS_SENDMSG] = "sendmsg"
	syscallNames[unix.SYS_RECVMSG] = "recvmsg"
	syscallNames[unix.SYS_SHUTDOWN] = "shutdown"
	syscallNames[unix.SYS_BIND] = "bind"
	syscallNames[unix.SYS_LISTEN] = "listen"
	syscallNames[unix.SYS_GETSOCKNAME] = "getsockname"
	syscallNames[unix.SYS_GETPEERNAME] = "getpeername"
	syscallNames[unix.SYS_SOCKETPAIR] = "socketpair"
	syscallNames[unix.SYS_SETSOCKOPT] = "setsockopt"
	syscallNames[unix.SYS_GETSOCKOPT] = "getsockopt"
	syscallNames[unix.SYS_CLONE] = "clone"
	syscallNames[unix.SYS_EXECVE] = "execve"
	syscallNames[unix.SYS_EXIT] = "exit"
	syscallNames[unix.SYS_FCNTL] = "fcntl"
	syscallNames[unix.SYS_FSYNC] = "fsync"
	syscallNames[unix.SYS_TRUNCATE] = "truncate"
	syscallNames[unix.SYS_FTRUNCATE] = "ftruncate"
	// syscallNames[unix.SYS_GETDENTS] = "getdents"

	// AT family syscalls (more modern, work on both architectures)
	syscallNames[unix.SYS_OPENAT] = "openat"
	syscallNames[unix.SYS_MKDIRAT] = "mkdirat"
	syscallNames[unix.SYS_UNLINKAT] = "unlinkat"
	syscallNames[unix.SYS_RENAMEAT] = "renameat"
	syscallNames[unix.SYS_RENAMEAT2] = "renameat2"
	syscallNames[unix.SYS_EXECVEAT] = "execveat"
	syscallNames[unix.SYS_ACCEPT4] = "accept4"

	// Note: Syscall processors are now registered in registerCommonSyscallProcessors()
	// to avoid duplicate registration
}

// Cross-platform init
func init() {
	// Everything here runs during init time only, before any goroutines start
	// so no locking is needed
	initSyscallNames()
	registerCommonSyscallProcessors()

	// Note: We're now using processRegistry instead of syscallTracers
}

// registerCommonSyscallProcessors registers the common syscall processors that are available
// across all architectures. Architecture-specific processors are registered in their
// respective architecture initialization files.
func registerCommonSyscallProcessors() {
	// Register common syscall processors
	RegisterSyscallProcessor(&openatSyscallProcessor{
		baseSyscallProcessor: &baseSyscallProcessor{
			num:         unix.SYS_OPENAT,
			name:        "openat",
			syscallType: OpenFileType,
		},
	})

	RegisterSyscallProcessor(&fstatatSyscallProcessor{
		baseSyscallProcessor: &baseSyscallProcessor{
			num:         unix.SYS_NEWFSTATAT,
			name:        "newfstatat",
			syscallType: CheckFileType,
		},
	})

	RegisterSyscallProcessor(&execveSyscallProcessor{
		baseSyscallProcessor: &baseSyscallProcessor{
			num:         unix.SYS_EXECVE,
			name:        "execve",
			syscallType: ExecType,
		},
	})

	RegisterSyscallProcessor(&execveatSyscallProcessor{
		baseSyscallProcessor: &baseSyscallProcessor{
			num:         unix.SYS_EXECVEAT,
			name:        "execveat",
			syscallType: ExecType,
		},
	})

	// Note: Architecture-specific syscalls (like SYS_OPEN and SYS_STAT for amd64)
	// are registered in their respective arch-specific init functions
}

// Return human-readable names for system calls
func getSyscallName(num uint32) string {
	// No lock needed since syscallNames is read-only after init
	if name, ok := syscallNames[num]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", num)
}

// SyscallType represents the type of syscall operation
type SyscallType string

const (
	// Types of syscalls
	CheckFileType SyscallType = "type.checkfile" // Syscalls that check file existence/stats (stat, access, etc.)
	OpenFileType  SyscallType = "type.openfile"  // Syscalls that open files (open, openat, etc.)
	ExecType      SyscallType = "type.exec"      // Syscalls that execute processes (execve, execveat)
	NetworkType   SyscallType = "type.network"   // Syscalls for network operations (socket, connect, etc.)
	MemoryType    SyscallType = "type.memory"    // Syscalls for memory operations (mmap, etc.)
	ProcessType   SyscallType = "type.process"   // Syscalls for process operations (fork, etc.)
	SignalType    SyscallType = "type.signal"    // Syscalls for signal handling
	TimeType      SyscallType = "type.time"      // Syscalls for time operations
	SecurityType  SyscallType = "type.security"  // Syscalls for security operations
	IpcType       SyscallType = "type.ipc"       // Syscalls for IPC operations
	MiscType      SyscallType = "type.misc"      // Syscalls that don't fit other categories
)

// SyscallProcessor interfaces define how to process different syscalls
type SyscallProcessor interface {
	SyscallNumber() uint32
	SyscallName() string
	SyscallType() SyscallType
	OnCall(pid int, regs unix.PtraceRegs, state *syscallState)
	OnReturn(pid int, regs unix.PtraceRegs, state *syscallState)
	EventOnCall() bool
	OKReturnStatus(retVal uint64) bool
}

// Base syscall processor implementation with common functionality
type baseSyscallProcessor struct {
	num         uint32
	name        string
	syscallType SyscallType
}

func (p *baseSyscallProcessor) SyscallNumber() uint32 {
	return p.num
}

func (p *baseSyscallProcessor) SyscallName() string {
	return p.name
}

func (p *baseSyscallProcessor) SyscallType() SyscallType {
	return p.syscallType
}

func (p *baseSyscallProcessor) EventOnCall() bool {
	return false
}

func (p *baseSyscallProcessor) OKReturnStatus(retVal uint64) bool {
	// Default implementation - success if return value >= 0
	return int64(retVal) >= 0
}

// RegisterSyscallProcessor adds a processor for a syscall
// This should only be called during init time
func RegisterSyscallProcessor(processor SyscallProcessor) {
	// No locking needed since this happens during init
	syscallProcessors[processor.SyscallNumber()] = processor
}

// GetSyscallProcessor returns the processor for a given syscall, or nil if not found
func GetSyscallProcessor(syscallNum uint32) SyscallProcessor {
	// No lock needed since syscallProcessors is read-only after init
	return syscallProcessors[syscallNum]
}

// BaseArchHandler provides common functionality for architecture handlers
type BaseArchHandler struct {
	fileOps     map[uint32]bool
	networkOps  map[uint32]bool
	execOps     map[uint32]bool
	memoryOps   map[uint32]bool
	processOps  map[uint32]bool
	signalOps   map[uint32]bool
	timeOps     map[uint32]bool
	securityOps map[uint32]bool
	ipcOps      map[uint32]bool
}

// NewBaseArchHandler creates a new base architecture handler
func NewBaseArchHandler() *BaseArchHandler {
	return &BaseArchHandler{
		fileOps:     make(map[uint32]bool),
		networkOps:  make(map[uint32]bool),
		execOps:     make(map[uint32]bool),
		memoryOps:   make(map[uint32]bool),
		processOps:  make(map[uint32]bool),
		signalOps:   make(map[uint32]bool),
		timeOps:     make(map[uint32]bool),
		securityOps: make(map[uint32]bool),
		ipcOps:      make(map[uint32]bool),
	}
}

// RegisterFileOp registers syscalls as file operations
func (h *BaseArchHandler) RegisterFileOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.fileOps[num] = true
	}
}

// RegisterNetworkOp registers syscalls as network operations
func (h *BaseArchHandler) RegisterNetworkOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.networkOps[num] = true
	}
}

// RegisterExecOp registers syscalls as exec operations
func (h *BaseArchHandler) RegisterExecOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.execOps[num] = true
	}
}

// RegisterMemoryOp registers syscalls as memory operations
func (h *BaseArchHandler) RegisterMemoryOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.memoryOps[num] = true
	}
}

// RegisterProcessOp registers syscalls as process operations
func (h *BaseArchHandler) RegisterProcessOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.processOps[num] = true
	}
}

// RegisterSignalOp registers syscalls as signal operations
func (h *BaseArchHandler) RegisterSignalOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.signalOps[num] = true
	}
}

// RegisterTimeOp registers syscalls as time operations
func (h *BaseArchHandler) RegisterTimeOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.timeOps[num] = true
	}
}

// RegisterSecurityOp registers syscalls as security operations
func (h *BaseArchHandler) RegisterSecurityOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.securityOps[num] = true
	}
}

// RegisterIpcOp registers syscalls as IPC operations
func (h *BaseArchHandler) RegisterIpcOp(syscalls ...uint32) {
	for _, num := range syscalls {
		h.ipcOps[num] = true
	}
}

// IsFileOpSyscall returns true if the syscall is a file operation
func (h *BaseArchHandler) IsFileOpSyscall(num uint32) bool {
	return h.fileOps[num]
}

// IsNetworkSyscall returns true if the syscall is a network operation
func (h *BaseArchHandler) IsNetworkSyscall(num uint32) bool {
	return h.networkOps[num]
}

// IsExecSyscall returns true if the syscall is an exec operation
func (h *BaseArchHandler) IsExecSyscall(num uint32) bool {
	return h.execOps[num]
}

// IsMemorySyscall returns true if the syscall is a memory operation
func (h *BaseArchHandler) IsMemorySyscall(num uint32) bool {
	return h.memoryOps[num]
}

// IsProcessSyscall returns true if the syscall is a process operation
func (h *BaseArchHandler) IsProcessSyscall(num uint32) bool {
	return h.processOps[num]
}

// IsSignalSyscall returns true if the syscall is a signal operation
func (h *BaseArchHandler) IsSignalSyscall(num uint32) bool {
	return h.signalOps[num]
}

// IsTimeSyscall returns true if the syscall is a time operation
func (h *BaseArchHandler) IsTimeSyscall(num uint32) bool {
	return h.timeOps[num]
}

// IsSecuritySyscall returns true if the syscall is a security operation
func (h *BaseArchHandler) IsSecuritySyscall(num uint32) bool {
	return h.securityOps[num]
}

// IsIpcSyscall returns true if the syscall is an IPC operation
func (h *BaseArchHandler) IsIpcSyscall(num uint32) bool {
	return h.ipcOps[num]
}

// ArchHandler defines an interface for architecture-specific operations
// This interface will be implemented in the arch-specific files
type ArchHandler interface {
	// Register operations
	CallFirstParam(regs unix.PtraceRegs) uint64
	CallSecondParam(regs unix.PtraceRegs) uint64
	CallThirdParam(regs unix.PtraceRegs) uint64
	CallFourthParam(regs unix.PtraceRegs) uint64
	CallFifthParam(regs unix.PtraceRegs) uint64
	CallSixthParam(regs unix.PtraceRegs) uint64
	CallReturnValue(regs unix.PtraceRegs) uint64

	// System call operations
	GetSyscallNumber(regs unix.PtraceRegs) uint32

	// Architecture-specific classification
	IsFileOpSyscall(num uint32) bool
	IsNetworkSyscall(num uint32) bool
	IsExecSyscall(num uint32) bool
	IsMemorySyscall(num uint32) bool
	IsProcessSyscall(num uint32) bool
	IsSignalSyscall(num uint32) bool
	IsTimeSyscall(num uint32) bool
	IsSecuritySyscall(num uint32) bool
	IsIpcSyscall(num uint32) bool

	// Architecture name for logging
	Name() string
}

// Architecture-specific handler is set at init time
var archHandler ArchHandler

// Wrapper functions for syscall classification
// These delegate to the architecture-specific handler

// IsFileOpSyscall checks if a syscall is related to file operations
func IsFileOpSyscall(num uint32) bool {
	return archHandler.IsFileOpSyscall(num)
}

// IsNetworkSyscall checks if a syscall is related to network operations
func IsNetworkSyscall(num uint32) bool {
	return archHandler.IsNetworkSyscall(num)
}

// IsExecSyscall checks if a syscall is related to process execution
func IsExecSyscall(num uint32) bool {
	return archHandler.IsExecSyscall(num)
}

// IsMemorySyscall checks if a syscall is related to memory management
func IsMemorySyscall(num uint32) bool {
	return archHandler.IsMemorySyscall(num)
}

// IsProcessSyscall checks if a syscall is related to process management (non-exec)
func IsProcessSyscall(num uint32) bool {
	return archHandler.IsProcessSyscall(num)
}

// IsSignalSyscall checks if a syscall is related to signal handling
func IsSignalSyscall(num uint32) bool {
	return archHandler.IsSignalSyscall(num)
}

// IsTimeSyscall checks if a syscall is related to time operations
func IsTimeSyscall(num uint32) bool {
	return archHandler.IsTimeSyscall(num)
}

// IsSecuritySyscall checks if a syscall is related to security operations
func IsSecuritySyscall(num uint32) bool {
	return archHandler.IsSecuritySyscall(num)
}

// IsIpcSyscall checks if a syscall is related to inter-process communication
func IsIpcSyscall(num uint32) bool {
	return archHandler.IsIpcSyscall(num)
}

// GetSyscallType returns the type of syscall based on classification functions
func GetSyscallType(syscallNum uint32) SyscallType {
	// Check for specific processor first
	if processor := GetSyscallProcessor(syscallNum); processor != nil {
		return processor.SyscallType()
	}

	// Otherwise use the general classification functions
	switch {
	case IsFileOpSyscall(syscallNum):
		// Further classify file ops
		// This is a simplified check - ideally we'd have a more comprehensive classification
		for _, openSyscall := range []uint32{unix.SYS_OPENAT} {
			if syscallNum == openSyscall {
				return OpenFileType
			}
		}
		return CheckFileType
	case IsExecSyscall(syscallNum):
		return ExecType
	case IsNetworkSyscall(syscallNum):
		return NetworkType
	case IsMemorySyscall(syscallNum):
		return MemoryType
	case IsProcessSyscall(syscallNum):
		return ProcessType
	case IsSignalSyscall(syscallNum):
		return SignalType
	case IsTimeSyscall(syscallNum):
		return TimeType
	case IsSecuritySyscall(syscallNum):
		return SecurityType
	case IsIpcSyscall(syscallNum):
		return IpcType
	default:
		return MiscType
	}
}
