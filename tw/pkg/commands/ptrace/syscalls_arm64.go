//go:build linux && arm64
// +build linux,arm64

package ptrace

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ARM64Handler implements the ArchHandler interface for ARM64 architecture
type ARM64Handler struct {
	*BaseArchHandler
}

func (h *ARM64Handler) Name() string {
	return "ARM64"
}

// Register accessor methods
func (h *ARM64Handler) CallFirstParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[0])
}

func (h *ARM64Handler) CallSecondParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[1])
}

func (h *ARM64Handler) CallThirdParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[2])
}

func (h *ARM64Handler) CallFourthParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[3])
}

func (h *ARM64Handler) CallFifthParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[4])
}

func (h *ARM64Handler) CallSixthParam(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[5])
}

func (h *ARM64Handler) CallReturnValue(regs unix.PtraceRegs) uint64 {
	return uint64(regs.Regs[0])
}

// Get syscall number from registers for ARM64
func (h *ARM64Handler) GetSyscallNumber(regs unix.PtraceRegs) uint32 {
	return uint32(regs.Regs[8])
}

// ARM64 handler uses the base implementation for all syscall classifications
// since we've populated the maps in the init function

// ARM64-specific initialization
func init() {
	// Initialize the ARM64-specific architecture handler
	base := NewBaseArchHandler()

	// Register file operations
	base.RegisterFileOp(
		unix.SYS_OPENAT, unix.SYS_CLOSE, unix.SYS_READ, unix.SYS_WRITE,
		unix.SYS_PREAD64, unix.SYS_PWRITE64, unix.SYS_LSEEK, unix.SYS_FSTAT,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2,
		unix.SYS_READLINKAT, unix.SYS_TRUNCATE, unix.SYS_FTRUNCATE, unix.SYS_FSYNC,
		unix.SYS_FDATASYNC,
	)

	// Register network operations
	base.RegisterNetworkOp(
		unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_BIND, unix.SYS_LISTEN,
		unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME,
		unix.SYS_SOCKETPAIR, unix.SYS_SENDTO, unix.SYS_RECVFROM, unix.SYS_SHUTDOWN,
		unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT, unix.SYS_SENDMSG, unix.SYS_RECVMSG,
	)

	// Register exec operations
	base.RegisterExecOp(
		unix.SYS_EXECVE, unix.SYS_EXECVEAT,
	)

	// Register memory operations
	base.RegisterMemoryOp(
		unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MREMAP,
		unix.SYS_MSYNC, unix.SYS_MINCORE, unix.SYS_MADVISE, unix.SYS_BRK,
		unix.SYS_MLOCK, unix.SYS_MUNLOCK, unix.SYS_MLOCKALL, unix.SYS_MUNLOCKALL,
	)

	// Register process operations
	base.RegisterProcessOp(
		unix.SYS_CLONE, unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETUID,
		unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_SETUID,
		unix.SYS_SETGID, unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_WAIT4,
		unix.SYS_SCHED_YIELD, unix.SYS_CHDIR, unix.SYS_GETCWD, unix.SYS_CAPGET,
		unix.SYS_CAPSET, unix.SYS_PRCTL, unix.SYS_SETPRIORITY, unix.SYS_GETPRIORITY,
	)

	// Register signal operations
	base.RegisterSignalOp(
		unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL, unix.SYS_RT_SIGACTION,
		unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGPENDING,
		unix.SYS_RT_SIGTIMEDWAIT, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_SIGSUSPEND,
	)

	// Register time operations
	base.RegisterTimeOp(
		unix.SYS_NANOSLEEP, unix.SYS_GETITIMER, unix.SYS_SETITIMER,
		unix.SYS_TIMER_CREATE, unix.SYS_TIMER_GETTIME, unix.SYS_TIMER_SETTIME,
		unix.SYS_TIMER_DELETE, unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_SETTIME,
		unix.SYS_CLOCK_GETRES, unix.SYS_CLOCK_NANOSLEEP,
	)

	// Register security operations
	base.RegisterSecurityOp(
		unix.SYS_CAPGET, unix.SYS_CAPSET, unix.SYS_PRCTL,
		unix.SYS_SECCOMP, unix.SYS_PTRACE,
	)

	// Register IPC operations
	base.RegisterIpcOp(
		unix.SYS_PIPE2, unix.SYS_FUTEX, unix.SYS_SOCKETPAIR,
		unix.SYS_SHMGET, unix.SYS_SHMAT, unix.SYS_SHMCTL, unix.SYS_SHMDT,
		unix.SYS_SEMGET, unix.SYS_SEMOP, unix.SYS_SEMCTL,
		unix.SYS_MSGGET, unix.SYS_MSGSND, unix.SYS_MSGRCV, unix.SYS_MSGCTL,
	)

	archHandler = &ARM64Handler{BaseArchHandler: base}

	// Debug: Print OpenAT syscall number
	fmt.Fprintf(os.Stdout, "ARM64 init: unix.SYS_OPENAT=%d\n", unix.SYS_OPENAT)

	// Let's not register openat handler here - it's registered in the common code
	// and we're possibly registering it twice with different handlers
}

// ARM64 implementation of handleSyscall
func (t *Tracer) handleSyscall(pid int) {
	handleSyscall(t, pid)
}
