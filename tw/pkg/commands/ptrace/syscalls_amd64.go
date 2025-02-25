//go:build linux && amd64
// +build linux,amd64

package ptrace

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Get the first parameter from syscall registers (AMD64)
func getFirstParam(regs syscall.PtraceRegs) uint64 {
	return regs.Rdi
}

// Get the second parameter from syscall registers (AMD64)
func getSecondParam(regs syscall.PtraceRegs) uint64 {
	return regs.Rsi
}

// Get syscall number from registers (AMD64)
func getSyscallNumber(regs syscall.PtraceRegs) uint64 {
	return regs.Orig_rax
}

// Get return value from registers (AMD64)
func getReturnValue(regs syscall.PtraceRegs) uint64 {
	return regs.Rax
}

// getSyscallName maps syscall numbers to names for AMD64
func getSyscallName(num uint32) string {
	if name, ok := syscallNames[num]; ok {
		return name
	}
	return "syscall_" + itoa(int(num))
}

// itoa is a simple function to convert int to string
func itoa(val int) string {
	if val < 0 {
		return "-" + uitoa(uint(-val))
	}
	return uitoa(uint(val))
}

// uitoa converts an unsigned integer to a string
func uitoa(val uint) string {
	var buf [32]byte // big enough for int64
	i := len(buf) - 1
	for val >= 10 {
		q := val / 10
		buf[i] = byte('0' + val - q*10)
		i--
		val = q
	}
	buf[i] = byte('0' + val)
	return string(buf[i:])
}

// registerSyscallHandlers registers architecture-specific syscall handlers
func (t *Tracer) registerHandlers() {
	// File check syscalls
	t.registerFileCheckHandlers()

	// File open syscalls
	t.registerFileOpenHandlers()

	// Exec syscalls
	t.registerExecHandlers()
}

func (t *Tracer) registerFileCheckHandlers() {
	// stat(const char *pathname, struct stat *statbuf)
	t.handlers[unix.SYS_STAT] = NewFileCheckHandler(unix.SYS_STAT, "stat", 1)

	// fstat(int fd, struct stat *statbuf)
	t.handlers[unix.SYS_FSTAT] = NewFileCheckHandler(unix.SYS_FSTAT, "fstat", 0)

	// lstat(const char *pathname, struct stat *statbuf)
	t.handlers[unix.SYS_LSTAT] = NewFileCheckHandler(unix.SYS_LSTAT, "lstat", 1)

	// access(const char *pathname, int mode)
	t.handlers[unix.SYS_ACCESS] = NewFileCheckHandler(unix.SYS_ACCESS, "access", 1)

	// newfstatat/fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
	t.handlers[unix.SYS_NEWFSTATAT] = NewFileCheckHandler(unix.SYS_NEWFSTATAT, "newfstatat", 2)

	// faccessat(int dirfd, const char *pathname, int mode, int flags)
	t.handlers[unix.SYS_FACCESSAT] = NewFileCheckHandler(unix.SYS_FACCESSAT, "faccessat", 2)

	// statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)
	t.handlers[unix.SYS_STATX] = NewFileCheckHandler(unix.SYS_STATX, "statx", 2)
}

func (t *Tracer) registerFileOpenHandlers() {
	// open(const char *pathname, int flags, mode_t mode)
	t.handlers[unix.SYS_OPEN] = NewFileOpenHandler(unix.SYS_OPEN, "open", 1)

	// openat(int dirfd, const char *pathname, int flags, mode_t mode)
	t.handlers[unix.SYS_OPENAT] = NewFileOpenHandler(unix.SYS_OPENAT, "openat", 2)

	// readlink(const char *pathname, char *buf, size_t bufsiz)
	t.handlers[unix.SYS_READLINK] = NewFileOpenHandler(unix.SYS_READLINK, "readlink", 1)

	// readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
	t.handlers[unix.SYS_READLINKAT] = NewFileOpenHandler(unix.SYS_READLINKAT, "readlinkat", 2)
}

func (t *Tracer) registerExecHandlers() {
	// execve(const char *pathname, char *const argv[], char *const envp[])
	t.handlers[unix.SYS_EXECVE] = NewExecHandler(unix.SYS_EXECVE, "execve", 1)

	// execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
	t.handlers[unix.SYS_EXECVEAT] = NewExecHandler(unix.SYS_EXECVEAT, "execveat", 2)
}

// Initialize syscallNames map using unix constants
var syscallNames = map[uint32]string{
	unix.SYS_READ:           "read",
	unix.SYS_WRITE:          "write",
	unix.SYS_OPEN:           "open",
	unix.SYS_CLOSE:          "close",
	unix.SYS_STAT:           "stat",
	unix.SYS_FSTAT:          "fstat",
	unix.SYS_LSTAT:          "lstat",
	unix.SYS_POLL:           "poll",
	unix.SYS_LSEEK:          "lseek",
	unix.SYS_MMAP:           "mmap",
	unix.SYS_MPROTECT:       "mprotect",
	unix.SYS_MUNMAP:         "munmap",
	unix.SYS_BRK:            "brk",
	unix.SYS_RT_SIGACTION:   "rt_sigaction",
	unix.SYS_RT_SIGPROCMASK: "rt_sigprocmask",
	unix.SYS_RT_SIGRETURN:   "rt_sigreturn",
	unix.SYS_IOCTL:          "ioctl",
	unix.SYS_PREAD64:        "pread64",
	unix.SYS_PWRITE64:       "pwrite64",
	unix.SYS_READV:          "readv",
	unix.SYS_WRITEV:         "writev",
	unix.SYS_ACCESS:         "access",
	unix.SYS_PIPE:           "pipe",
	unix.SYS_SELECT:         "select",
	unix.SYS_SCHED_YIELD:    "sched_yield",
	unix.SYS_MREMAP:         "mremap",
	unix.SYS_MSYNC:          "msync",
	unix.SYS_MINCORE:        "mincore",
	unix.SYS_MADVISE:        "madvise",
	unix.SYS_SHMGET:         "shmget",
	unix.SYS_SHMAT:          "shmat",
	unix.SYS_SHMCTL:         "shmctl",
	unix.SYS_DUP:            "dup",
	unix.SYS_DUP2:           "dup2",
	unix.SYS_PAUSE:          "pause",
	unix.SYS_NANOSLEEP:      "nanosleep",
	unix.SYS_GETITIMER:      "getitimer",
	unix.SYS_ALARM:          "alarm",
	unix.SYS_SETITIMER:      "setitimer",
	unix.SYS_GETPID:         "getpid",
	unix.SYS_SENDFILE:       "sendfile",
	unix.SYS_SOCKET:         "socket",
	unix.SYS_CONNECT:        "connect",
	unix.SYS_ACCEPT:         "accept",
	unix.SYS_SENDTO:         "sendto",
	unix.SYS_RECVFROM:       "recvfrom",
	unix.SYS_SENDMSG:        "sendmsg",
	unix.SYS_RECVMSG:        "recvmsg",
	unix.SYS_SHUTDOWN:       "shutdown",
	unix.SYS_BIND:           "bind",
	unix.SYS_LISTEN:         "listen",
	unix.SYS_GETSOCKNAME:    "getsockname",
	unix.SYS_GETPEERNAME:    "getpeername",
	unix.SYS_SOCKETPAIR:     "socketpair",
	unix.SYS_SETSOCKOPT:     "setsockopt",
	unix.SYS_GETSOCKOPT:     "getsockopt",
	unix.SYS_CLONE:          "clone",
	unix.SYS_FORK:           "fork",
	unix.SYS_VFORK:          "vfork",
	unix.SYS_EXECVE:         "execve",
	unix.SYS_EXIT:           "exit",
	unix.SYS_WAIT4:          "wait4",
	unix.SYS_KILL:           "kill",
	unix.SYS_UNAME:          "uname",
	unix.SYS_SEMGET:         "semget",
	unix.SYS_SEMOP:          "semop",
	unix.SYS_SEMCTL:         "semctl",
	unix.SYS_SHMDT:          "shmdt",
	unix.SYS_MSGGET:         "msgget",
	unix.SYS_MSGSND:         "msgsnd",
	unix.SYS_MSGRCV:         "msgrcv",
	unix.SYS_MSGCTL:         "msgctl",
	unix.SYS_FCNTL:          "fcntl",
	unix.SYS_FLOCK:          "flock",
	unix.SYS_FSYNC:          "fsync",
	unix.SYS_FDATASYNC:      "fdatasync",
	unix.SYS_TRUNCATE:       "truncate",
	unix.SYS_FTRUNCATE:      "ftruncate",
	unix.SYS_GETDENTS:       "getdents",
	unix.SYS_GETCWD:         "getcwd",
	unix.SYS_CHDIR:          "chdir",
	unix.SYS_FCHDIR:         "fchdir",
	unix.SYS_RENAME:         "rename",
	unix.SYS_MKDIR:          "mkdir",
	unix.SYS_RMDIR:          "rmdir",
	unix.SYS_CREAT:          "creat",
	unix.SYS_LINK:           "link",
	unix.SYS_UNLINK:         "unlink",
	unix.SYS_SYMLINK:        "symlink",
	unix.SYS_READLINK:       "readlink",
	unix.SYS_CHMOD:          "chmod",
	unix.SYS_FCHMOD:         "fchmod",
	unix.SYS_CHOWN:          "chown",
	unix.SYS_FCHOWN:         "fchown",
	unix.SYS_LCHOWN:         "lchown",
	unix.SYS_UMASK:          "umask",
	unix.SYS_GETTIMEOFDAY:   "gettimeofday",
	unix.SYS_GETRLIMIT:      "getrlimit",
	unix.SYS_GETRUSAGE:      "getrusage",
	unix.SYS_SYSINFO:        "sysinfo",
	unix.SYS_TIMES:          "times",
	unix.SYS_OPENAT:         "openat",
	unix.SYS_NEWFSTATAT:     "newfstatat",
	unix.SYS_READLINKAT:     "readlinkat",
	unix.SYS_FACCESSAT:      "faccessat",
	unix.SYS_EXECVEAT:       "execveat",
	unix.SYS_STATX:          "statx",
}
