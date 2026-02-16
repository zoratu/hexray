//! Magic constants database for common system values.
//!
//! This module provides named constants for common magic numbers like:
//! - ioctl codes (TIOCGWINSZ, etc.)
//! - Signal numbers (SIGINT, SIGTERM, etc.)
//! - Open flags (O_RDONLY, O_WRONLY, etc.)
//! - mmap flags (PROT_READ, MAP_SHARED, etc.)
//! - Socket constants (AF_INET, SOCK_STREAM, etc.)
//! - File descriptor values (STDIN, STDOUT, STDERR)
//! - errno values

use std::collections::HashMap;

/// Categories of constants for context-aware lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstantCategory {
    /// General-purpose constants (file descriptors, common values)
    General,
    /// ioctl request codes
    Ioctl,
    /// Signal numbers
    Signal,
    /// File open flags
    OpenFlags,
    /// mmap protection flags
    MmapProt,
    /// mmap mapping flags
    MmapFlags,
    /// Socket address families
    AddressFamily,
    /// Socket types
    SocketType,
    /// Socket protocol
    Protocol,
    /// errno values
    Errno,
    /// fcntl commands
    Fcntl,
    /// seek whence values
    Seek,
    /// poll/select events
    PollEvents,
    /// epoll_ctl operations
    EpollCtl,
    /// *at() syscall flags (AT_FDCWD, AT_SYMLINK_NOFOLLOW, etc.)
    AtFlags,
    /// Signal handler values (SIG_IGN, SIG_DFL)
    SignalHandler,
    /// File permission modes (0644, 0755, etc.)
    FileMode,
    /// Socket options (SO_REUSEADDR, TCP_NODELAY, etc.)
    SockOpt,
    /// Socket option levels (SOL_SOCKET, IPPROTO_TCP, etc.)
    SockOptLevel,
    /// Clone flags for clone() syscall
    CloneFlags,
    /// ptrace request codes
    PtraceRequest,
    /// prctl option codes
    PrctlOption,
    /// Seccomp operations and flags
    Seccomp,
    /// Wait options (WNOHANG, WUNTRACED, etc.)
    WaitOptions,
}

/// A named constant with its value and category.
#[derive(Debug, Clone)]
pub struct NamedConstant {
    pub name: &'static str,
    pub value: i128,
    pub category: ConstantCategory,
    /// Optional description
    pub description: Option<&'static str>,
}

/// Database of magic constants.
pub struct ConstantDatabase {
    /// Constants indexed by value for quick lookup.
    by_value: HashMap<i128, Vec<NamedConstant>>,
    /// Constants indexed by category and value.
    by_category: HashMap<ConstantCategory, HashMap<i128, NamedConstant>>,
}

impl Default for ConstantDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstantDatabase {
    /// Creates a new empty constant database.
    pub fn new() -> Self {
        Self {
            by_value: HashMap::new(),
            by_category: HashMap::new(),
        }
    }

    /// Creates a database with all builtin constants loaded.
    pub fn with_builtins() -> Self {
        let mut db = Self::new();
        load_posix_constants(&mut db);
        load_linux_constants(&mut db);
        load_macos_constants(&mut db);
        db
    }

    /// Adds a constant to the database.
    pub fn add(&mut self, constant: NamedConstant) {
        self.by_value
            .entry(constant.value)
            .or_default()
            .push(constant.clone());

        self.by_category
            .entry(constant.category)
            .or_default()
            .insert(constant.value, constant);
    }

    /// Looks up a constant by value, preferring the given category.
    pub fn lookup(
        &self,
        value: i128,
        preferred_category: Option<ConstantCategory>,
    ) -> Option<&str> {
        // First try the preferred category
        if let Some(cat) = preferred_category {
            if let Some(cat_map) = self.by_category.get(&cat) {
                if let Some(constant) = cat_map.get(&value) {
                    return Some(constant.name);
                }
            }
        }

        // Fall back to any matching constant
        if let Some(constants) = self.by_value.get(&value) {
            // Prefer General category if no specific category was requested
            for c in constants {
                if c.category == ConstantCategory::General {
                    return Some(c.name);
                }
            }
            // Return first match
            return constants.first().map(|c| c.name);
        }

        None
    }

    /// Looks up a constant by value in a specific category only.
    pub fn lookup_in_category(&self, value: i128, category: ConstantCategory) -> Option<&str> {
        self.by_category.get(&category)?.get(&value).map(|c| c.name)
    }

    /// Formats a value as a constant if known, otherwise as an integer.
    pub fn format_value(&self, value: i128, category: Option<ConstantCategory>) -> String {
        if let Some(name) = self.lookup(value, category) {
            name.to_string()
        } else {
            format_integer_default(value)
        }
    }

    /// Formats flags (bitwise OR of multiple constants).
    pub fn format_flags(&self, value: i128, category: ConstantCategory) -> String {
        if value == 0 {
            if let Some(name) = self.lookup_in_category(0, category) {
                return name.to_string();
            }
            return "0".to_string();
        }

        let cat_map = match self.by_category.get(&category) {
            Some(m) => m,
            None => return format_integer_default(value),
        };

        let mut remaining = value;
        let mut parts: Vec<String> = Vec::new();

        // Sort constants by value (descending) to match larger values first
        let mut sorted: Vec<_> = cat_map.iter().collect();
        sorted.sort_by(|a, b| b.0.cmp(a.0));

        for (val, constant) in sorted {
            if *val != 0 && (remaining & val) == *val {
                parts.push(constant.name.to_string());
                remaining &= !val;
            }
        }

        if remaining != 0 {
            parts.push(format_integer_default(remaining));
        }

        if parts.is_empty() {
            "0".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

/// Format an integer in a reasonable way.
fn format_integer_default(n: i128) -> String {
    // Use decimal for small/medium values, hex for large values (likely addresses)
    if n <= 0xFFFF {
        format!("{}", n)
    } else {
        format!("{:#x}", n)
    }
}

/// Load POSIX constants (common across Unix systems).
pub fn load_posix_constants(db: &mut ConstantDatabase) {
    use ConstantCategory::*;

    // File descriptors
    db.add(NamedConstant {
        name: "STDIN_FILENO",
        value: 0,
        category: General,
        description: Some("Standard input"),
    });
    db.add(NamedConstant {
        name: "STDOUT_FILENO",
        value: 1,
        category: General,
        description: Some("Standard output"),
    });
    db.add(NamedConstant {
        name: "STDERR_FILENO",
        value: 2,
        category: General,
        description: Some("Standard error"),
    });

    // Open flags
    db.add(NamedConstant {
        name: "O_RDONLY",
        value: 0x0000,
        category: OpenFlags,
        description: Some("Read only"),
    });
    db.add(NamedConstant {
        name: "O_WRONLY",
        value: 0x0001,
        category: OpenFlags,
        description: Some("Write only"),
    });
    db.add(NamedConstant {
        name: "O_RDWR",
        value: 0x0002,
        category: OpenFlags,
        description: Some("Read and write"),
    });
    db.add(NamedConstant {
        name: "O_CREAT",
        value: 0x0040,
        category: OpenFlags,
        description: Some("Create if not exists"),
    });
    db.add(NamedConstant {
        name: "O_EXCL",
        value: 0x0080,
        category: OpenFlags,
        description: Some("Exclusive create"),
    });
    db.add(NamedConstant {
        name: "O_TRUNC",
        value: 0x0200,
        category: OpenFlags,
        description: Some("Truncate"),
    });
    db.add(NamedConstant {
        name: "O_APPEND",
        value: 0x0400,
        category: OpenFlags,
        description: Some("Append mode"),
    });
    db.add(NamedConstant {
        name: "O_NONBLOCK",
        value: 0x0800,
        category: OpenFlags,
        description: Some("Non-blocking mode"),
    });

    // Seek whence values
    db.add(NamedConstant {
        name: "SEEK_SET",
        value: 0,
        category: Seek,
        description: Some("Seek from beginning"),
    });
    db.add(NamedConstant {
        name: "SEEK_CUR",
        value: 1,
        category: Seek,
        description: Some("Seek from current position"),
    });
    db.add(NamedConstant {
        name: "SEEK_END",
        value: 2,
        category: Seek,
        description: Some("Seek from end"),
    });

    // Signals (POSIX)
    db.add(NamedConstant {
        name: "SIGHUP",
        value: 1,
        category: Signal,
        description: Some("Hangup"),
    });
    db.add(NamedConstant {
        name: "SIGINT",
        value: 2,
        category: Signal,
        description: Some("Interrupt"),
    });
    db.add(NamedConstant {
        name: "SIGQUIT",
        value: 3,
        category: Signal,
        description: Some("Quit"),
    });
    db.add(NamedConstant {
        name: "SIGILL",
        value: 4,
        category: Signal,
        description: Some("Illegal instruction"),
    });
    db.add(NamedConstant {
        name: "SIGTRAP",
        value: 5,
        category: Signal,
        description: Some("Trace trap"),
    });
    db.add(NamedConstant {
        name: "SIGABRT",
        value: 6,
        category: Signal,
        description: Some("Abort"),
    });
    db.add(NamedConstant {
        name: "SIGFPE",
        value: 8,
        category: Signal,
        description: Some("Floating point exception"),
    });
    db.add(NamedConstant {
        name: "SIGKILL",
        value: 9,
        category: Signal,
        description: Some("Kill"),
    });
    db.add(NamedConstant {
        name: "SIGSEGV",
        value: 11,
        category: Signal,
        description: Some("Segmentation fault"),
    });
    db.add(NamedConstant {
        name: "SIGPIPE",
        value: 13,
        category: Signal,
        description: Some("Broken pipe"),
    });
    db.add(NamedConstant {
        name: "SIGALRM",
        value: 14,
        category: Signal,
        description: Some("Alarm"),
    });
    db.add(NamedConstant {
        name: "SIGTERM",
        value: 15,
        category: Signal,
        description: Some("Terminate"),
    });

    // Signal handlers
    db.add(NamedConstant {
        name: "SIG_DFL",
        value: 0,
        category: SignalHandler,
        description: Some("Default signal handler"),
    });
    db.add(NamedConstant {
        name: "SIG_IGN",
        value: 1,
        category: SignalHandler,
        description: Some("Ignore signal"),
    });

    // Common file permission modes (octal)
    db.add(NamedConstant {
        name: "0644",
        value: 0o644,
        category: FileMode,
        description: Some("rw-r--r--"),
    });
    db.add(NamedConstant {
        name: "0755",
        value: 0o755,
        category: FileMode,
        description: Some("rwxr-xr-x"),
    });
    db.add(NamedConstant {
        name: "0777",
        value: 0o777,
        category: FileMode,
        description: Some("rwxrwxrwx"),
    });
    db.add(NamedConstant {
        name: "0666",
        value: 0o666,
        category: FileMode,
        description: Some("rw-rw-rw-"),
    });
    db.add(NamedConstant {
        name: "0600",
        value: 0o600,
        category: FileMode,
        description: Some("rw-------"),
    });
    db.add(NamedConstant {
        name: "0700",
        value: 0o700,
        category: FileMode,
        description: Some("rwx------"),
    });

    // mmap protection flags
    db.add(NamedConstant {
        name: "PROT_NONE",
        value: 0x0,
        category: MmapProt,
        description: Some("No access"),
    });
    db.add(NamedConstant {
        name: "PROT_READ",
        value: 0x1,
        category: MmapProt,
        description: Some("Read access"),
    });
    db.add(NamedConstant {
        name: "PROT_WRITE",
        value: 0x2,
        category: MmapProt,
        description: Some("Write access"),
    });
    db.add(NamedConstant {
        name: "PROT_EXEC",
        value: 0x4,
        category: MmapProt,
        description: Some("Execute access"),
    });

    // mmap flags
    db.add(NamedConstant {
        name: "MAP_SHARED",
        value: 0x01,
        category: MmapFlags,
        description: Some("Share changes"),
    });
    db.add(NamedConstant {
        name: "MAP_PRIVATE",
        value: 0x02,
        category: MmapFlags,
        description: Some("Private copy-on-write"),
    });
    db.add(NamedConstant {
        name: "MAP_FIXED",
        value: 0x10,
        category: MmapFlags,
        description: Some("Fixed address"),
    });
    db.add(NamedConstant {
        name: "MAP_ANONYMOUS",
        value: 0x20,
        category: MmapFlags,
        description: Some("Anonymous mapping"),
    });

    // Socket address families
    db.add(NamedConstant {
        name: "AF_UNSPEC",
        value: 0,
        category: AddressFamily,
        description: Some("Unspecified"),
    });
    db.add(NamedConstant {
        name: "AF_UNIX",
        value: 1,
        category: AddressFamily,
        description: Some("Unix domain"),
    });
    db.add(NamedConstant {
        name: "AF_INET",
        value: 2,
        category: AddressFamily,
        description: Some("IPv4"),
    });
    db.add(NamedConstant {
        name: "AF_INET6",
        value: 10,
        category: AddressFamily,
        description: Some("IPv6"),
    });

    // Socket types
    db.add(NamedConstant {
        name: "SOCK_STREAM",
        value: 1,
        category: SocketType,
        description: Some("TCP"),
    });
    db.add(NamedConstant {
        name: "SOCK_DGRAM",
        value: 2,
        category: SocketType,
        description: Some("UDP"),
    });
    db.add(NamedConstant {
        name: "SOCK_RAW",
        value: 3,
        category: SocketType,
        description: Some("Raw socket"),
    });

    // fcntl commands
    db.add(NamedConstant {
        name: "F_DUPFD",
        value: 0,
        category: Fcntl,
        description: Some("Duplicate fd"),
    });
    db.add(NamedConstant {
        name: "F_GETFD",
        value: 1,
        category: Fcntl,
        description: Some("Get fd flags"),
    });
    db.add(NamedConstant {
        name: "F_SETFD",
        value: 2,
        category: Fcntl,
        description: Some("Set fd flags"),
    });
    db.add(NamedConstant {
        name: "F_GETFL",
        value: 3,
        category: Fcntl,
        description: Some("Get file status flags"),
    });
    db.add(NamedConstant {
        name: "F_SETFL",
        value: 4,
        category: Fcntl,
        description: Some("Set file status flags"),
    });
    db.add(NamedConstant {
        name: "F_GETOWN",
        value: 5,
        category: Fcntl,
        description: Some("Get process/group ID receiving SIGIO"),
    });
    db.add(NamedConstant {
        name: "F_SETOWN",
        value: 6,
        category: Fcntl,
        description: Some("Set process/group ID to receive SIGIO"),
    });
    db.add(NamedConstant {
        name: "F_GETLK",
        value: 7,
        category: Fcntl,
        description: Some("Get record locking info"),
    });
    db.add(NamedConstant {
        name: "F_SETLK",
        value: 8,
        category: Fcntl,
        description: Some("Set record locking info"),
    });
    db.add(NamedConstant {
        name: "F_SETLKW",
        value: 9,
        category: Fcntl,
        description: Some("Set record locking info; wait if blocked"),
    });
    // macOS-specific fcntl commands
    db.add(NamedConstant {
        name: "F_ALLOCATECONTIG",
        value: 0x02,
        category: Fcntl,
        description: Some("Allocate contiguous space"),
    });
    db.add(NamedConstant {
        name: "F_NOCACHE",
        value: 48,
        category: Fcntl,
        description: Some("Turn data caching off/on"),
    });
    db.add(NamedConstant {
        name: "F_FULLFSYNC",
        value: 51,
        category: Fcntl,
        description: Some("Full fsync including device flush"),
    });

    // Poll events
    db.add(NamedConstant {
        name: "POLLIN",
        value: 0x0001,
        category: PollEvents,
        description: Some("Data to read"),
    });
    db.add(NamedConstant {
        name: "POLLPRI",
        value: 0x0002,
        category: PollEvents,
        description: Some("Urgent data"),
    });
    db.add(NamedConstant {
        name: "POLLOUT",
        value: 0x0004,
        category: PollEvents,
        description: Some("Writing possible"),
    });
    db.add(NamedConstant {
        name: "POLLERR",
        value: 0x0008,
        category: PollEvents,
        description: Some("Error"),
    });
    db.add(NamedConstant {
        name: "POLLHUP",
        value: 0x0010,
        category: PollEvents,
        description: Some("Hang up"),
    });
    db.add(NamedConstant {
        name: "POLLNVAL",
        value: 0x0020,
        category: PollEvents,
        description: Some("Invalid fd"),
    });

    // Common errno values (POSIX standard ones)
    db.add(NamedConstant {
        name: "EPERM",
        value: 1,
        category: Errno,
        description: Some("Operation not permitted"),
    });
    db.add(NamedConstant {
        name: "ENOENT",
        value: 2,
        category: Errno,
        description: Some("No such file or directory"),
    });
    db.add(NamedConstant {
        name: "ESRCH",
        value: 3,
        category: Errno,
        description: Some("No such process"),
    });
    db.add(NamedConstant {
        name: "EINTR",
        value: 4,
        category: Errno,
        description: Some("Interrupted system call"),
    });
    db.add(NamedConstant {
        name: "EIO",
        value: 5,
        category: Errno,
        description: Some("I/O error"),
    });
    db.add(NamedConstant {
        name: "ENXIO",
        value: 6,
        category: Errno,
        description: Some("No such device or address"),
    });
    db.add(NamedConstant {
        name: "E2BIG",
        value: 7,
        category: Errno,
        description: Some("Argument list too long"),
    });
    db.add(NamedConstant {
        name: "ENOEXEC",
        value: 8,
        category: Errno,
        description: Some("Exec format error"),
    });
    db.add(NamedConstant {
        name: "EBADF",
        value: 9,
        category: Errno,
        description: Some("Bad file descriptor"),
    });
    db.add(NamedConstant {
        name: "ECHILD",
        value: 10,
        category: Errno,
        description: Some("No child processes"),
    });
    db.add(NamedConstant {
        name: "EAGAIN",
        value: 11,
        category: Errno,
        description: Some("Resource temporarily unavailable"),
    });
    db.add(NamedConstant {
        name: "ENOMEM",
        value: 12,
        category: Errno,
        description: Some("Out of memory"),
    });
    db.add(NamedConstant {
        name: "EACCES",
        value: 13,
        category: Errno,
        description: Some("Permission denied"),
    });
    db.add(NamedConstant {
        name: "EFAULT",
        value: 14,
        category: Errno,
        description: Some("Bad address"),
    });
    db.add(NamedConstant {
        name: "EBUSY",
        value: 16,
        category: Errno,
        description: Some("Device or resource busy"),
    });
    db.add(NamedConstant {
        name: "EEXIST",
        value: 17,
        category: Errno,
        description: Some("File exists"),
    });
    db.add(NamedConstant {
        name: "ENODEV",
        value: 19,
        category: Errno,
        description: Some("No such device"),
    });
    db.add(NamedConstant {
        name: "ENOTDIR",
        value: 20,
        category: Errno,
        description: Some("Not a directory"),
    });
    db.add(NamedConstant {
        name: "EISDIR",
        value: 21,
        category: Errno,
        description: Some("Is a directory"),
    });
    db.add(NamedConstant {
        name: "EINVAL",
        value: 22,
        category: Errno,
        description: Some("Invalid argument"),
    });

    // *at() syscall constants
    db.add(NamedConstant {
        name: "AT_FDCWD",
        value: -100, // -2 on macOS, -100 on Linux
        category: AtFlags,
        description: Some("Use current working directory (Linux)"),
    });
    db.add(NamedConstant {
        name: "AT_SYMLINK_NOFOLLOW",
        value: 0x100,
        category: AtFlags,
        description: Some("Do not follow symlinks"),
    });
    db.add(NamedConstant {
        name: "AT_REMOVEDIR",
        value: 0x200,
        category: AtFlags,
        description: Some("Remove directory instead of file"),
    });
    db.add(NamedConstant {
        name: "AT_SYMLINK_FOLLOW",
        value: 0x400,
        category: AtFlags,
        description: Some("Follow symbolic links"),
    });
    db.add(NamedConstant {
        name: "AT_EACCESS",
        value: 0x200,
        category: AtFlags,
        description: Some("Use effective IDs for access check"),
    });
}

/// Load Linux-specific constants.
pub fn load_linux_constants(db: &mut ConstantDatabase) {
    use ConstantCategory::*;

    // Linux-specific ioctl codes (x86_64)
    // Terminal ioctls
    db.add(NamedConstant {
        name: "TCGETS",
        value: 0x5401,
        category: Ioctl,
        description: Some("Get terminal attributes"),
    });
    db.add(NamedConstant {
        name: "TCSETS",
        value: 0x5402,
        category: Ioctl,
        description: Some("Set terminal attributes"),
    });
    db.add(NamedConstant {
        name: "TCSETSW",
        value: 0x5403,
        category: Ioctl,
        description: Some("Set terminal attributes (drain)"),
    });
    db.add(NamedConstant {
        name: "TCSETSF",
        value: 0x5404,
        category: Ioctl,
        description: Some("Set terminal attributes (drain, flush)"),
    });
    db.add(NamedConstant {
        name: "TIOCGWINSZ",
        value: 0x5413,
        category: Ioctl,
        description: Some("Get window size"),
    });
    db.add(NamedConstant {
        name: "TIOCSWINSZ",
        value: 0x5414,
        category: Ioctl,
        description: Some("Set window size"),
    });
    db.add(NamedConstant {
        name: "TIOCGPGRP",
        value: 0x540F,
        category: Ioctl,
        description: Some("Get process group"),
    });
    db.add(NamedConstant {
        name: "TIOCSPGRP",
        value: 0x5410,
        category: Ioctl,
        description: Some("Set process group"),
    });
    db.add(NamedConstant {
        name: "FIONREAD",
        value: 0x541B,
        category: Ioctl,
        description: Some("Get bytes available to read"),
    });
    db.add(NamedConstant {
        name: "FIONBIO",
        value: 0x5421,
        category: Ioctl,
        description: Some("Set/clear non-blocking I/O"),
    });

    // Linux-specific signals
    db.add(NamedConstant {
        name: "SIGBUS",
        value: 7,
        category: Signal,
        description: Some("Bus error"),
    });
    db.add(NamedConstant {
        name: "SIGUSR1",
        value: 10,
        category: Signal,
        description: Some("User signal 1"),
    });
    db.add(NamedConstant {
        name: "SIGUSR2",
        value: 12,
        category: Signal,
        description: Some("User signal 2"),
    });
    db.add(NamedConstant {
        name: "SIGCHLD",
        value: 17,
        category: Signal,
        description: Some("Child stopped/terminated"),
    });
    db.add(NamedConstant {
        name: "SIGCONT",
        value: 18,
        category: Signal,
        description: Some("Continue"),
    });
    db.add(NamedConstant {
        name: "SIGSTOP",
        value: 19,
        category: Signal,
        description: Some("Stop process"),
    });
    db.add(NamedConstant {
        name: "SIGTSTP",
        value: 20,
        category: Signal,
        description: Some("Terminal stop"),
    });
    db.add(NamedConstant {
        name: "SIGTTIN",
        value: 21,
        category: Signal,
        description: Some("Background read from tty"),
    });
    db.add(NamedConstant {
        name: "SIGTTOU",
        value: 22,
        category: Signal,
        description: Some("Background write to tty"),
    });
    db.add(NamedConstant {
        name: "SIGWINCH",
        value: 28,
        category: Signal,
        description: Some("Window resize"),
    });

    // Linux-specific epoll
    db.add(NamedConstant {
        name: "EPOLL_CTL_ADD",
        value: 1,
        category: EpollCtl,
        description: Some("Add fd to epoll"),
    });
    db.add(NamedConstant {
        name: "EPOLL_CTL_DEL",
        value: 2,
        category: EpollCtl,
        description: Some("Remove fd from epoll"),
    });
    db.add(NamedConstant {
        name: "EPOLL_CTL_MOD",
        value: 3,
        category: EpollCtl,
        description: Some("Modify fd in epoll"),
    });
    db.add(NamedConstant {
        name: "EPOLLIN",
        value: 0x001,
        category: PollEvents,
        description: Some("Available for read"),
    });
    db.add(NamedConstant {
        name: "EPOLLOUT",
        value: 0x004,
        category: PollEvents,
        description: Some("Available for write"),
    });
    db.add(NamedConstant {
        name: "EPOLLERR",
        value: 0x008,
        category: PollEvents,
        description: Some("Error condition"),
    });
    db.add(NamedConstant {
        name: "EPOLLHUP",
        value: 0x010,
        category: PollEvents,
        description: Some("Hang up"),
    });
    db.add(NamedConstant {
        name: "EPOLLET",
        value: 1 << 31,
        category: PollEvents,
        description: Some("Edge triggered"),
    });

    // Linux-specific open flags
    db.add(NamedConstant {
        name: "O_DIRECT",
        value: 0x4000,
        category: OpenFlags,
        description: Some("Direct I/O (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_LARGEFILE",
        value: 0x8000,
        category: OpenFlags,
        description: Some("Large file support (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_DIRECTORY",
        value: 0x10000,
        category: OpenFlags,
        description: Some("Must be directory (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_NOFOLLOW",
        value: 0x20000,
        category: OpenFlags,
        description: Some("Don't follow symlinks (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_NOATIME",
        value: 0x40000,
        category: OpenFlags,
        description: Some("Don't update atime (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_CLOEXEC",
        value: 0x80000,
        category: OpenFlags,
        description: Some("Close on exec (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_PATH",
        value: 0x200000,
        category: OpenFlags,
        description: Some("Path-only fd (Linux)"),
    });
    db.add(NamedConstant {
        name: "O_TMPFILE",
        value: 0x410000,
        category: OpenFlags,
        description: Some("Temporary file (Linux)"),
    });

    // Socket option levels
    db.add(NamedConstant {
        name: "SOL_SOCKET",
        value: 1,
        category: SockOptLevel,
        description: Some("Socket level options"),
    });
    db.add(NamedConstant {
        name: "IPPROTO_IP",
        value: 0,
        category: SockOptLevel,
        description: Some("IP protocol options"),
    });
    db.add(NamedConstant {
        name: "IPPROTO_TCP",
        value: 6,
        category: SockOptLevel,
        description: Some("TCP protocol options"),
    });
    db.add(NamedConstant {
        name: "IPPROTO_UDP",
        value: 17,
        category: SockOptLevel,
        description: Some("UDP protocol options"),
    });
    db.add(NamedConstant {
        name: "IPPROTO_IPV6",
        value: 41,
        category: SockOptLevel,
        description: Some("IPv6 protocol options"),
    });

    // Socket options (SOL_SOCKET level)
    db.add(NamedConstant {
        name: "SO_DEBUG",
        value: 1,
        category: SockOpt,
        description: Some("Enable debugging"),
    });
    db.add(NamedConstant {
        name: "SO_REUSEADDR",
        value: 2,
        category: SockOpt,
        description: Some("Allow address reuse"),
    });
    db.add(NamedConstant {
        name: "SO_TYPE",
        value: 3,
        category: SockOpt,
        description: Some("Get socket type"),
    });
    db.add(NamedConstant {
        name: "SO_ERROR",
        value: 4,
        category: SockOpt,
        description: Some("Get/clear error"),
    });
    db.add(NamedConstant {
        name: "SO_DONTROUTE",
        value: 5,
        category: SockOpt,
        description: Some("Bypass routing"),
    });
    db.add(NamedConstant {
        name: "SO_BROADCAST",
        value: 6,
        category: SockOpt,
        description: Some("Allow broadcast"),
    });
    db.add(NamedConstant {
        name: "SO_SNDBUF",
        value: 7,
        category: SockOpt,
        description: Some("Send buffer size"),
    });
    db.add(NamedConstant {
        name: "SO_RCVBUF",
        value: 8,
        category: SockOpt,
        description: Some("Receive buffer size"),
    });
    db.add(NamedConstant {
        name: "SO_KEEPALIVE",
        value: 9,
        category: SockOpt,
        description: Some("Enable keepalive"),
    });
    db.add(NamedConstant {
        name: "SO_OOBINLINE",
        value: 10,
        category: SockOpt,
        description: Some("OOB data inline"),
    });
    db.add(NamedConstant {
        name: "SO_LINGER",
        value: 13,
        category: SockOpt,
        description: Some("Linger on close"),
    });
    db.add(NamedConstant {
        name: "SO_REUSEPORT",
        value: 15,
        category: SockOpt,
        description: Some("Allow port reuse"),
    });
    db.add(NamedConstant {
        name: "SO_RCVTIMEO",
        value: 20,
        category: SockOpt,
        description: Some("Receive timeout"),
    });
    db.add(NamedConstant {
        name: "SO_SNDTIMEO",
        value: 21,
        category: SockOpt,
        description: Some("Send timeout"),
    });

    // TCP options
    db.add(NamedConstant {
        name: "TCP_NODELAY",
        value: 1,
        category: SockOpt,
        description: Some("Disable Nagle algorithm"),
    });
    db.add(NamedConstant {
        name: "TCP_MAXSEG",
        value: 2,
        category: SockOpt,
        description: Some("Max segment size"),
    });
    db.add(NamedConstant {
        name: "TCP_CORK",
        value: 3,
        category: SockOpt,
        description: Some("Cork output"),
    });
    db.add(NamedConstant {
        name: "TCP_KEEPIDLE",
        value: 4,
        category: SockOpt,
        description: Some("Keepalive idle time"),
    });
    db.add(NamedConstant {
        name: "TCP_KEEPINTVL",
        value: 5,
        category: SockOpt,
        description: Some("Keepalive interval"),
    });
    db.add(NamedConstant {
        name: "TCP_KEEPCNT",
        value: 6,
        category: SockOpt,
        description: Some("Keepalive count"),
    });
    db.add(NamedConstant {
        name: "TCP_QUICKACK",
        value: 12,
        category: SockOpt,
        description: Some("Quick ACK mode"),
    });
    db.add(NamedConstant {
        name: "TCP_FASTOPEN",
        value: 23,
        category: SockOpt,
        description: Some("TCP Fast Open"),
    });

    // More network ioctls
    db.add(NamedConstant {
        name: "SIOCGIFNAME",
        value: 0x8910,
        category: Ioctl,
        description: Some("Get interface name"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFCONF",
        value: 0x8912,
        category: Ioctl,
        description: Some("Get interface list"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFFLAGS",
        value: 0x8913,
        category: Ioctl,
        description: Some("Get interface flags"),
    });
    db.add(NamedConstant {
        name: "SIOCSIFFLAGS",
        value: 0x8914,
        category: Ioctl,
        description: Some("Set interface flags"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFADDR",
        value: 0x8915,
        category: Ioctl,
        description: Some("Get interface address"),
    });
    db.add(NamedConstant {
        name: "SIOCSIFADDR",
        value: 0x8916,
        category: Ioctl,
        description: Some("Set interface address"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFNETMASK",
        value: 0x891B,
        category: Ioctl,
        description: Some("Get netmask"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFHWADDR",
        value: 0x8927,
        category: Ioctl,
        description: Some("Get hardware address"),
    });
    db.add(NamedConstant {
        name: "SIOCGIFINDEX",
        value: 0x8933,
        category: Ioctl,
        description: Some("Get interface index"),
    });

    // Block device ioctls
    db.add(NamedConstant {
        name: "BLKROSET",
        value: 0x125D,
        category: Ioctl,
        description: Some("Set read-only"),
    });
    db.add(NamedConstant {
        name: "BLKROGET",
        value: 0x125E,
        category: Ioctl,
        description: Some("Get read-only"),
    });
    db.add(NamedConstant {
        name: "BLKGETSIZE",
        value: 0x1260,
        category: Ioctl,
        description: Some("Get device size (sectors)"),
    });
    db.add(NamedConstant {
        name: "BLKFLSBUF",
        value: 0x1261,
        category: Ioctl,
        description: Some("Flush buffer cache"),
    });
    db.add(NamedConstant {
        name: "BLKGETSIZE64",
        value: 0x80081272,
        category: Ioctl,
        description: Some("Get device size (bytes)"),
    });
    db.add(NamedConstant {
        name: "BLKDISCARD",
        value: 0x1277,
        category: Ioctl,
        description: Some("Discard sectors"),
    });

    // More errno values
    db.add(NamedConstant {
        name: "EPERM",
        value: 1,
        category: Errno,
        description: Some("Operation not permitted"),
    });
    db.add(NamedConstant {
        name: "ENOENT",
        value: 2,
        category: Errno,
        description: Some("No such file or directory"),
    });
    db.add(NamedConstant {
        name: "ESRCH",
        value: 3,
        category: Errno,
        description: Some("No such process"),
    });
    db.add(NamedConstant {
        name: "EINTR",
        value: 4,
        category: Errno,
        description: Some("Interrupted system call"),
    });
    db.add(NamedConstant {
        name: "EIO",
        value: 5,
        category: Errno,
        description: Some("I/O error"),
    });
    db.add(NamedConstant {
        name: "ENXIO",
        value: 6,
        category: Errno,
        description: Some("No such device or address"),
    });
    db.add(NamedConstant {
        name: "E2BIG",
        value: 7,
        category: Errno,
        description: Some("Argument list too long"),
    });
    db.add(NamedConstant {
        name: "ENOEXEC",
        value: 8,
        category: Errno,
        description: Some("Exec format error"),
    });
    db.add(NamedConstant {
        name: "EBADF",
        value: 9,
        category: Errno,
        description: Some("Bad file descriptor"),
    });
    db.add(NamedConstant {
        name: "ECHILD",
        value: 10,
        category: Errno,
        description: Some("No child processes"),
    });
    db.add(NamedConstant {
        name: "EAGAIN",
        value: 11,
        category: Errno,
        description: Some("Try again"),
    });
    db.add(NamedConstant {
        name: "ENOMEM",
        value: 12,
        category: Errno,
        description: Some("Out of memory"),
    });
    db.add(NamedConstant {
        name: "EACCES",
        value: 13,
        category: Errno,
        description: Some("Permission denied"),
    });
    db.add(NamedConstant {
        name: "EFAULT",
        value: 14,
        category: Errno,
        description: Some("Bad address"),
    });
    db.add(NamedConstant {
        name: "EBUSY",
        value: 16,
        category: Errno,
        description: Some("Device or resource busy"),
    });
    db.add(NamedConstant {
        name: "EEXIST",
        value: 17,
        category: Errno,
        description: Some("File exists"),
    });
    db.add(NamedConstant {
        name: "EXDEV",
        value: 18,
        category: Errno,
        description: Some("Cross-device link"),
    });
    db.add(NamedConstant {
        name: "ENODEV",
        value: 19,
        category: Errno,
        description: Some("No such device"),
    });
    db.add(NamedConstant {
        name: "ENOTDIR",
        value: 20,
        category: Errno,
        description: Some("Not a directory"),
    });
    db.add(NamedConstant {
        name: "EISDIR",
        value: 21,
        category: Errno,
        description: Some("Is a directory"),
    });
    db.add(NamedConstant {
        name: "ENFILE",
        value: 23,
        category: Errno,
        description: Some("File table overflow"),
    });
    db.add(NamedConstant {
        name: "EMFILE",
        value: 24,
        category: Errno,
        description: Some("Too many open files"),
    });
    db.add(NamedConstant {
        name: "ENOTTY",
        value: 25,
        category: Errno,
        description: Some("Not a typewriter"),
    });
    db.add(NamedConstant {
        name: "ETXTBSY",
        value: 26,
        category: Errno,
        description: Some("Text file busy"),
    });
    db.add(NamedConstant {
        name: "EFBIG",
        value: 27,
        category: Errno,
        description: Some("File too large"),
    });
    db.add(NamedConstant {
        name: "ENOSPC",
        value: 28,
        category: Errno,
        description: Some("No space left on device"),
    });
    db.add(NamedConstant {
        name: "ESPIPE",
        value: 29,
        category: Errno,
        description: Some("Illegal seek"),
    });
    db.add(NamedConstant {
        name: "EROFS",
        value: 30,
        category: Errno,
        description: Some("Read-only file system"),
    });
    db.add(NamedConstant {
        name: "EMLINK",
        value: 31,
        category: Errno,
        description: Some("Too many links"),
    });
    db.add(NamedConstant {
        name: "EPIPE",
        value: 32,
        category: Errno,
        description: Some("Broken pipe"),
    });
    db.add(NamedConstant {
        name: "EWOULDBLOCK",
        value: 11,
        category: Errno,
        description: Some("Would block (same as EAGAIN)"),
    });
    db.add(NamedConstant {
        name: "EINPROGRESS",
        value: 115,
        category: Errno,
        description: Some("Operation in progress"),
    });
    db.add(NamedConstant {
        name: "ECONNREFUSED",
        value: 111,
        category: Errno,
        description: Some("Connection refused"),
    });
    db.add(NamedConstant {
        name: "ECONNRESET",
        value: 104,
        category: Errno,
        description: Some("Connection reset by peer"),
    });
    db.add(NamedConstant {
        name: "ETIMEDOUT",
        value: 110,
        category: Errno,
        description: Some("Connection timed out"),
    });

    // Wait options
    db.add(NamedConstant {
        name: "WNOHANG",
        value: 1,
        category: WaitOptions,
        description: Some("Don't block"),
    });
    db.add(NamedConstant {
        name: "WUNTRACED",
        value: 2,
        category: WaitOptions,
        description: Some("Report stopped children"),
    });
    db.add(NamedConstant {
        name: "WCONTINUED",
        value: 8,
        category: WaitOptions,
        description: Some("Report continued children"),
    });
    db.add(NamedConstant {
        name: "WNOWAIT",
        value: 0x01000000,
        category: WaitOptions,
        description: Some("Don't reap child"),
    });

    // ptrace requests
    db.add(NamedConstant {
        name: "PTRACE_TRACEME",
        value: 0,
        category: PtraceRequest,
        description: Some("Allow parent to trace"),
    });
    db.add(NamedConstant {
        name: "PTRACE_PEEKTEXT",
        value: 1,
        category: PtraceRequest,
        description: Some("Read word at addr"),
    });
    db.add(NamedConstant {
        name: "PTRACE_PEEKDATA",
        value: 2,
        category: PtraceRequest,
        description: Some("Read word at addr"),
    });
    db.add(NamedConstant {
        name: "PTRACE_PEEKUSER",
        value: 3,
        category: PtraceRequest,
        description: Some("Read word in user area"),
    });
    db.add(NamedConstant {
        name: "PTRACE_POKETEXT",
        value: 4,
        category: PtraceRequest,
        description: Some("Write word at addr"),
    });
    db.add(NamedConstant {
        name: "PTRACE_POKEDATA",
        value: 5,
        category: PtraceRequest,
        description: Some("Write word at addr"),
    });
    db.add(NamedConstant {
        name: "PTRACE_POKEUSER",
        value: 6,
        category: PtraceRequest,
        description: Some("Write word in user area"),
    });
    db.add(NamedConstant {
        name: "PTRACE_CONT",
        value: 7,
        category: PtraceRequest,
        description: Some("Continue execution"),
    });
    db.add(NamedConstant {
        name: "PTRACE_KILL",
        value: 8,
        category: PtraceRequest,
        description: Some("Kill tracee"),
    });
    db.add(NamedConstant {
        name: "PTRACE_SINGLESTEP",
        value: 9,
        category: PtraceRequest,
        description: Some("Single step"),
    });
    db.add(NamedConstant {
        name: "PTRACE_GETREGS",
        value: 12,
        category: PtraceRequest,
        description: Some("Get registers"),
    });
    db.add(NamedConstant {
        name: "PTRACE_SETREGS",
        value: 13,
        category: PtraceRequest,
        description: Some("Set registers"),
    });
    db.add(NamedConstant {
        name: "PTRACE_ATTACH",
        value: 16,
        category: PtraceRequest,
        description: Some("Attach to process"),
    });
    db.add(NamedConstant {
        name: "PTRACE_DETACH",
        value: 17,
        category: PtraceRequest,
        description: Some("Detach from process"),
    });
    db.add(NamedConstant {
        name: "PTRACE_SYSCALL",
        value: 24,
        category: PtraceRequest,
        description: Some("Continue to next syscall"),
    });
    db.add(NamedConstant {
        name: "PTRACE_SETOPTIONS",
        value: 0x4200,
        category: PtraceRequest,
        description: Some("Set ptrace options"),
    });
    db.add(NamedConstant {
        name: "PTRACE_GETEVENTMSG",
        value: 0x4201,
        category: PtraceRequest,
        description: Some("Get event message"),
    });
    db.add(NamedConstant {
        name: "PTRACE_SEIZE",
        value: 0x4206,
        category: PtraceRequest,
        description: Some("Seize process"),
    });

    // prctl options
    db.add(NamedConstant {
        name: "PR_SET_PDEATHSIG",
        value: 1,
        category: PrctlOption,
        description: Some("Set parent death signal"),
    });
    db.add(NamedConstant {
        name: "PR_GET_PDEATHSIG",
        value: 2,
        category: PrctlOption,
        description: Some("Get parent death signal"),
    });
    db.add(NamedConstant {
        name: "PR_SET_DUMPABLE",
        value: 4,
        category: PrctlOption,
        description: Some("Set dumpable flag"),
    });
    db.add(NamedConstant {
        name: "PR_GET_DUMPABLE",
        value: 3,
        category: PrctlOption,
        description: Some("Get dumpable flag"),
    });
    db.add(NamedConstant {
        name: "PR_SET_NAME",
        value: 15,
        category: PrctlOption,
        description: Some("Set process name"),
    });
    db.add(NamedConstant {
        name: "PR_GET_NAME",
        value: 16,
        category: PrctlOption,
        description: Some("Get process name"),
    });
    db.add(NamedConstant {
        name: "PR_SET_SECCOMP",
        value: 22,
        category: PrctlOption,
        description: Some("Set seccomp mode"),
    });
    db.add(NamedConstant {
        name: "PR_GET_SECCOMP",
        value: 21,
        category: PrctlOption,
        description: Some("Get seccomp mode"),
    });
    db.add(NamedConstant {
        name: "PR_SET_NO_NEW_PRIVS",
        value: 38,
        category: PrctlOption,
        description: Some("Set no-new-privileges"),
    });
    db.add(NamedConstant {
        name: "PR_GET_NO_NEW_PRIVS",
        value: 39,
        category: PrctlOption,
        description: Some("Get no-new-privileges"),
    });
    db.add(NamedConstant {
        name: "PR_CAP_AMBIENT",
        value: 47,
        category: PrctlOption,
        description: Some("Ambient capabilities"),
    });

    // Seccomp
    db.add(NamedConstant {
        name: "SECCOMP_MODE_DISABLED",
        value: 0,
        category: Seccomp,
        description: Some("Seccomp disabled"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_MODE_STRICT",
        value: 1,
        category: Seccomp,
        description: Some("Strict mode"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_MODE_FILTER",
        value: 2,
        category: Seccomp,
        description: Some("Filter mode"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_SET_MODE_STRICT",
        value: 0,
        category: Seccomp,
        description: Some("Set strict mode"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_SET_MODE_FILTER",
        value: 1,
        category: Seccomp,
        description: Some("Set filter mode"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_GET_ACTION_AVAIL",
        value: 2,
        category: Seccomp,
        description: Some("Check action availability"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_KILL_PROCESS",
        value: 0x80000000,
        category: Seccomp,
        description: Some("Kill process"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_KILL_THREAD",
        value: 0x00000000,
        category: Seccomp,
        description: Some("Kill thread"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_TRAP",
        value: 0x00030000,
        category: Seccomp,
        description: Some("Deliver SIGSYS"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_ERRNO",
        value: 0x00050000,
        category: Seccomp,
        description: Some("Return errno"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_TRACE",
        value: 0x7ff00000,
        category: Seccomp,
        description: Some("Pass to tracer"),
    });
    db.add(NamedConstant {
        name: "SECCOMP_RET_ALLOW",
        value: 0x7fff0000,
        category: Seccomp,
        description: Some("Allow syscall"),
    });

    // Clone flags
    db.add(NamedConstant {
        name: "CLONE_VM",
        value: 0x00000100,
        category: CloneFlags,
        description: Some("Share VM"),
    });
    db.add(NamedConstant {
        name: "CLONE_FS",
        value: 0x00000200,
        category: CloneFlags,
        description: Some("Share filesystem info"),
    });
    db.add(NamedConstant {
        name: "CLONE_FILES",
        value: 0x00000400,
        category: CloneFlags,
        description: Some("Share file descriptors"),
    });
    db.add(NamedConstant {
        name: "CLONE_SIGHAND",
        value: 0x00000800,
        category: CloneFlags,
        description: Some("Share signal handlers"),
    });
    db.add(NamedConstant {
        name: "CLONE_PTRACE",
        value: 0x00002000,
        category: CloneFlags,
        description: Some("Allow ptrace by parent"),
    });
    db.add(NamedConstant {
        name: "CLONE_VFORK",
        value: 0x00004000,
        category: CloneFlags,
        description: Some("Parent sleeps until child exits"),
    });
    db.add(NamedConstant {
        name: "CLONE_PARENT",
        value: 0x00008000,
        category: CloneFlags,
        description: Some("Same parent as caller"),
    });
    db.add(NamedConstant {
        name: "CLONE_THREAD",
        value: 0x00010000,
        category: CloneFlags,
        description: Some("Same thread group"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWNS",
        value: 0x00020000,
        category: CloneFlags,
        description: Some("New mount namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_SYSVSEM",
        value: 0x00040000,
        category: CloneFlags,
        description: Some("Share SysV semaphores"),
    });
    db.add(NamedConstant {
        name: "CLONE_SETTLS",
        value: 0x00080000,
        category: CloneFlags,
        description: Some("Set TLS"),
    });
    db.add(NamedConstant {
        name: "CLONE_PARENT_SETTID",
        value: 0x00100000,
        category: CloneFlags,
        description: Some("Set parent TID"),
    });
    db.add(NamedConstant {
        name: "CLONE_CHILD_CLEARTID",
        value: 0x00200000,
        category: CloneFlags,
        description: Some("Clear child TID"),
    });
    db.add(NamedConstant {
        name: "CLONE_DETACHED",
        value: 0x00400000,
        category: CloneFlags,
        description: Some("Unused (ignored)"),
    });
    db.add(NamedConstant {
        name: "CLONE_CHILD_SETTID",
        value: 0x01000000,
        category: CloneFlags,
        description: Some("Set child TID"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWCGROUP",
        value: 0x02000000,
        category: CloneFlags,
        description: Some("New cgroup namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWUTS",
        value: 0x04000000,
        category: CloneFlags,
        description: Some("New UTS namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWIPC",
        value: 0x08000000,
        category: CloneFlags,
        description: Some("New IPC namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWUSER",
        value: 0x10000000,
        category: CloneFlags,
        description: Some("New user namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWPID",
        value: 0x20000000,
        category: CloneFlags,
        description: Some("New PID namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_NEWNET",
        value: 0x40000000,
        category: CloneFlags,
        description: Some("New network namespace"),
    });
    db.add(NamedConstant {
        name: "CLONE_IO",
        value: 0x80000000u32 as i128,
        category: CloneFlags,
        description: Some("Share I/O context"),
    });
}

/// Load macOS-specific constants.
pub fn load_macos_constants(db: &mut ConstantDatabase) {
    use ConstantCategory::*;

    // macOS ioctl codes (different encoding)
    // TIOCGWINSZ on macOS: _IOR('t', 104, struct winsize) = 0x40087468
    db.add(NamedConstant {
        name: "TIOCGWINSZ",
        value: 0x40087468,
        category: Ioctl,
        description: Some("Get window size"),
    });
    db.add(NamedConstant {
        name: "TIOCSWINSZ",
        value: 0x80087467,
        category: Ioctl,
        description: Some("Set window size"),
    });
    db.add(NamedConstant {
        name: "TIOCGPGRP",
        value: 0x40047477,
        category: Ioctl,
        description: Some("Get process group"),
    });
    db.add(NamedConstant {
        name: "TIOCSPGRP",
        value: 0x80047476,
        category: Ioctl,
        description: Some("Set process group"),
    });
    db.add(NamedConstant {
        name: "FIONREAD",
        value: 0x4004667F,
        category: Ioctl,
        description: Some("Get bytes available to read"),
    });
    db.add(NamedConstant {
        name: "FIONBIO",
        value: 0x8004667E,
        category: Ioctl,
        description: Some("Set/clear non-blocking I/O"),
    });

    // macOS open flags (different values)
    db.add(NamedConstant {
        name: "O_CREAT",
        value: 0x0200,
        category: OpenFlags,
        description: Some("Create if not exists (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_EXCL",
        value: 0x0800,
        category: OpenFlags,
        description: Some("Exclusive create (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_TRUNC",
        value: 0x0400,
        category: OpenFlags,
        description: Some("Truncate (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_NONBLOCK",
        value: 0x0004,
        category: OpenFlags,
        description: Some("Non-blocking (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_APPEND",
        value: 0x0008,
        category: OpenFlags,
        description: Some("Append mode (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_SHLOCK",
        value: 0x0010,
        category: OpenFlags,
        description: Some("Shared lock (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_EXLOCK",
        value: 0x0020,
        category: OpenFlags,
        description: Some("Exclusive lock (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_ASYNC",
        value: 0x0040,
        category: OpenFlags,
        description: Some("Async I/O (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_NOFOLLOW",
        value: 0x0100,
        category: OpenFlags,
        description: Some("Don't follow symlinks (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_EVTONLY",
        value: 0x8000,
        category: OpenFlags,
        description: Some("Event notifications only (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_NOCTTY",
        value: 0x20000,
        category: OpenFlags,
        description: Some("Don't assign controlling terminal (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_DIRECTORY",
        value: 0x100000,
        category: OpenFlags,
        description: Some("Must be a directory (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_SYMLINK",
        value: 0x200000,
        category: OpenFlags,
        description: Some("Allow open of symlink (macOS)"),
    });
    db.add(NamedConstant {
        name: "O_CLOEXEC",
        value: 0x1000000,
        category: OpenFlags,
        description: Some("Close on exec (macOS)"),
    });

    // macOS-specific mmap flag
    db.add(NamedConstant {
        name: "MAP_ANON",
        value: 0x1000,
        category: MmapFlags,
        description: Some("Anonymous mapping (macOS)"),
    });

    // macOS socket constants
    db.add(NamedConstant {
        name: "AF_INET6",
        value: 30,
        category: AddressFamily,
        description: Some("IPv6 (macOS)"),
    });

    // macOS signals (different numbers for some)
    db.add(NamedConstant {
        name: "SIGBUS",
        value: 10,
        category: Signal,
        description: Some("Bus error (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGUSR1",
        value: 30,
        category: Signal,
        description: Some("User signal 1 (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGUSR2",
        value: 31,
        category: Signal,
        description: Some("User signal 2 (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGCHLD",
        value: 20,
        category: Signal,
        description: Some("Child stopped/terminated (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGCONT",
        value: 19,
        category: Signal,
        description: Some("Continue (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGSTOP",
        value: 17,
        category: Signal,
        description: Some("Stop process (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGTSTP",
        value: 18,
        category: Signal,
        description: Some("Terminal stop (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGWINCH",
        value: 28,
        category: Signal,
        description: Some("Window resize (macOS)"),
    });
    db.add(NamedConstant {
        name: "SIGINFO",
        value: 29,
        category: Signal,
        description: Some("Information request (macOS/BSD)"),
    });

    // macOS AT_FDCWD is -2, not -100 like Linux
    db.add(NamedConstant {
        name: "AT_FDCWD",
        value: -2,
        category: AtFlags,
        description: Some("Use current working directory (macOS)"),
    });
}

/// Map function names to argument categories for context-aware constant lookup.
pub fn get_argument_category(func_name: &str, arg_index: usize) -> Option<ConstantCategory> {
    match func_name {
        "ioctl" | "_ioctl" if arg_index == 1 => Some(ConstantCategory::Ioctl),
        "signal" | "_signal" if arg_index == 0 => Some(ConstantCategory::Signal),
        "signal" | "_signal" if arg_index == 1 => Some(ConstantCategory::SignalHandler),
        "kill" | "_kill" if arg_index == 1 => Some(ConstantCategory::Signal),
        "raise" | "_raise" if arg_index == 0 => Some(ConstantCategory::Signal),
        "sigaction" | "_sigaction" if arg_index == 0 => Some(ConstantCategory::Signal),
        "open" | "_open" if arg_index == 1 => Some(ConstantCategory::OpenFlags),
        "open" | "_open" if arg_index == 2 => Some(ConstantCategory::FileMode),
        "openat" | "_openat" if arg_index == 2 => Some(ConstantCategory::OpenFlags),
        "openat" | "_openat" if arg_index == 3 => Some(ConstantCategory::FileMode),
        "creat" | "_creat" if arg_index == 1 => Some(ConstantCategory::FileMode),
        "mkdir" | "_mkdir" | "mkdirat" | "_mkdirat" if arg_index == 1 => {
            Some(ConstantCategory::FileMode)
        }
        "chmod" | "_chmod" | "fchmod" | "_fchmod" if arg_index == 1 => {
            Some(ConstantCategory::FileMode)
        }
        "mmap" | "_mmap" if arg_index == 2 => Some(ConstantCategory::MmapProt),
        "mmap" | "_mmap" if arg_index == 3 => Some(ConstantCategory::MmapFlags),
        "mprotect" | "_mprotect" if arg_index == 2 => Some(ConstantCategory::MmapProt),
        "socket" | "_socket" if arg_index == 0 => Some(ConstantCategory::AddressFamily),
        "socket" | "_socket" if arg_index == 1 => Some(ConstantCategory::SocketType),
        "fcntl" | "_fcntl" if arg_index == 1 => Some(ConstantCategory::Fcntl),
        "lseek" | "_lseek" | "fseek" | "_fseek" if arg_index == 2 => Some(ConstantCategory::Seek),
        "poll" | "_poll" | "ppoll" | "_ppoll" => None, // events are in struct
        "read" | "_read" | "write" | "_write" if arg_index == 0 => Some(ConstantCategory::General),
        "epoll_ctl" | "_epoll_ctl" if arg_index == 1 => Some(ConstantCategory::EpollCtl),
        // *at() syscalls - first arg is directory fd (AT_FDCWD)
        "openat" | "_openat" | "fstatat" | "_fstatat" | "fstatat64" | "_fstatat64" | "fchmodat"
        | "_fchmodat" | "fchownat" | "_fchownat" | "linkat" | "_linkat" | "unlinkat"
        | "_unlinkat" | "renameat" | "_renameat" | "symlinkat" | "_symlinkat" | "readlinkat"
        | "_readlinkat" | "faccessat" | "_faccessat" | "mkdirat" | "_mkdirat" | "mknodat"
        | "_mknodat" | "futimesat" | "_futimesat" | "utimensat" | "_utimensat"
            if arg_index == 0 =>
        {
            Some(ConstantCategory::AtFlags)
        }
        // Some *at() functions have flags as last argument
        "fchmodat" | "_fchmodat" | "fchownat" | "_fchownat" | "faccessat" | "_faccessat"
        | "linkat" | "_linkat" | "unlinkat" | "_unlinkat"
            if arg_index == 3 =>
        {
            Some(ConstantCategory::AtFlags)
        }
        // Socket options
        "setsockopt" | "_setsockopt" | "getsockopt" | "_getsockopt" if arg_index == 1 => {
            Some(ConstantCategory::SockOptLevel)
        }
        "setsockopt" | "_setsockopt" | "getsockopt" | "_getsockopt" if arg_index == 2 => {
            Some(ConstantCategory::SockOpt)
        }
        // Wait functions
        "waitpid" | "_waitpid" | "wait4" | "_wait4" | "waitid" | "_waitid" if arg_index == 2 => {
            Some(ConstantCategory::WaitOptions)
        }
        // ptrace
        "ptrace" | "_ptrace" if arg_index == 0 => Some(ConstantCategory::PtraceRequest),
        // prctl
        "prctl" | "_prctl" if arg_index == 0 => Some(ConstantCategory::PrctlOption),
        // seccomp
        "seccomp" | "_seccomp" if arg_index == 0 => Some(ConstantCategory::Seccomp),
        // clone
        "clone" | "_clone" | "clone3" | "_clone3" if arg_index == 0 => {
            Some(ConstantCategory::CloneFlags)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_lookup() {
        let db = ConstantDatabase::with_builtins();

        // Test ioctl lookup
        assert_eq!(
            db.lookup(0x40087468, Some(ConstantCategory::Ioctl)),
            Some("TIOCGWINSZ")
        );

        // Test signal lookup
        assert_eq!(db.lookup(2, Some(ConstantCategory::Signal)), Some("SIGINT"));

        // Test general lookup
        assert_eq!(
            db.lookup(1, Some(ConstantCategory::General)),
            Some("STDOUT_FILENO")
        );
    }

    #[test]
    fn test_flags_formatting() {
        let db = ConstantDatabase::with_builtins();

        // Test mmap prot flags
        let flags = db.format_flags(0x3, ConstantCategory::MmapProt);
        assert!(flags.contains("PROT_READ"));
        assert!(flags.contains("PROT_WRITE"));
    }

    #[test]
    fn test_argument_category() {
        assert_eq!(
            get_argument_category("ioctl", 1),
            Some(ConstantCategory::Ioctl)
        );
        assert_eq!(
            get_argument_category("signal", 0),
            Some(ConstantCategory::Signal)
        );
        assert_eq!(
            get_argument_category("mmap", 2),
            Some(ConstantCategory::MmapProt)
        );
    }
}
