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
        "kill" | "_kill" if arg_index == 1 => Some(ConstantCategory::Signal),
        "raise" | "_raise" if arg_index == 0 => Some(ConstantCategory::Signal),
        "sigaction" | "_sigaction" if arg_index == 0 => Some(ConstantCategory::Signal),
        "open" | "_open" | "openat" | "_openat" if arg_index == 1 => {
            Some(ConstantCategory::OpenFlags)
        }
        "open" | "_open" | "openat" | "_openat" if arg_index == 2 => {
            Some(ConstantCategory::OpenFlags)
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
