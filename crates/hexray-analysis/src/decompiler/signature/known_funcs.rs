//! Static lookup table for the parameter signatures of common libc /
//! musl functions.
//!
//! Used by [`super::SignatureRecovery`] to substitute readable
//! parameter names + types in place of the recovered-from-registers
//! defaults whenever a recognized callee is identified by name.
//!
//! Names are normalized: the table is keyed without leading
//! underscores, so both `printf` and `_printf` resolve to the same
//! entry.

use super::ParamType;

/// Known function parameter names for well-known library functions.
///
/// Returns a slice of (param_index, param_name, param_type) for functions with known signatures.
pub(super) fn get_known_function_params(
    func_name: &str,
) -> Option<&'static [(&'static str, ParamType)]> {
    // Normalize function name (strip leading underscores)
    let name = func_name.trim_start_matches('_');

    match name {
        // main() function
        "main" => Some(&[
            ("argc", ParamType::SignedInt(32)),
            ("argv", ParamType::Pointer),
        ]),

        // Memory functions
        "malloc" | "valloc" => Some(&[("size", ParamType::UnsignedInt(64))]),
        "calloc" => Some(&[
            ("nmemb", ParamType::UnsignedInt(64)),
            ("size", ParamType::UnsignedInt(64)),
        ]),
        "realloc" | "reallocf" => Some(&[
            ("ptr", ParamType::Pointer),
            ("size", ParamType::UnsignedInt(64)),
        ]),
        "free" => Some(&[("ptr", ParamType::Pointer)]),
        "memcpy" | "memmove" => Some(&[
            ("dst", ParamType::Pointer),
            ("src", ParamType::Pointer),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "memset" => Some(&[
            ("s", ParamType::Pointer),
            ("c", ParamType::SignedInt(32)),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "memcmp" => Some(&[
            ("s1", ParamType::Pointer),
            ("s2", ParamType::Pointer),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "memchr" => Some(&[
            ("s", ParamType::Pointer),
            ("c", ParamType::SignedInt(32)),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "bzero" => Some(&[("s", ParamType::Pointer), ("n", ParamType::UnsignedInt(64))]),

        // String functions
        "strlen" | "wcslen" => Some(&[("s", ParamType::Pointer)]),
        "strcpy" | "wcscpy" => Some(&[("dst", ParamType::Pointer), ("src", ParamType::Pointer)]),
        "strncpy" | "wcsncpy" => Some(&[
            ("dst", ParamType::Pointer),
            ("src", ParamType::Pointer),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "strcat" | "wcscat" => Some(&[("dst", ParamType::Pointer), ("src", ParamType::Pointer)]),
        "strncat" | "wcsncat" => Some(&[
            ("dst", ParamType::Pointer),
            ("src", ParamType::Pointer),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "strcmp" | "wcscmp" => Some(&[("s1", ParamType::Pointer), ("s2", ParamType::Pointer)]),
        "strncmp" | "wcsncmp" => Some(&[
            ("s1", ParamType::Pointer),
            ("s2", ParamType::Pointer),
            ("n", ParamType::UnsignedInt(64)),
        ]),
        "strchr" | "strrchr" | "wcschr" | "wcsrchr" => {
            Some(&[("s", ParamType::Pointer), ("c", ParamType::SignedInt(32))])
        }
        "strstr" | "wcsstr" => Some(&[
            ("haystack", ParamType::Pointer),
            ("needle", ParamType::Pointer),
        ]),
        "strdup" | "strndup" => Some(&[("s", ParamType::Pointer)]),
        "strtok" => Some(&[("str", ParamType::Pointer), ("delim", ParamType::Pointer)]),
        "strtok_r" => Some(&[
            ("str", ParamType::Pointer),
            ("delim", ParamType::Pointer),
            ("saveptr", ParamType::Pointer),
        ]),

        // String conversion
        "atoi" | "atol" | "atoll" => Some(&[("nptr", ParamType::Pointer)]),
        "strtol" | "strtoll" => Some(&[
            ("nptr", ParamType::Pointer),
            ("endptr", ParamType::Pointer),
            ("base", ParamType::SignedInt(32)),
        ]),
        "strtoul" | "strtoull" => Some(&[
            ("nptr", ParamType::Pointer),
            ("endptr", ParamType::Pointer),
            ("base", ParamType::SignedInt(32)),
        ]),
        "strtod" | "strtof" | "strtold" => {
            Some(&[("nptr", ParamType::Pointer), ("endptr", ParamType::Pointer)])
        }

        // File I/O
        "fopen" | "freopen" => Some(&[
            ("filename", ParamType::Pointer),
            ("mode", ParamType::Pointer),
        ]),
        "fclose" | "fflush" => Some(&[("stream", ParamType::Pointer)]),
        "fread" => Some(&[
            ("ptr", ParamType::Pointer),
            ("size", ParamType::UnsignedInt(64)),
            ("nmemb", ParamType::UnsignedInt(64)),
            ("stream", ParamType::Pointer),
        ]),
        "fwrite" => Some(&[
            ("ptr", ParamType::Pointer),
            ("size", ParamType::UnsignedInt(64)),
            ("nmemb", ParamType::UnsignedInt(64)),
            ("stream", ParamType::Pointer),
        ]),
        "fgets" => Some(&[
            ("s", ParamType::Pointer),
            ("size", ParamType::SignedInt(32)),
            ("stream", ParamType::Pointer),
        ]),
        "fputs" => Some(&[("s", ParamType::Pointer), ("stream", ParamType::Pointer)]),
        "fgetc" | "getc" => Some(&[("stream", ParamType::Pointer)]),
        "fputc" | "putc" => Some(&[
            ("c", ParamType::SignedInt(32)),
            ("stream", ParamType::Pointer),
        ]),
        "fseek" => Some(&[
            ("stream", ParamType::Pointer),
            ("offset", ParamType::SignedInt(64)),
            ("whence", ParamType::SignedInt(32)),
        ]),
        "ftell" | "rewind" => Some(&[("stream", ParamType::Pointer)]),
        "fprintf" => Some(&[
            ("stream", ParamType::Pointer),
            ("format", ParamType::Pointer),
        ]),
        "fscanf" => Some(&[
            ("stream", ParamType::Pointer),
            ("format", ParamType::Pointer),
        ]),

        // POSIX I/O
        "open" => Some(&[
            ("pathname", ParamType::Pointer),
            ("flags", ParamType::SignedInt(32)),
            ("mode", ParamType::UnsignedInt(32)),
        ]),
        "close" => Some(&[("fd", ParamType::SignedInt(32))]),
        "read" => Some(&[
            ("fd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("count", ParamType::UnsignedInt(64)),
        ]),
        "write" => Some(&[
            ("fd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("count", ParamType::UnsignedInt(64)),
        ]),
        "lseek" => Some(&[
            ("fd", ParamType::SignedInt(32)),
            ("offset", ParamType::SignedInt(64)),
            ("whence", ParamType::SignedInt(32)),
        ]),
        "dup" => Some(&[("oldfd", ParamType::SignedInt(32))]),
        "dup2" => Some(&[
            ("oldfd", ParamType::SignedInt(32)),
            ("newfd", ParamType::SignedInt(32)),
        ]),
        "pipe" => Some(&[("pipefd", ParamType::Pointer)]),

        // Directory functions
        "opendir" => Some(&[("name", ParamType::Pointer)]),
        "closedir" => Some(&[("dirp", ParamType::Pointer)]),
        "readdir" => Some(&[("dirp", ParamType::Pointer)]),
        "mkdir" => Some(&[
            ("pathname", ParamType::Pointer),
            ("mode", ParamType::UnsignedInt(32)),
        ]),
        "rmdir" | "chdir" => Some(&[("pathname", ParamType::Pointer)]),

        // Process functions
        "fork" | "vfork" | "getpid" | "getppid" => Some(&[]),
        "exit" | "Exit" | "quick_exit" => Some(&[("status", ParamType::SignedInt(32))]),
        "execve" => Some(&[
            ("pathname", ParamType::Pointer),
            ("argv", ParamType::Pointer),
            ("envp", ParamType::Pointer),
        ]),
        "execv" | "execvp" => Some(&[
            ("pathname", ParamType::Pointer),
            ("argv", ParamType::Pointer),
        ]),
        "waitpid" => Some(&[
            ("pid", ParamType::SignedInt(32)),
            ("wstatus", ParamType::Pointer),
            ("options", ParamType::SignedInt(32)),
        ]),
        "kill" => Some(&[
            ("pid", ParamType::SignedInt(32)),
            ("sig", ParamType::SignedInt(32)),
        ]),

        // Socket functions
        "socket" => Some(&[
            ("domain", ParamType::SignedInt(32)),
            ("type_", ParamType::SignedInt(32)),
            ("protocol", ParamType::SignedInt(32)),
        ]),
        "bind" | "connect" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("addr", ParamType::Pointer),
            ("addrlen", ParamType::UnsignedInt(32)),
        ]),
        "listen" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("backlog", ParamType::SignedInt(32)),
        ]),
        "accept" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("addr", ParamType::Pointer),
            ("addrlen", ParamType::Pointer),
        ]),
        "send" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("len", ParamType::UnsignedInt(64)),
            ("flags", ParamType::SignedInt(32)),
        ]),
        "recv" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("len", ParamType::UnsignedInt(64)),
            ("flags", ParamType::SignedInt(32)),
        ]),
        "sendto" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("len", ParamType::UnsignedInt(64)),
            ("flags", ParamType::SignedInt(32)),
            ("dest_addr", ParamType::Pointer),
            ("addrlen", ParamType::UnsignedInt(32)),
        ]),
        "recvfrom" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("buf", ParamType::Pointer),
            ("len", ParamType::UnsignedInt(64)),
            ("flags", ParamType::SignedInt(32)),
            ("src_addr", ParamType::Pointer),
            ("addrlen", ParamType::Pointer),
        ]),
        "setsockopt" | "getsockopt" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("level", ParamType::SignedInt(32)),
            ("optname", ParamType::SignedInt(32)),
            ("optval", ParamType::Pointer),
            ("optlen", ParamType::UnsignedInt(32)),
        ]),
        "shutdown" => Some(&[
            ("sockfd", ParamType::SignedInt(32)),
            ("how", ParamType::SignedInt(32)),
        ]),

        // Memory mapping
        "mmap" => Some(&[
            ("addr", ParamType::Pointer),
            ("length", ParamType::UnsignedInt(64)),
            ("prot", ParamType::SignedInt(32)),
            ("flags", ParamType::SignedInt(32)),
            ("fd", ParamType::SignedInt(32)),
            ("offset", ParamType::SignedInt(64)),
        ]),
        "munmap" => Some(&[
            ("addr", ParamType::Pointer),
            ("length", ParamType::UnsignedInt(64)),
        ]),
        "mprotect" => Some(&[
            ("addr", ParamType::Pointer),
            ("len", ParamType::UnsignedInt(64)),
            ("prot", ParamType::SignedInt(32)),
        ]),

        // printf/scanf family
        "printf" | "puts" => Some(&[("format", ParamType::Pointer)]),
        "sprintf" => Some(&[("str", ParamType::Pointer), ("format", ParamType::Pointer)]),
        "snprintf" => Some(&[
            ("str", ParamType::Pointer),
            ("size", ParamType::UnsignedInt(64)),
            ("format", ParamType::Pointer),
        ]),
        "scanf" => Some(&[("format", ParamType::Pointer)]),
        "sscanf" => Some(&[("str", ParamType::Pointer), ("format", ParamType::Pointer)]),

        // Environment
        "getenv" => Some(&[("name", ParamType::Pointer)]),
        "setenv" => Some(&[
            ("name", ParamType::Pointer),
            ("value", ParamType::Pointer),
            ("overwrite", ParamType::SignedInt(32)),
        ]),
        "unsetenv" => Some(&[("name", ParamType::Pointer)]),

        // Error handling
        "perror" => Some(&[("s", ParamType::Pointer)]),
        "strerror" => Some(&[("errnum", ParamType::SignedInt(32))]),

        // Threading
        "pthread_create" => Some(&[
            ("thread", ParamType::Pointer),
            ("attr", ParamType::Pointer),
            ("start_routine", ParamType::Pointer),
            ("arg", ParamType::Pointer),
        ]),
        "pthread_join" => Some(&[
            ("thread", ParamType::UnsignedInt(64)),
            ("retval", ParamType::Pointer),
        ]),
        "pthread_mutex_lock" | "pthread_mutex_unlock" | "pthread_mutex_trylock" => {
            Some(&[("mutex", ParamType::Pointer)])
        }
        "pthread_mutex_init" => {
            Some(&[("mutex", ParamType::Pointer), ("attr", ParamType::Pointer)])
        }
        "pthread_cond_wait" => Some(&[("cond", ParamType::Pointer), ("mutex", ParamType::Pointer)]),
        "pthread_cond_signal" | "pthread_cond_broadcast" => Some(&[("cond", ParamType::Pointer)]),

        // qsort/bsearch
        "qsort" => Some(&[
            ("base", ParamType::Pointer),
            ("nmemb", ParamType::UnsignedInt(64)),
            ("size", ParamType::UnsignedInt(64)),
            ("compar", ParamType::Pointer),
        ]),
        "bsearch" => Some(&[
            ("key", ParamType::Pointer),
            ("base", ParamType::Pointer),
            ("nmemb", ParamType::UnsignedInt(64)),
            ("size", ParamType::UnsignedInt(64)),
            ("compar", ParamType::Pointer),
        ]),

        // Signal handling
        "signal" => Some(&[
            ("signum", ParamType::SignedInt(32)),
            ("handler", ParamType::Pointer),
        ]),
        "sigaction" => Some(&[
            ("signum", ParamType::SignedInt(32)),
            ("act", ParamType::Pointer),
            ("oldact", ParamType::Pointer),
        ]),

        // Time functions
        "time" => Some(&[("tloc", ParamType::Pointer)]),
        "gettimeofday" => Some(&[("tv", ParamType::Pointer), ("tz", ParamType::Pointer)]),
        "sleep" => Some(&[("seconds", ParamType::UnsignedInt(32))]),
        "usleep" => Some(&[("usec", ParamType::UnsignedInt(32))]),
        "nanosleep" => Some(&[("req", ParamType::Pointer), ("rem", ParamType::Pointer)]),

        // Networking address functions
        "inet_addr" | "inet_aton" => Some(&[("cp", ParamType::Pointer)]),
        "inet_ntoa" => Some(&[("in", ParamType::UnsignedInt(32))]),
        "htons" | "ntohs" => Some(&[("hostshort", ParamType::UnsignedInt(16))]),
        "htonl" | "ntohl" => Some(&[("hostlong", ParamType::UnsignedInt(32))]),
        "getaddrinfo" => Some(&[
            ("node", ParamType::Pointer),
            ("service", ParamType::Pointer),
            ("hints", ParamType::Pointer),
            ("res", ParamType::Pointer),
        ]),
        "freeaddrinfo" => Some(&[("res", ParamType::Pointer)]),

        _ => None,
    }
}
