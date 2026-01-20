//! Standard C library function prototypes.
//!
//! This module provides function prototypes for common libc functions.

use crate::database::TypeDatabase;
use crate::types::*;

/// Load standard C library function prototypes.
pub fn load_libc_functions(db: &mut TypeDatabase) {
    // String functions
    db.add_function(
        FunctionPrototype::new("strlen", CType::typedef_ref("size_t"))
            .param("s", CType::ptr(CType::char()))
            .doc("Calculate the length of a string"),
    );

    db.add_function(
        FunctionPrototype::new("strcpy", CType::ptr(CType::char()))
            .param("dest", CType::ptr(CType::char()))
            .param("src", CType::ptr(CType::char()))
            .doc("Copy a string"),
    );

    db.add_function(
        FunctionPrototype::new("strncpy", CType::ptr(CType::char()))
            .param("dest", CType::ptr(CType::char()))
            .param("src", CType::ptr(CType::char()))
            .param("n", CType::typedef_ref("size_t"))
            .doc("Copy a string with length limit"),
    );

    db.add_function(
        FunctionPrototype::new("strcat", CType::ptr(CType::char()))
            .param("dest", CType::ptr(CType::char()))
            .param("src", CType::ptr(CType::char()))
            .doc("Concatenate two strings"),
    );

    db.add_function(
        FunctionPrototype::new("strcmp", CType::int())
            .param("s1", CType::ptr(CType::char()))
            .param("s2", CType::ptr(CType::char()))
            .doc("Compare two strings"),
    );

    db.add_function(
        FunctionPrototype::new("strncmp", CType::int())
            .param("s1", CType::ptr(CType::char()))
            .param("s2", CType::ptr(CType::char()))
            .param("n", CType::typedef_ref("size_t"))
            .doc("Compare two strings with length limit"),
    );

    db.add_function(
        FunctionPrototype::new("strchr", CType::ptr(CType::char()))
            .param("s", CType::ptr(CType::char()))
            .param("c", CType::int())
            .doc("Locate character in string"),
    );

    db.add_function(
        FunctionPrototype::new("strrchr", CType::ptr(CType::char()))
            .param("s", CType::ptr(CType::char()))
            .param("c", CType::int())
            .doc("Locate last occurrence of character in string"),
    );

    db.add_function(
        FunctionPrototype::new("strstr", CType::ptr(CType::char()))
            .param("haystack", CType::ptr(CType::char()))
            .param("needle", CType::ptr(CType::char()))
            .doc("Locate a substring"),
    );

    db.add_function(
        FunctionPrototype::new("strdup", CType::ptr(CType::char()))
            .param("s", CType::ptr(CType::char()))
            .doc("Duplicate a string"),
    );

    // Memory functions
    db.add_function(
        FunctionPrototype::new("memcpy", CType::ptr(CType::void()))
            .param("dest", CType::ptr(CType::void()))
            .param("src", CType::ptr(CType::void()))
            .param("n", CType::typedef_ref("size_t"))
            .doc("Copy memory area"),
    );

    db.add_function(
        FunctionPrototype::new("memmove", CType::ptr(CType::void()))
            .param("dest", CType::ptr(CType::void()))
            .param("src", CType::ptr(CType::void()))
            .param("n", CType::typedef_ref("size_t"))
            .doc("Copy memory area (handles overlapping)"),
    );

    db.add_function(
        FunctionPrototype::new("memset", CType::ptr(CType::void()))
            .param("s", CType::ptr(CType::void()))
            .param("c", CType::int())
            .param("n", CType::typedef_ref("size_t"))
            .doc("Fill memory with a constant byte"),
    );

    db.add_function(
        FunctionPrototype::new("memcmp", CType::int())
            .param("s1", CType::ptr(CType::void()))
            .param("s2", CType::ptr(CType::void()))
            .param("n", CType::typedef_ref("size_t"))
            .doc("Compare memory areas"),
    );

    db.add_function(
        FunctionPrototype::new("memchr", CType::ptr(CType::void()))
            .param("s", CType::ptr(CType::void()))
            .param("c", CType::int())
            .param("n", CType::typedef_ref("size_t"))
            .doc("Scan memory for a character"),
    );

    // Memory allocation
    db.add_function(
        FunctionPrototype::new("malloc", CType::ptr(CType::void()))
            .param("size", CType::typedef_ref("size_t"))
            .doc("Allocate memory"),
    );

    db.add_function(
        FunctionPrototype::new("calloc", CType::ptr(CType::void()))
            .param("nmemb", CType::typedef_ref("size_t"))
            .param("size", CType::typedef_ref("size_t"))
            .doc("Allocate and zero-initialize array"),
    );

    db.add_function(
        FunctionPrototype::new("realloc", CType::ptr(CType::void()))
            .param("ptr", CType::ptr(CType::void()))
            .param("size", CType::typedef_ref("size_t"))
            .doc("Reallocate memory"),
    );

    db.add_function(
        FunctionPrototype::new("free", CType::void())
            .param("ptr", CType::ptr(CType::void()))
            .doc("Free allocated memory"),
    );

    // I/O functions
    db.add_function(
        FunctionPrototype::new("printf", CType::int())
            .param("format", CType::ptr(CType::char()))
            .variadic()
            .doc("Formatted output to stdout"),
    );

    db.add_function(
        FunctionPrototype::new("fprintf", CType::int())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .param("format", CType::ptr(CType::char()))
            .variadic()
            .doc("Formatted output to stream"),
    );

    db.add_function(
        FunctionPrototype::new("sprintf", CType::int())
            .param("str", CType::ptr(CType::char()))
            .param("format", CType::ptr(CType::char()))
            .variadic()
            .doc("Formatted output to string"),
    );

    db.add_function(
        FunctionPrototype::new("snprintf", CType::int())
            .param("str", CType::ptr(CType::char()))
            .param("size", CType::typedef_ref("size_t"))
            .param("format", CType::ptr(CType::char()))
            .variadic()
            .doc("Formatted output to string with size limit"),
    );

    db.add_function(
        FunctionPrototype::new("scanf", CType::int())
            .param("format", CType::ptr(CType::char()))
            .variadic()
            .doc("Formatted input from stdin"),
    );

    db.add_function(
        FunctionPrototype::new("puts", CType::int())
            .param("s", CType::ptr(CType::char()))
            .doc("Output a string to stdout"),
    );

    db.add_function(
        FunctionPrototype::new("putchar", CType::int())
            .param("c", CType::int())
            .doc("Output a character to stdout"),
    );

    db.add_function(
        FunctionPrototype::new("getchar", CType::int()).doc("Get a character from stdin"),
    );

    db.add_function(
        FunctionPrototype::new("fgets", CType::ptr(CType::char()))
            .param("s", CType::ptr(CType::char()))
            .param("size", CType::int())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Read a line from stream"),
    );

    db.add_function(
        FunctionPrototype::new("fputs", CType::int())
            .param("s", CType::ptr(CType::char()))
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Write a string to stream"),
    );

    // File operations
    db.add_function(
        FunctionPrototype::new("fopen", CType::ptr(CType::typedef_ref("FILE")))
            .param("pathname", CType::ptr(CType::char()))
            .param("mode", CType::ptr(CType::char()))
            .doc("Open a file"),
    );

    db.add_function(
        FunctionPrototype::new("fclose", CType::int())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Close a file"),
    );

    db.add_function(
        FunctionPrototype::new("fread", CType::typedef_ref("size_t"))
            .param("ptr", CType::ptr(CType::void()))
            .param("size", CType::typedef_ref("size_t"))
            .param("nmemb", CType::typedef_ref("size_t"))
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Read from a file"),
    );

    db.add_function(
        FunctionPrototype::new("fwrite", CType::typedef_ref("size_t"))
            .param("ptr", CType::ptr(CType::void()))
            .param("size", CType::typedef_ref("size_t"))
            .param("nmemb", CType::typedef_ref("size_t"))
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Write to a file"),
    );

    db.add_function(
        FunctionPrototype::new("fseek", CType::int())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .param("offset", CType::long())
            .param("whence", CType::int())
            .doc("Seek in a file"),
    );

    db.add_function(
        FunctionPrototype::new("ftell", CType::long())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Get current file position"),
    );

    db.add_function(
        FunctionPrototype::new("fflush", CType::int())
            .param("stream", CType::ptr(CType::typedef_ref("FILE")))
            .doc("Flush a stream"),
    );

    // POSIX file I/O
    db.add_function(
        FunctionPrototype::new("open", CType::int())
            .param("pathname", CType::ptr(CType::char()))
            .param("flags", CType::int())
            .variadic()
            .doc("Open a file descriptor"),
    );

    db.add_function(
        FunctionPrototype::new("close", CType::int())
            .param("fd", CType::int())
            .doc("Close a file descriptor"),
    );

    db.add_function(
        FunctionPrototype::new("read", CType::typedef_ref("ssize_t"))
            .param("fd", CType::int())
            .param("buf", CType::ptr(CType::void()))
            .param("count", CType::typedef_ref("size_t"))
            .doc("Read from a file descriptor"),
    );

    db.add_function(
        FunctionPrototype::new("write", CType::typedef_ref("ssize_t"))
            .param("fd", CType::int())
            .param("buf", CType::ptr(CType::void()))
            .param("count", CType::typedef_ref("size_t"))
            .doc("Write to a file descriptor"),
    );

    db.add_function(
        FunctionPrototype::new("lseek", CType::typedef_ref("off_t"))
            .param("fd", CType::int())
            .param("offset", CType::typedef_ref("off_t"))
            .param("whence", CType::int())
            .doc("Reposition file offset"),
    );

    // Process functions
    db.add_function(
        FunctionPrototype::new("exit", CType::void())
            .param("status", CType::int())
            .doc("Terminate the process"),
    );

    db.add_function(
        FunctionPrototype::new("_exit", CType::void())
            .param("status", CType::int())
            .doc("Terminate the process immediately"),
    );

    db.add_function(
        FunctionPrototype::new("fork", CType::typedef_ref("pid_t")).doc("Create a child process"),
    );

    db.add_function(
        FunctionPrototype::new("getpid", CType::typedef_ref("pid_t")).doc("Get process ID"),
    );

    db.add_function(
        FunctionPrototype::new("getppid", CType::typedef_ref("pid_t")).doc("Get parent process ID"),
    );

    db.add_function(
        FunctionPrototype::new("getuid", CType::typedef_ref("uid_t")).doc("Get real user ID"),
    );

    db.add_function(
        FunctionPrototype::new("getgid", CType::typedef_ref("gid_t")).doc("Get real group ID"),
    );

    // Error handling
    db.add_function(
        FunctionPrototype::new("perror", CType::void())
            .param("s", CType::ptr(CType::char()))
            .doc("Print error message"),
    );

    db.add_function(
        FunctionPrototype::new("strerror", CType::ptr(CType::char()))
            .param("errnum", CType::int())
            .doc("Return string describing error number"),
    );

    // Utility functions
    db.add_function(
        FunctionPrototype::new("atoi", CType::int())
            .param("nptr", CType::ptr(CType::char()))
            .doc("Convert string to integer"),
    );

    db.add_function(
        FunctionPrototype::new("atol", CType::long())
            .param("nptr", CType::ptr(CType::char()))
            .doc("Convert string to long"),
    );

    db.add_function(
        FunctionPrototype::new("atof", CType::double())
            .param("nptr", CType::ptr(CType::char()))
            .doc("Convert string to double"),
    );

    db.add_function(
        FunctionPrototype::new("strtol", CType::long())
            .param("nptr", CType::ptr(CType::char()))
            .param("endptr", CType::ptr(CType::ptr(CType::char())))
            .param("base", CType::int())
            .doc("Convert string to long integer"),
    );

    db.add_function(
        FunctionPrototype::new("strtoul", CType::ulong())
            .param("nptr", CType::ptr(CType::char()))
            .param("endptr", CType::ptr(CType::ptr(CType::char())))
            .param("base", CType::int())
            .doc("Convert string to unsigned long integer"),
    );

    db.add_function(
        FunctionPrototype::new("abs", CType::int())
            .param("j", CType::int())
            .doc("Absolute value of integer"),
    );

    db.add_function(
        FunctionPrototype::new("rand", CType::int()).doc("Generate pseudo-random number"),
    );

    db.add_function(
        FunctionPrototype::new("srand", CType::void())
            .param("seed", CType::uint())
            .doc("Seed pseudo-random number generator"),
    );

    // Time functions
    db.add_function(
        FunctionPrototype::new("time", CType::typedef_ref("time_t"))
            .param("tloc", CType::ptr(CType::typedef_ref("time_t")))
            .doc("Get time in seconds"),
    );

    db.add_function(
        FunctionPrototype::new(
            "localtime",
            CType::ptr(CType::Named("struct tm".to_string())),
        )
        .param("timep", CType::ptr(CType::typedef_ref("time_t")))
        .doc("Convert time_t to local time"),
    );

    db.add_function(
        FunctionPrototype::new("gmtime", CType::ptr(CType::Named("struct tm".to_string())))
            .param("timep", CType::ptr(CType::typedef_ref("time_t")))
            .doc("Convert time_t to UTC"),
    );

    db.add_function(
        FunctionPrototype::new("strftime", CType::typedef_ref("size_t"))
            .param("s", CType::ptr(CType::char()))
            .param("max", CType::typedef_ref("size_t"))
            .param("format", CType::ptr(CType::char()))
            .param("tm", CType::ptr(CType::Named("struct tm".to_string())))
            .doc("Format time as string"),
    );

    db.add_function(
        FunctionPrototype::new("sleep", CType::uint())
            .param("seconds", CType::uint())
            .doc("Sleep for specified seconds"),
    );

    db.add_function(
        FunctionPrototype::new("usleep", CType::int())
            .param("usec", CType::uint())
            .doc("Sleep for specified microseconds"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libc_functions() {
        let mut db = TypeDatabase::new();
        load_libc_functions(&mut db);

        assert!(db.has_function("printf"));
        assert!(db.has_function("malloc"));
        assert!(db.has_function("strlen"));
        assert!(db.has_function("memcpy"));
    }

    #[test]
    fn test_printf_signature() {
        let mut db = TypeDatabase::new();
        load_libc_functions(&mut db);

        let printf = db.get_function("printf").unwrap();
        assert!(printf.variadic);
        assert_eq!(printf.parameters.len(), 1);
        assert_eq!(printf.parameters[0].0, "format");
    }
}
