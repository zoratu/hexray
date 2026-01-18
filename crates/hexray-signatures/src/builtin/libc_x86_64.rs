//! x86_64 libc function signatures.
//!
//! These signatures are based on common glibc/musl implementations.
//! Patterns include wildcards for variable parts like stack frame sizes.

use crate::signature::{FunctionSignature, CallingConvention, Parameter, ParameterType};
use crate::SignatureDatabase;

/// Load x86_64 libc signatures into the database.
pub fn load_libc(db: &mut SignatureDatabase) {
    // String functions
    add_string_functions(db);

    // Memory functions
    add_memory_functions(db);

    // I/O functions
    add_io_functions(db);

    // Process functions
    add_process_functions(db);

    // Math functions
    add_math_functions(db);
}

fn add_string_functions(db: &mut SignatureDatabase) {
    // strlen - simple loop-based implementation
    // push rbp; mov rbp, rsp; mov QWORD PTR [rbp-0x8], rdi
    if let Ok(sig) = FunctionSignature::from_hex("strlen", "55 48 89 E5 48 89 7D F8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::string("s"))
            .with_library("libc")
            .with_doc("Calculate the length of a string")
            .with_confidence(0.7));
    }

    // strlen - SSE2 optimized (glibc)
    // Common SSE2 strlen starts with alignment check
    if let Ok(sig) = FunctionSignature::from_hex("__strlen_sse2", "F3 0F 1E FA 89 F8 25 ?? ?? ?? ?? 48") {
        db.add(sig
            .with_alias("strlen")
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::string("s"))
            .with_library("glibc")
            .with_doc("SSE2-optimized strlen")
            .with_confidence(0.85));
    }

    // strcpy
    if let Ok(sig) = FunctionSignature::from_hex("strcpy", "55 48 89 E5 48 89 7D E8 48 89 75 E0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("dest"))
            .with_param(Parameter::string("src"))
            .with_library("libc")
            .with_doc("Copy a string")
            .with_confidence(0.7));
    }

    // strncpy
    if let Ok(sig) = FunctionSignature::from_hex("strncpy", "55 48 89 E5 48 83 EC 30 48 89 7D E8 48 89 75 E0 48 89 55 D8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("dest"))
            .with_param(Parameter::string("src"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Copy a string with length limit")
            .with_confidence(0.75));
    }

    // strcmp
    if let Ok(sig) = FunctionSignature::from_hex("strcmp", "55 48 89 E5 48 89 7D F8 48 89 75 F0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("s1"))
            .with_param(Parameter::string("s2"))
            .with_library("libc")
            .with_doc("Compare two strings")
            .with_confidence(0.7));
    }

    // strncmp
    if let Ok(sig) = FunctionSignature::from_hex("strncmp", "55 48 89 E5 48 83 EC 20 48 89 7D E8 48 89 75 E0 48 89 55 D8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("s1"))
            .with_param(Parameter::string("s2"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Compare two strings with length limit")
            .with_confidence(0.75));
    }

    // strcat
    if let Ok(sig) = FunctionSignature::from_hex("strcat", "55 48 89 E5 48 89 7D F8 48 89 75 F0 48 8B 45 F8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("dest"))
            .with_param(Parameter::string("src"))
            .with_library("libc")
            .with_doc("Concatenate two strings")
            .with_confidence(0.7));
    }

    // strchr
    if let Ok(sig) = FunctionSignature::from_hex("strchr", "55 48 89 E5 48 89 7D F8 89 75 F4") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("s"))
            .with_param(Parameter::int("c"))
            .with_library("libc")
            .with_doc("Locate character in string")
            .with_confidence(0.7));
    }

    // strrchr
    if let Ok(sig) = FunctionSignature::from_hex("strrchr", "55 48 89 E5 48 89 7D E8 89 75 E4 48 C7 45 F8 00") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("s"))
            .with_param(Parameter::int("c"))
            .with_library("libc")
            .with_doc("Locate last occurrence of character in string")
            .with_confidence(0.7));
    }

    // strstr
    if let Ok(sig) = FunctionSignature::from_hex("strstr", "55 48 89 E5 48 83 EC 20 48 89 7D E8 48 89 75 E0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("haystack"))
            .with_param(Parameter::string("needle"))
            .with_library("libc")
            .with_doc("Locate a substring")
            .with_confidence(0.7));
    }
}

fn add_memory_functions(db: &mut SignatureDatabase) {
    // memcpy - simple implementation
    if let Ok(sig) = FunctionSignature::from_hex("memcpy", "55 48 89 E5 48 89 7D E8 48 89 75 E0 48 89 55 D8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("dest"))
            .with_param(Parameter::ptr("src"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Copy memory area")
            .with_confidence(0.7));
    }

    // memcpy - rep movsb variant
    if let Ok(sig) = FunctionSignature::from_hex("__memcpy_erms", "48 89 F8 48 89 D1 F3 A4 C3") {
        db.add(sig
            .with_alias("memcpy")
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("dest"))
            .with_param(Parameter::ptr("src"))
            .with_param(Parameter::size("n"))
            .with_library("glibc")
            .with_doc("ERMS-optimized memcpy")
            .with_confidence(0.9));
    }

    // memmove
    if let Ok(sig) = FunctionSignature::from_hex("memmove", "55 48 89 E5 48 89 7D E8 48 89 75 E0 48 89 55 D8 48 8B 45 E8 48 3B 45 E0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("dest"))
            .with_param(Parameter::ptr("src"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Copy memory area (handles overlapping)")
            .with_confidence(0.75));
    }

    // memset - simple implementation
    if let Ok(sig) = FunctionSignature::from_hex("memset", "55 48 89 E5 48 89 7D D8 89 75 D4 48 89 55 C8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("s"))
            .with_param(Parameter::int("c"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Fill memory with a constant byte")
            .with_confidence(0.7));
    }

    // memset - rep stosb variant
    if let Ok(sig) = FunctionSignature::from_hex("__memset_erms", "48 89 F8 40 88 F0 48 89 D1 F3 AA C3") {
        db.add(sig
            .with_alias("memset")
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("s"))
            .with_param(Parameter::int("c"))
            .with_param(Parameter::size("n"))
            .with_library("glibc")
            .with_doc("ERMS-optimized memset")
            .with_confidence(0.9));
    }

    // memcmp
    if let Ok(sig) = FunctionSignature::from_hex("memcmp", "55 48 89 E5 48 89 7D E8 48 89 75 E0 48 89 55 D8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::ptr("s1"))
            .with_param(Parameter::ptr("s2"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Compare memory areas")
            .with_confidence(0.7));
    }

    // malloc
    if let Ok(sig) = FunctionSignature::from_hex("malloc", "55 48 89 E5 53 48 83 EC 08 48 89 FB") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::size("size"))
            .with_library("libc")
            .with_doc("Allocate dynamic memory")
            .with_confidence(0.6));
    }

    // free
    if let Ok(sig) = FunctionSignature::from_hex("free", "55 48 89 E5 53 48 83 EC 08 48 85 FF 74") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::ptr("ptr"))
            .with_library("libc")
            .with_doc("Free allocated memory")
            .with_confidence(0.6));
    }

    // calloc
    if let Ok(sig) = FunctionSignature::from_hex("calloc", "55 48 89 E5 53 48 83 EC 18 48 89 FB 48 89 F0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::size("nmemb"))
            .with_param(Parameter::size("size"))
            .with_library("libc")
            .with_doc("Allocate and zero-initialize memory")
            .with_confidence(0.6));
    }

    // realloc
    if let Ok(sig) = FunctionSignature::from_hex("realloc", "55 48 89 E5 53 48 83 EC 18 48 89 FB 48 89 F0 48 85 FF") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("ptr"))
            .with_param(Parameter::size("size"))
            .with_library("libc")
            .with_doc("Reallocate memory block")
            .with_confidence(0.6));
    }
}

fn add_io_functions(db: &mut SignatureDatabase) {
    // printf - PLT stub pattern
    if let Ok(sig) = FunctionSignature::from_hex("printf", "FF 25 ?? ?? ?? ?? 68") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("format"))
            .variadic()
            .with_library("libc")
            .with_doc("Formatted output to stdout")
            .with_confidence(0.5));
    }

    // puts
    if let Ok(sig) = FunctionSignature::from_hex("puts", "55 48 89 E5 48 83 EC 10 48 89 7D F8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("s"))
            .with_library("libc")
            .with_doc("Output a string and newline")
            .with_confidence(0.65));
    }

    // fopen
    if let Ok(sig) = FunctionSignature::from_hex("fopen", "55 48 89 E5 48 83 EC 20 48 89 7D E8 48 89 75 E0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::FilePtr)
            .with_param(Parameter::string("pathname"))
            .with_param(Parameter::string("mode"))
            .with_library("libc")
            .with_doc("Open a file")
            .with_confidence(0.7));
    }

    // fclose
    if let Ok(sig) = FunctionSignature::from_hex("fclose", "55 48 89 E5 53 48 83 EC 08 48 89 FB") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::file("stream"))
            .with_library("libc")
            .with_doc("Close a file")
            .with_confidence(0.6));
    }

    // fread
    if let Ok(sig) = FunctionSignature::from_hex("fread", "55 48 89 E5 48 83 EC 30 48 89 7D E8 48 89 75 E0 48 89 55 D8 48 89 4D D0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::ptr("ptr"))
            .with_param(Parameter::size("size"))
            .with_param(Parameter::size("nmemb"))
            .with_param(Parameter::file("stream"))
            .with_library("libc")
            .with_doc("Read from file")
            .with_confidence(0.7));
    }

    // fwrite
    if let Ok(sig) = FunctionSignature::from_hex("fwrite", "55 48 89 E5 48 83 EC 30 48 89 7D E8 48 89 75 E0 48 89 55 D8 48 89 4D D0") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::ptr("ptr"))
            .with_param(Parameter::size("size"))
            .with_param(Parameter::size("nmemb"))
            .with_param(Parameter::file("stream"))
            .with_library("libc")
            .with_doc("Write to file")
            .with_confidence(0.7));
    }

    // read (syscall wrapper)
    if let Ok(sig) = FunctionSignature::from_hex("read", "B8 00 00 00 00 0F 05 48 3D 00 F0 FF FF") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 8, signed: true })
            .with_param(Parameter::int("fd"))
            .with_param(Parameter::ptr("buf"))
            .with_param(Parameter::size("count"))
            .with_library("libc")
            .with_doc("Read from file descriptor")
            .with_confidence(0.8));
    }

    // write (syscall wrapper)
    if let Ok(sig) = FunctionSignature::from_hex("write", "B8 01 00 00 00 0F 05 48 3D 00 F0 FF FF") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 8, signed: true })
            .with_param(Parameter::int("fd"))
            .with_param(Parameter::ptr("buf"))
            .with_param(Parameter::size("count"))
            .with_library("libc")
            .with_doc("Write to file descriptor")
            .with_confidence(0.8));
    }
}

fn add_process_functions(db: &mut SignatureDatabase) {
    // exit
    if let Ok(sig) = FunctionSignature::from_hex("exit", "55 48 89 E5 89 7D FC E8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::int("status"))
            .with_library("libc")
            .with_doc("Terminate the process")
            .with_confidence(0.6));
    }

    // _exit (syscall wrapper)
    if let Ok(sig) = FunctionSignature::from_hex("_exit", "B8 3C 00 00 00 0F 05") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::int("status"))
            .with_library("libc")
            .with_doc("Terminate the process immediately")
            .with_confidence(0.9));
    }

    // abort
    if let Ok(sig) = FunctionSignature::from_hex("abort", "55 48 89 E5 53 48 83 EC 08 48 8B 05") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Void)
            .with_library("libc")
            .with_doc("Abort the process")
            .with_confidence(0.6));
    }

    // getenv
    if let Ok(sig) = FunctionSignature::from_hex("getenv", "55 48 89 E5 48 83 EC 20 48 89 7D E8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("name"))
            .with_library("libc")
            .with_doc("Get environment variable")
            .with_confidence(0.65));
    }

    // setenv
    if let Ok(sig) = FunctionSignature::from_hex("setenv", "55 48 89 E5 48 83 EC 30 48 89 7D E8 48 89 75 E0 89 55 DC") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("name"))
            .with_param(Parameter::string("value"))
            .with_param(Parameter::int("overwrite"))
            .with_library("libc")
            .with_doc("Set environment variable")
            .with_confidence(0.7));
    }
}

fn add_math_functions(db: &mut SignatureDatabase) {
    // abs
    if let Ok(sig) = FunctionSignature::from_hex("abs", "89 F8 C1 F8 1F 31 C7 29 C7 89 F8 C3") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::int("j"))
            .with_library("libc")
            .with_doc("Compute absolute value of integer")
            .with_confidence(0.85));
    }

    // atoi - typical implementation
    if let Ok(sig) = FunctionSignature::from_hex("atoi", "55 48 89 E5 48 83 EC 10 48 89 7D F8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("nptr"))
            .with_library("libc")
            .with_doc("Convert string to integer")
            .with_confidence(0.6));
    }

    // atol
    if let Ok(sig) = FunctionSignature::from_hex("atol", "55 48 89 E5 48 83 EC 20 48 89 7D E8") {
        db.add(sig
            .with_convention(CallingConvention::SystemV)
            .with_return_type(ParameterType::Int { size: 8, signed: true })
            .with_param(Parameter::string("nptr"))
            .with_library("libc")
            .with_doc("Convert string to long integer")
            .with_confidence(0.6));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_libc() {
        let mut db = SignatureDatabase::new();
        load_libc(&mut db);

        // Should have a reasonable number of signatures
        assert!(db.len() > 20);

        // Check specific functions exist
        assert!(db.get("strlen").is_some());
        assert!(db.get("memcpy").is_some());
        assert!(db.get("malloc").is_some());
    }

    #[test]
    fn test_signature_properties() {
        let mut db = SignatureDatabase::new();
        load_libc(&mut db);

        let strlen = db.get("strlen").unwrap();
        assert_eq!(strlen.library, "libc");
        assert!(strlen.doc.is_some());
        assert!(!strlen.parameters.is_empty());
    }
}
