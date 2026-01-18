//! ARM64 libc function signatures.
//!
//! These signatures are based on common glibc/musl ARM64 implementations.

use crate::signature::{FunctionSignature, CallingConvention, Parameter, ParameterType};
use crate::SignatureDatabase;

/// Load ARM64 libc signatures into the database.
pub fn load_libc(db: &mut SignatureDatabase) {
    // String functions
    add_string_functions(db);

    // Memory functions
    add_memory_functions(db);

    // I/O functions
    add_io_functions(db);
}

fn add_string_functions(db: &mut SignatureDatabase) {
    // strlen - typical AARCH64 prologue
    // stp x29, x30, [sp, #-32]!; mov x29, sp
    if let Ok(sig) = FunctionSignature::from_hex("strlen", "FD 7B BE A9 FD 03 00 91") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::string("s"))
            .with_library("libc")
            .with_doc("Calculate the length of a string")
            .with_confidence(0.7));
    }

    // strlen - NEON optimized variant
    // May start with ld1 instruction for vectorized search
    if let Ok(sig) = FunctionSignature::from_hex("__strlen_asimd", "00 70 40 0D ?? ?? ?? ?? 00 ?? 00 4E") {
        db.add(sig
            .with_alias("strlen")
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Size)
            .with_param(Parameter::string("s"))
            .with_library("glibc")
            .with_doc("ASIMD-optimized strlen")
            .with_confidence(0.8));
    }

    // strcpy
    if let Ok(sig) = FunctionSignature::from_hex("strcpy", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("dest"))
            .with_param(Parameter::string("src"))
            .with_library("libc")
            .with_doc("Copy a string")
            .with_confidence(0.65));
    }

    // strcmp
    if let Ok(sig) = FunctionSignature::from_hex("strcmp", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9 E1 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("s1"))
            .with_param(Parameter::string("s2"))
            .with_library("libc")
            .with_doc("Compare two strings")
            .with_confidence(0.65));
    }

    // strchr - simple loop
    if let Ok(sig) = FunctionSignature::from_hex("strchr", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9 E1 0F 00 39") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::String)
            .with_param(Parameter::string("s"))
            .with_param(Parameter::int("c"))
            .with_library("libc")
            .with_doc("Locate character in string")
            .with_confidence(0.65));
    }
}

fn add_memory_functions(db: &mut SignatureDatabase) {
    // memcpy - typical prologue
    if let Ok(sig) = FunctionSignature::from_hex("memcpy", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9 E1 ?? 00 F9 E2 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("dest"))
            .with_param(Parameter::ptr("src"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Copy memory area")
            .with_confidence(0.65));
    }

    // memset - typical prologue
    if let Ok(sig) = FunctionSignature::from_hex("memset", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9 E1 0F 00 39 E2 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::ptr("s"))
            .with_param(Parameter::int("c"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Fill memory with a constant byte")
            .with_confidence(0.65));
    }

    // memcmp
    if let Ok(sig) = FunctionSignature::from_hex("memcmp", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9 E1 ?? 00 F9 E2 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::ptr("s1"))
            .with_param(Parameter::ptr("s2"))
            .with_param(Parameter::size("n"))
            .with_library("libc")
            .with_doc("Compare memory areas")
            .with_confidence(0.65));
    }

    // malloc
    if let Ok(sig) = FunctionSignature::from_hex("malloc", "FD 7B BD A9 FD 03 00 91 F3 0B 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::OpaquePtr)
            .with_param(Parameter::size("size"))
            .with_library("libc")
            .with_doc("Allocate dynamic memory")
            .with_confidence(0.55));
    }

    // free
    if let Ok(sig) = FunctionSignature::from_hex("free", "FD 7B BD A9 FD 03 00 91 F3 0B 00 F9 F3 03 00 AA ?? 00 00 B4") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::ptr("ptr"))
            .with_library("libc")
            .with_doc("Free allocated memory")
            .with_confidence(0.55));
    }
}

fn add_io_functions(db: &mut SignatureDatabase) {
    // puts
    if let Ok(sig) = FunctionSignature::from_hex("puts", "FD 7B BE A9 FD 03 00 91 E0 ?? 00 F9") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Int { size: 4, signed: true })
            .with_param(Parameter::string("s"))
            .with_library("libc")
            .with_doc("Output a string and newline")
            .with_confidence(0.6));
    }

    // exit (typically calls _exit syscall)
    if let Ok(sig) = FunctionSignature::from_hex("exit", "FD 7B BD A9 FD 03 00 91 F3 0B 00 F9 F3 03 00 2A") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::int("status"))
            .with_library("libc")
            .with_doc("Terminate the process")
            .with_confidence(0.55));
    }

    // _exit syscall wrapper (svc #0 with x8=93)
    if let Ok(sig) = FunctionSignature::from_hex("_exit", "08 0B 80 D2 01 00 00 D4") {
        db.add(sig
            .with_convention(CallingConvention::Aarch64)
            .with_return_type(ParameterType::Void)
            .with_param(Parameter::int("status"))
            .with_library("libc")
            .with_doc("Terminate the process immediately")
            .with_confidence(0.85));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_libc() {
        let mut db = SignatureDatabase::new();
        load_libc(&mut db);

        // Should have signatures
        assert!(db.len() > 10);

        // Check specific functions exist
        assert!(db.get("strlen").is_some());
        assert!(db.get("memcpy").is_some());
    }
}
