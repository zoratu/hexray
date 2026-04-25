//! Property tests for the AMDGPU decoder.
//!
//! These run only when the `amdgpu` feature is enabled. The
//! properties exercise the variable-length walker against random
//! byte streams and target families, asserting:
//!
//! 1. The walker never panics on arbitrary input.
//! 2. The walker never desyncs — every advance is exactly 4 or 8
//!    bytes (or it's the trailing-fragment truncation error).
//! 3. Sum of advance sizes equals input length (modulo trailing
//!    fragment).
//! 4. The encoding-class dispatch is deterministic — same dword
//!    + same family always returns the same class.

#![cfg(feature = "amdgpu")]

use hexray_disasm::amdgpu::{decode_class, AmdgpuDisassembler, EncodingClass, EncodingFamily};
use hexray_disasm::Disassembler;
use proptest::prelude::*;

fn arb_family() -> impl Strategy<Value = EncodingFamily> {
    prop_oneof![Just(EncodingFamily::Gfx9), Just(EncodingFamily::Gfx10Plus),]
}

proptest! {
    /// The encoding-class classifier is a pure function: any dword +
    /// family always produces the same class. This catches state
    /// leakage if anyone accidentally introduces it.
    #[test]
    fn classification_is_deterministic(dword: u32, family in arb_family()) {
        let a = decode_class(dword, family);
        let b = decode_class(dword, family);
        prop_assert_eq!(a, b);
    }

    /// Every classified `EncodingClass` returns either 4 or 8 for its
    /// `encoding_size`. There's no other valid value.
    #[test]
    fn encoding_size_is_4_or_8(dword: u32, family in arb_family()) {
        let class = decode_class(dword, family);
        let size = class.encoding_size();
        prop_assert!(size == 4 || size == 8, "got {} for {:?}", size, class);
    }

    /// The `disassemble_block` walker never panics on arbitrary input
    /// and produces a result count that matches the bytes it consumed.
    #[test]
    fn block_walker_never_panics_and_consumes_all_input(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
        family in arb_family(),
    ) {
        let target = match family {
            EncodingFamily::Gfx9 => hexray_core::GfxArchitecture::new(9, 0, 6),
            EncodingFamily::Gfx10Plus => hexray_core::GfxArchitecture::new(10, 3, 0),
        };
        let d = AmdgpuDisassembler::for_target(target);
        let result = d.disassemble_block(&bytes, 0x1000);

        // Compute the size we expect each result entry to span. We
        // walk through the output and reconstruct the running offset.
        let mut consumed = 0usize;
        for r in &result {
            match r {
                Ok(instr) => {
                    prop_assert!(instr.size == 4 || instr.size == 8);
                    consumed += instr.size;
                }
                Err(_) => {
                    // The walker advances 4 bytes on a hard decode
                    // failure (or surfaces a trailing-fragment error
                    // for sub-dword input).
                    let remaining = bytes.len() - consumed;
                    if remaining >= 4 {
                        consumed += 4;
                    } else {
                        consumed += remaining;
                    }
                }
            }
        }
        prop_assert_eq!(consumed, bytes.len());
    }

    /// `Unknown` class encodings always advance by 4 bytes. Without
    /// this property a malformed dword could trap the walker.
    #[test]
    fn unknown_class_advances_4_bytes(dword: u32, family in arb_family()) {
        let class = decode_class(dword, family);
        if class == EncodingClass::Unknown {
            prop_assert_eq!(class.encoding_size(), 4);
        }
    }

    /// VOP1 / VOPC bit pattern always implies 32-bit encoding.
    #[test]
    fn vop_class_is_32bit(dword: u32, family in arb_family()) {
        let class = decode_class(dword, family);
        if matches!(
            class,
            EncodingClass::Vop1 | EncodingClass::Vop2 | EncodingClass::Vopc
        ) {
            prop_assert_eq!(class.encoding_size(), 4);
        }
    }

    /// VOP3, SMEM, MUBUF, DS, FLAT classes always imply 64-bit
    /// encoding (decoder must read a second dword).
    #[test]
    fn extended_classes_are_64bit(dword: u32, family in arb_family()) {
        let class = decode_class(dword, family);
        if matches!(
            class,
            EncodingClass::Vop3a
                | EncodingClass::Vop3b
                | EncodingClass::Smem
                | EncodingClass::Mubuf
                | EncodingClass::Mtbuf
                | EncodingClass::Mimg
                | EncodingClass::Ds
                | EncodingClass::Flat
                | EncodingClass::Exp
        ) {
            prop_assert_eq!(class.encoding_size(), 8);
        }
    }
}
