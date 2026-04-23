//! Decoder-level tests for the SASS skeleton.
//!
//! These are the M3 "does the plumbing work" tests: decode NOP goldens,
//! stride-by-16 block walking even on failure, panic-free on fuzzed
//! input, and determinism.

use super::*;
use crate::{DecodeError, Disassembler};

/// The canonical 7x/8x NOP bytes from CuAssembler (`CuSMVersion.py`). All
/// sm_75 / sm_80 / sm_86 / sm_89 cubins emit this exact encoding for a
/// zero-operand, zero-guard `NOP`.
const NOP_BYTES: [u8; 16] = [
    0x18, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0F, 0x00,
];

#[test]
fn canonical_nop_decodes() {
    let d = SassDisassembler::ampere();
    let decoded = d.decode_instruction(&NOP_BYTES, 0x1000).unwrap();
    assert_eq!(decoded.size, 16);
    assert_eq!(decoded.instruction.mnemonic, "NOP");
    assert_eq!(decoded.instruction.operation, Operation::Nop);
    assert_eq!(decoded.instruction.address, 0x1000);
    assert_eq!(decoded.instruction.size, 16);
    assert_eq!(decoded.instruction.bytes, &NOP_BYTES);
    assert!(decoded.instruction.guard.is_none());
    assert_eq!(decoded.instruction.control_flow, ControlFlow::Sequential);
}

#[test]
fn nop_control_bits_round_trip() {
    // The canonical NOP's high word encodes the scheduling control slot
    // we care about. M3 only proves the extraction round-trips; M6 will
    // tighten this to assert specific nvdisasm-rendered field values
    // once we can cross-check against real cubins.
    let word = SassWord::from_bytes(&NOP_BYTES);
    let cb = ControlBits::from_word(&word);
    assert_eq!(cb.to_raw(), 0x7E0);
}

#[test]
fn sm_dispatch_uses_correct_architecture() {
    let d = SassDisassembler::ampere();
    match d.architecture() {
        Architecture::Cuda(CudaArchitecture::Sass(sm)) => {
            assert_eq!(sm.major, 8);
            assert_eq!(sm.minor, 0);
        }
        other => panic!("wrong arch: {other:?}"),
    }
}

#[test]
fn decode_instruction_rejects_truncated_input() {
    let d = SassDisassembler::ampere();
    let err = d.decode_instruction(&NOP_BYTES[..8], 0x2000).unwrap_err();
    match err {
        DecodeError::Truncated {
            address,
            needed,
            available,
        } => {
            assert_eq!(address, 0x2000);
            assert_eq!(needed, 16);
            assert_eq!(available, 8);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn unknown_opcode_produces_error_but_does_not_desync() {
    // Build a block of 3 instructions: [NOP, garbage, NOP]. The garbage
    // slot must decode as Err (unknown) and the block walker must step
    // past it by exactly 16 bytes so the trailing NOP still decodes at
    // the expected address.
    let mut block = Vec::with_capacity(48);
    block.extend_from_slice(&NOP_BYTES);
    block.extend_from_slice(&[0xFF; 16]); // nothing plausible here
    block.extend_from_slice(&NOP_BYTES);

    let d = SassDisassembler::ampere();
    let results = d.disassemble_block(&block, 0x0);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());

    let first = results[0].as_ref().unwrap();
    let third = results[2].as_ref().unwrap();
    assert_eq!(first.address, 0);
    assert_eq!(third.address, 32); // proves we advanced 2*16 not a byte
}

#[test]
fn disassemble_block_handles_trailing_partial_word() {
    // A block that's 16 + 5 bytes long. The tail slot is too short; we
    // must surface a Truncated error for it, not silently eat the bytes.
    let mut block = Vec::with_capacity(21);
    block.extend_from_slice(&NOP_BYTES);
    block.extend_from_slice(&[0, 1, 2, 3, 4]);

    let d = SassDisassembler::ampere();
    let results = d.disassemble_block(&block, 0x1000);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(matches!(
        results[1],
        Err(DecodeError::Truncated {
            needed: 16,
            available: 5,
            ..
        })
    ));
}

#[test]
fn decoding_is_deterministic() {
    // Decoding the same bytes twice must yield byte-identical output.
    // Easy property but worth pinning because M7+ threads control bits
    // through a typed struct and we want to catch accidental hash-set
    // iteration later.
    let d = SassDisassembler::ampere();
    let a = d.decode_instruction(&NOP_BYTES, 0x1000).unwrap();
    let b = d.decode_instruction(&NOP_BYTES, 0x1000).unwrap();
    assert_eq!(a.instruction.mnemonic, b.instruction.mnemonic);
    assert_eq!(a.instruction.operation, b.instruction.operation);
    assert_eq!(a.instruction.bytes, b.instruction.bytes);
    assert_eq!(a.instruction.control_flow, b.instruction.control_flow);
}

#[test]
fn block_decoder_is_panic_free_on_arbitrary_bytes() {
    // Smoke fuzz: march a rotating pattern through the block walker.
    // This wouldn't catch a real bug, but a proptest-driven version in
    // M6 will; today we just want to make sure nothing panics.
    let d = SassDisassembler::ampere();
    let mut buf = Vec::with_capacity(16 * 64);
    for i in 0..(16 * 64) {
        buf.push((i & 0xFF) as u8);
    }
    let results = d.disassemble_block(&buf, 0x0);
    assert_eq!(results.len(), 64);
    // Not all of them decode; some will be Err. What matters is that we
    // got exactly 64 slots (no desync) and no panic.
    for (i, result) in results.iter().enumerate() {
        let expected_addr = (i * 16) as u64;
        if let Ok(instr) = result {
            assert_eq!(instr.address, expected_addr);
            assert_eq!(instr.size, 16);
        }
    }
}

#[test]
fn pre_volta_target_is_rejected() {
    // sm_50 Maxwell uses a different 64-bit encoding we don't support.
    let maxwell = SassDisassembler::for_sm(hexray_core::SmArchitecture::new(
        5,
        0,
        hexray_core::SmVariant::Base,
    ));
    assert!(!maxwell.is_volta_or_newer());
    let err = maxwell.decode_instruction(&NOP_BYTES, 0x0).unwrap_err();
    assert!(matches!(err, DecodeError::Unsupported { .. }));
}

#[test]
fn architecture_reflects_configured_sm() {
    let ada = SassDisassembler::ada();
    match ada.architecture() {
        Architecture::Cuda(CudaArchitecture::Sass(sm)) => {
            assert_eq!(sm.canonical_name(), "sm_89");
        }
        other => panic!("wrong arch: {other:?}"),
    }

    let hopper = SassDisassembler::hopper();
    match hopper.architecture() {
        Architecture::Cuda(CudaArchitecture::Sass(sm)) => {
            assert_eq!(sm.canonical_name(), "sm_90");
        }
        other => panic!("wrong arch: {other:?}"),
    }
}

#[test]
fn is_fixed_width_and_size_invariants() {
    let d = SassDisassembler::ampere();
    assert!(d.is_fixed_width());
    assert_eq!(d.min_instruction_size(), 16);
    assert_eq!(d.max_instruction_size(), 16);
}
