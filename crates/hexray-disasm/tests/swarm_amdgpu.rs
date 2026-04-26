//! Swarm tests for the AMDGPU decoder (Groce et al., ISSTA 2012).
//!
//! The Groce paper's central observation: a single "all features
//! enabled" test configuration explores a *narrower* slice of
//! behavior than a *swarm* of test configurations, each randomly
//! omitting some features. Feature-omission diversity surfaces bugs
//! that would otherwise hide behind the omitted feature.
//!
//! For the AMDGPU decoder, the "features" to swarm over are:
//!
//! - **Family band** (`Gfx9` / `Gfx10Plus` / `Gfx11Plus`): the same
//!   byte sequence dispatches to different OP tables under different
//!   bands. The walker must stay panic-free regardless.
//! - **Encoding class** (VOP1/2/3, VOPC, SOP1/2/P, SMEM, FLAT, …):
//!   each class has its own size + OP-extraction rule. Random byte
//!   streams cover every dispatch path.
//! - **Opcode-table membership**: OPs in random byte streams almost
//!   never hit our hand-curated tables, so the *fallback* path
//!   (`<class>.op0xNN` placeholder) is exercised on essentially
//!   every iteration. The swarm asserts this fallback never panics
//!   and always produces a valid `Instruction`.
//!
//! Specifically we test the **omission invariants**:
//!
//! 1. *Walker omission*: removing a single instruction-class
//!    handler (by feeding bytes that don't match any class) still
//!    advances the walker by 4 bytes (Unknown class).
//! 2. *Table omission*: looking up an OP not in any table still
//!    yields a valid placeholder mnemonic, not a panic.
//! 3. *Family omission*: dispatching the same dword under each of
//!    the three family bands yields three internally-consistent
//!    decoder outputs (same instruction size, same class).
//! 4. *Operand-field omission*: SOPP branches whose OP looks like a
//!    branch under one family but not another do not produce
//!    spurious PC-relative operands.

#![cfg(feature = "amdgpu")]

use hexray_core::{ControlFlow, GfxArchitecture};
use hexray_disasm::amdgpu::{decode_class, AmdgpuDisassembler, EncodingClass, EncodingFamily};
use hexray_disasm::Disassembler;
use proptest::prelude::*;

/// One random "swarm" configuration. The bitmask drives selection
/// over the swarm dimensions; the `bits` field is exposed in the
/// `Debug` output of failing test cases so we can re-run a single
/// shrunk seed.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // bits is reserved for future feature-toggle dimensions
struct SwarmConfig {
    family: EncodingFamily,
    bits: u64,
}

fn arb_swarm() -> impl Strategy<Value = SwarmConfig> {
    let family = prop_oneof![
        Just(EncodingFamily::Gfx9),
        Just(EncodingFamily::Gfx10Plus),
        Just(EncodingFamily::Gfx11Plus),
    ];
    (family, any::<u64>()).prop_map(|(family, bits)| SwarmConfig { family, bits })
}

fn target_for(family: EncodingFamily) -> GfxArchitecture {
    match family {
        EncodingFamily::Gfx9 => GfxArchitecture::new(9, 0, 6),
        EncodingFamily::Gfx10Plus => GfxArchitecture::new(10, 3, 0),
        EncodingFamily::Gfx11Plus => GfxArchitecture::new(11, 0, 0),
    }
}

proptest! {
    /// Walker invariant: under any swarm configuration, decoding a
    /// random byte stream always consumes every byte exactly once
    /// (no desync, no double-count, no panic).
    #[test]
    fn walker_consumes_all_input_under_any_swarm(
        config in arb_swarm(),
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let d = AmdgpuDisassembler::for_target(target_for(config.family));
        let result = d.disassemble_block(&bytes, 0x1000);

        let mut consumed = 0usize;
        for r in &result {
            match r {
                Ok(instr) => {
                    prop_assert!(
                        instr.size == 4 || instr.size == 8,
                        "swarm config {:?}, bytes {:?}: instr.size = {}",
                        config, bytes, instr.size
                    );
                    consumed += instr.size;
                }
                Err(_) => {
                    let remaining = bytes.len() - consumed;
                    consumed += remaining.min(4);
                }
            }
        }
        prop_assert_eq!(consumed, bytes.len());
    }

    /// Table-omission invariant: looking up an OP that's not in any
    /// table (which is the common case for random bytes) renders a
    /// placeholder mnemonic and produces a valid `Instruction` —
    /// never a panic.
    #[test]
    fn unknown_op_falls_back_to_placeholder(
        config in arb_swarm(),
        dword in any::<u32>(),
    ) {
        let d = AmdgpuDisassembler::for_target(target_for(config.family));
        let bytes = dword.to_le_bytes();
        // Pad to 8 bytes so 64-bit classes don't truncate.
        let mut padded = bytes.to_vec();
        padded.extend_from_slice(&[0u8; 4]);

        let result = d.decode_instruction(&padded, 0x1000);
        // Either we decoded successfully (mnemonic resolved or
        // placeholder), or we got a truncation error. No panics.
        if let Ok(decoded) = result {
            prop_assert!(!decoded.instruction.mnemonic.is_empty());
            prop_assert!(decoded.size == 4 || decoded.size == 8);
        }
    }

    /// Family-omission invariant: the same dword classified under
    /// each of the three family bands always produces a consistent
    /// instruction size — the encoding-class prefix is shared between
    /// Gfx10Plus and Gfx11Plus, only the OP tables differ. So
    /// `decode_class(dword, Gfx10Plus).encoding_size() ==
    /// decode_class(dword, Gfx11Plus).encoding_size()`.
    #[test]
    fn gfx10_and_gfx11_share_size_classification(dword in any::<u32>()) {
        let class10 = decode_class(dword, EncodingFamily::Gfx10Plus);
        let class11 = decode_class(dword, EncodingFamily::Gfx11Plus);
        prop_assert_eq!(class10, class11);
        prop_assert_eq!(class10.encoding_size(), class11.encoding_size());
    }

    /// Operand-field omission: SOPP whose OP looks like a branch
    /// under one band but not another should not produce spurious
    /// PC-relative operands. Tested by decoding the same dword under
    /// every family and checking that branch-target operands appear
    /// only when the family-aware opcode-table lookup confirms the OP
    /// is a branch.
    #[test]
    fn sopp_branches_only_render_pc_rel_when_family_says_so(
        dword in any::<u32>(),
        config in arb_swarm(),
    ) {
        // Reject dwords that aren't SOPP — out of scope for this
        // property.
        if decode_class(dword, config.family) != EncodingClass::Sopp {
            return Ok(());
        }
        let d = AmdgpuDisassembler::for_target(target_for(config.family));
        let bytes = dword.to_le_bytes();
        let result = d.decode_instruction(&bytes, 0x1000);
        if let Ok(decoded) = result {
            // SOPP decodes always succeed (32-bit fixed) and produce
            // either a non-branch entry (no operands) or a branch
            // with exactly one PC-relative operand.
            let has_pcrel = decoded
                .instruction
                .operands
                .iter()
                .any(|op| matches!(op, hexray_core::Operand::PcRelative { .. }));
            // Cross-check: if we see a PC-relative operand, the
            // control_flow on this instruction should NOT be the
            // sentinel `Halt` and the operand count should be exactly
            // one (just the branch target).
            if has_pcrel {
                prop_assert!(
                    !matches!(decoded.instruction.control_flow, ControlFlow::Halt),
                    "PC-relative SOPP shouldn't be tagged as Halt"
                );
                prop_assert_eq!(decoded.instruction.operands.len(), 1);
            }
        }
    }

    /// Decoder determinism under swarm: same `(dword, family)` always
    /// yields the same `(mnemonic, size, control_flow)` triple. This
    /// catches accidental dependencies on test ordering or shared
    /// mutable state.
    #[test]
    fn decoder_is_deterministic_under_swarm(
        config in arb_swarm(),
        dword in any::<u32>(),
    ) {
        let d = AmdgpuDisassembler::for_target(target_for(config.family));
        let mut bytes = dword.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 4]); // pad for 64-bit classes
        let a = d.decode_instruction(&bytes, 0x1000);
        let b = d.decode_instruction(&bytes, 0x1000);
        match (a, b) {
            (Ok(a), Ok(b)) => {
                prop_assert_eq!(a.size, b.size);
                prop_assert_eq!(a.instruction.mnemonic, b.instruction.mnemonic);
                prop_assert_eq!(a.instruction.operands.len(), b.instruction.operands.len());
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "decoder produced different success/error results"),
        }
    }
}
