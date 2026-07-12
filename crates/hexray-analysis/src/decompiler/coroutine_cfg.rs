//! CFG-level recognition of clang C++20 coroutine resume-dispatch.
//!
//! clang lowers a coroutine's `.resume` clone differently from gcc's `.actor`:
//! the resume-index dispatch is a TAIL block reached by a `jmp` from the entry,
//! and it branches (a `test/je/jmp` chain for few states, or a `.rodata` jump
//! table for many) to resume-point blocks scattered through the body. hexray's
//! generic structurer collapses that goto/jump-table flow before the
//! structured-body coroutine recovery ([`super::coroutine`]) can see it, so the
//! dispatch must be recognized at the CFG level (before structuring).
//!
//! This module currently performs RECOGNITION only (slice 1a): it locates the
//! dispatch block and the 1-byte resume-index frame field. The CFG rewrite that
//! turns the tail dispatch into a clean switch region is a following slice.

use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, ControlFlowGraph, Operand, Operation};

/// A stack home holding the frame pointer, keyed by (canonical base register name,
/// displacement) so a reload is matched against the SAME slot the entry spilled to —
/// not merely the same displacement off a different stack base.
type SpillSlot = (String, i64);

/// A recognized clang resume-dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct ClangResumeDispatch {
    /// The dispatch block: reads `frame[index_offset]` and branches to resume
    /// points.
    pub dispatch: BasicBlockId,
    /// Byte offset of the resume-index field within the coroutine frame.
    pub index_offset: i64,
    /// Width of the resume-index read in bytes (clang uses 1).
    pub index_size: u8,
    /// The shape of the dispatch branch.
    pub shape: DispatchShape,
}

/// How the dispatch block selects the resume point.
#[derive(Debug, Clone, PartialEq)]
pub enum DispatchShape {
    /// `test al,al; je r0; jmp r1` style compare chain (few states); the branch
    /// targets are the direct successors.
    CompareChain { targets: Vec<BasicBlockId> },
    /// `.rodata` jump table (`jmp *table[idx]`); targets come from the resolved
    /// `IndirectJump` (may be empty until the table is resolved).
    JumpTable { targets: Vec<BasicBlockId> },
}

/// Recognize a clang coroutine resume-dispatch in `cfg`, if present. Caller must
/// already know this is a coroutine resume clone (`is_coroutine_resume_clone`).
///
/// Recognizes the pattern: the entry stores the frame pointer (arg0) to a stack
/// slot and `jmp`s to a dispatch block that reloads it, reads a small (1-2 byte)
/// field near the frame base as the resume index, and branches on it.
pub fn detect_clang_resume_dispatch(cfg: &ControlFlowGraph) -> Option<ClangResumeDispatch> {
    // The frame pointer (first parameter) is spilled to a stack slot in the entry
    // block: `mov [rbp - K], <arg0 reg>`. Record every such slot so a later reload
    // `mov reg, [rbp - K]` can be recognized as re-materializing the frame pointer.
    let entry = cfg.entry_block()?;
    let frame_slots = frame_pointer_spill_slots(entry);
    if frame_slots.is_empty() {
        return None;
    }

    // The dispatch is the block the entry jumps to (clang emits it at the tail).
    let dispatch_id = match &entry.terminator {
        BlockTerminator::Jump { target } => *target,
        _ => return None,
    };
    let dispatch = cfg.block(dispatch_id)?;

    // The dispatch reloads the frame pointer from a spill slot and reads a small
    // resume-index field off it.
    let (index_offset, index_size) = resume_index_read(dispatch, &frame_slots)?;

    let shape = match &dispatch.terminator {
        BlockTerminator::ConditionalBranch {
            true_target,
            false_target,
            ..
        } => DispatchShape::CompareChain {
            targets: vec![*true_target, *false_target],
        },
        BlockTerminator::IndirectJump {
            possible_targets, ..
        } => DispatchShape::JumpTable {
            targets: possible_targets.clone(),
        },
        _ => return None,
    };

    Some(ClangResumeDispatch {
        dispatch: dispatch_id,
        index_offset,
        index_size,
        shape,
    })
}

/// Stack displacements `K` such that `mov [rbp - K], arg0reg` appears in the entry
/// block — i.e. slots that hold a spilled copy of the frame pointer (arg0). On
/// x86-64 SysV the first integer argument is `rdi`.
fn frame_pointer_spill_slots(entry: &BasicBlock) -> Vec<SpillSlot> {
    let mut slots: Vec<SpillSlot> = Vec::new();
    // First-arg candidate registers (canonical) that have been WRITTEN and so no
    // longer hold the original frame pointer. Tracked per register because the
    // candidate set mixes ABIs (SysV `rdi`, Win64 `rcx`): writing the scratch `rcx`
    // in a SysV clone must not invalidate a still-intact `rdi` spill.
    let mut modified_args: Vec<String> = Vec::new();
    for inst in &entry.instructions {
        // A store to a stack home, taken by its memory DESTINATION regardless of the
        // source (which may be a register, immediate, or zero register). The forms:
        //   x86-64: `mov [rbp - K], <src>`  -> Move, operands [Memory(dst), src]
        //   aarch64: `str <src>, [x29 - K]` -> Store, operands [src, Memory(dst)]
        let store = match (inst.operation, inst.operands.as_slice()) {
            (Operation::Move, [Operand::Memory(dst), src]) => Some((dst, src)),
            (Operation::Store, [src, Operand::Memory(dst)]) => Some((dst, src)),
            _ => None,
        };
        if let Some((dst, src)) = store {
            if let Some(base) = &dst.base {
                if is_frame_base_register(base.name()) && dst.index.is_none() {
                    let key = (canon_reg(base.name()), dst.displacement);
                    // Any store to the slot OVERWRITES it, so drop it first; re-record
                    // it as the frame pointer only for a store of the still-original
                    // arg register (a non-register or adjusted-arg store leaves it out).
                    slots.retain(|k| k != &key);
                    if let Operand::Register(sr) = src {
                        let sc = canon_reg(sr.name());
                        // Record only a FULL pointer-width store of the still-original
                        // arg register: a narrow store (`mov [rbp-K], edi`, `str w0,[..]`)
                        // saves only the low bits, so the slot doesn't hold the pointer.
                        if is_first_arg_register(&sc)
                            && !modified_args.contains(&sc)
                            && sr.size >= base.size
                            && u16::from(dst.size) * 8 >= base.size
                        {
                            slots.push(key);
                        }
                    }
                }
            }
            continue;
        }
        // A non-store instruction whose destination is a first-arg candidate
        // register modifies it — that register no longer holds the frame pointer.
        // Compare/Test only write flags (they read the arg), so they don't count.
        if !matches!(inst.operation, Operation::Compare | Operation::Test) {
            if let Some(Operand::Register(d)) = inst.operands.first() {
                let dc = canon_reg(d.name());
                if is_first_arg_register(&dc) && !modified_args.contains(&dc) {
                    modified_args.push(dc);
                }
            }
        }
    }
    slots
}

/// If `dispatch` reloads the frame pointer from one of `frame_slots` and reads a
/// small (1-2 byte) field off it, return `(field_offset, field_size)`.
fn resume_index_read(dispatch: &BasicBlock, frame_slots: &[SpillSlot]) -> Option<(i64, u8)> {
    // Canonical (widest) names of registers currently holding a reloaded frame
    // pointer, so a sub-register write (`xor eax,eax`) invalidates the full `rax`.
    let mut frame_regs: Vec<String> = Vec::new();
    // The LAST small frame-field read wins: the resume index is loaded immediately
    // before the dispatch branch, so an earlier read of some other small frame field
    // must not be mistaken for it.
    let mut result: Option<(i64, u8)> = None;
    for inst in &dispatch.instructions {
        if matches!(inst.operation, Operation::Move | Operation::Load) {
            if let (Some(Operand::Register(d)), Some(Operand::Memory(m))) =
                (inst.operands.first(), inst.operands.get(1))
            {
                let dcanon = canon_reg(d.name());
                if let Some(b) = &m.base {
                    // `mov reg, [rbp - K]` (frame spill slot) -> reg holds the frame ptr,
                    // but only for a FULL pointer-width reload: a narrow reload
                    // (`mov eax,[rbp-K]`) or an extending one (`ldrsw x8,[sp,K]`, 64-bit
                    // dest but 4-byte read) keeps only the low bits, so it truncates the
                    // register instead of re-materializing the pointer. Require both the
                    // destination register AND the memory access to be pointer-width.
                    if is_frame_base_register(b.name())
                        && m.index.is_none()
                        && frame_slots.contains(&(canon_reg(b.name()), m.displacement))
                    {
                        frame_regs.retain(|r| r != &dcanon);
                        if d.size >= b.size && u16::from(m.size) * 8 >= b.size {
                            frame_regs.push(dcanon);
                        }
                        continue;
                    }
                    // `mov(zx) al/eax, [frameReg + off]` (small field) -> a resume-index
                    // candidate. Record it (last wins) and fall through so the read's
                    // destination register is invalidated below.
                    if m.index.is_none()
                        && frame_regs.contains(&canon_reg(b.name()))
                        && (1..=2).contains(&m.size)
                        && (0..=0x400).contains(&m.displacement)
                    {
                        result = Some((m.displacement, m.size));
                    }
                }
                // A `Move`/`Load` into `d` that is neither the frame reload nor a
                // recognized index read OVERWRITES `d`, so it no longer holds the frame.
                frame_regs.retain(|r| r != &dcanon);
                continue;
            }
        }
        // Any other instruction whose destination (first operand) is a register
        // overwrites it — invalidate that alias. `inst.writes` is not populated for
        // x86-64, so read the destination operand directly. Comparisons write only
        // flags; over-invalidating elsewhere is harmless (it just declines).
        if !matches!(inst.operation, Operation::Compare | Operation::Test) {
            if let Some(Operand::Register(d)) = inst.operands.first() {
                let dcanon = canon_reg(d.name());
                frame_regs.retain(|r| r != &dcanon);
            }
        }
    }
    result
}

/// Canonical widest register name (`eax`/`al` -> `rax`, `w0` -> `x0`), so
/// sub-register writes are matched against a tracked full-width alias.
fn canon_reg(name: &str) -> String {
    if let Some((canon, _)) = super::abi::normalize_x86_64_register(name, 8) {
        return canon.to_string();
    }
    if let Some(num) = name.strip_prefix('w') {
        if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
            return format!("x{num}");
        }
    }
    name.to_string()
}

/// A stack-home base register: the frame pointer (`rbp`/`x29`/`fp`) or the stack
/// pointer (`rsp`/`sp`). clang -O0 homes the coroutine frame pointer relative to
/// either — aarch64 in particular often spills/reloads it via `[sp, #K]`. A false
/// match is unlikely because the caller pairs a specific slot displacement across
/// the arg0 spill, the reload, and the small resume-index read.
fn is_frame_base_register(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "rbp" | "ebp" | "x29" | "fp" | "rsp" | "esp" | "sp"
    )
}

/// The first integer-argument register (the coroutine frame pointer).
fn is_first_arg_register(name: &str) -> bool {
    // x86-64 SysV: rdi; Win64: rcx; aarch64 AAPCS: x0.
    matches!(
        name.to_lowercase().as_str(),
        "rdi" | "edi" | "rcx" | "ecx" | "x0" | "w0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, Condition, Instruction, MemoryRef, Register, RegisterClass,
    };

    fn r(id: u16, bits: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, bits)
    }

    fn mov(dst: Operand, src: Operand) -> Instruction {
        Instruction::new(0, 1, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![dst, src])
    }

    #[test]
    fn detects_shape_a_compare_chain_dispatch() {
        // entry: mov [rbp-0x70], rdi ; jmp dispatch
        // dispatch: mov rax, [rbp-0x70] ; mov al, [rax+0x11] ; test al,al ; je r0 else r1
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let (rbp, rdi, rax, al) = (r(5, 64), r(7, 64), r(0, 64), r(0, 8));
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: r0,
            false_target: r1,
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));

        let d = detect_clang_resume_dispatch(&cfg).expect("dispatch detected");
        assert_eq!(d.dispatch, dispatch_id);
        assert_eq!(d.index_offset, 0x11);
        assert_eq!(d.index_size, 1);
        assert_eq!(
            d.shape,
            DispatchShape::CompareChain {
                targets: vec![r0, r1]
            }
        );
    }

    #[test]
    fn stale_frame_register_after_reload_is_not_mistaken_for_index() {
        // entry: mov [rbp-0x70], rdi ; jmp dispatch
        // dispatch: mov rax, [rbp-0x70]   (rax = frame)
        //           mov rax, [rax+8]      (rax reloaded from a NON-frame pointer)
        //           movzx ecx, [rax+0x11] (byte off the NEW rax -> NOT the frame field)
        // Must NOT be detected: the byte read is off a clobbered register.
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let (rbp, rdi, rax, ecx) = (r(5, 64), r(7, 64), r(0, 64), r(1, 32));
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rax, 8, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(ecx),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));

        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn detects_arm64_store_form_spill_dispatch() {
        // aarch64 clang:
        // entry:    stur x0, [x29-0x38] ; b dispatch
        // dispatch: ldur x8, [x29-0x38] ; ldrb w8, [x8+0x11] ; subs ; b.eq r0 else r1
        let a = Architecture::Arm64;
        let gp = |id: u16, bits: u16| Register::new(a, RegisterClass::General, id, bits);
        let (x29, x0, x8, w8) = (gp(29, 64), gp(0, 64), gp(8, 64), gp(8, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x470);
        entry.instructions.push(
            Instruction::new(0, 4, vec![], "stur")
                .with_operation(Operation::Store)
                .with_operands(vec![
                    Operand::Register(x0),
                    Operand::Memory(MemoryRef::base_disp(x29, -0x38, 8)),
                ]),
        );
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x7b8);
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldur")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(x8),
                    Operand::Memory(MemoryRef::base_disp(x29, -0x38, 8)),
                ]),
        );
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldrb")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x8, 0x11, 1)),
                ]),
        );
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: r0,
            false_target: r1,
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(r0, 0x47c));
        cfg.add_block(BasicBlock::new(r1, 0x7d4));

        let d = detect_clang_resume_dispatch(&cfg).expect("arm64 dispatch detected");
        assert_eq!(d.index_offset, 0x11);
        assert_eq!(d.index_size, 1);
    }

    #[test]
    fn detects_arm64_sp_relative_home() {
        // aarch64 clang -O0 can home the frame pointer relative to sp:
        // entry:    str x0, [sp, #0x28] ; b dispatch
        // dispatch: ldr x8, [sp, #0x28] ; ldrb w8, [x8+0x11] ; b.eq r0 else r1
        let a = Architecture::Arm64;
        let gp = |id: u16, bits: u16| Register::new(a, RegisterClass::General, id, bits);
        let (sp, x0, x8, w8) = (gp(31, 64), gp(0, 64), gp(8, 64), gp(8, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x470);
        entry.instructions.push(
            Instruction::new(0, 4, vec![], "str")
                .with_operation(Operation::Store)
                .with_operands(vec![
                    Operand::Register(x0),
                    Operand::Memory(MemoryRef::base_disp(sp, 0x28, 8)),
                ]),
        );
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x7b8);
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldr")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(x8),
                    Operand::Memory(MemoryRef::base_disp(sp, 0x28, 8)),
                ]),
        );
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldrb")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x8, 0x11, 1)),
                ]),
        );
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x47c));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x7d4));

        let d = detect_clang_resume_dispatch(&cfg).expect("sp-relative dispatch detected");
        assert_eq!(d.index_offset, 0x11);
    }

    #[test]
    fn subregister_clobber_invalidates_frame_alias() {
        // dispatch: mov rax,[rbp-0x70] ; xor eax,eax ; movzx ecx,[rax+0x11]
        // `xor eax,eax` zeroes rax, so the byte read is off address 0, not the frame.
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let (rbp, rdi, rax, eax, ecx) = (r(5, 64), r(7, 64), r(0, 64), r(0, 32), r(1, 32));
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(
            Instruction::new(0, 1, vec![], "xor")
                .with_operation(Operation::Xor)
                .with_operands(vec![Operand::Register(eax), Operand::Register(eax)]),
        );
        dispatch.instructions.push(mov(
            Operand::Register(ecx),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));

        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn narrow_reload_is_not_a_frame_pointer() {
        // dispatch: mov eax, [rbp-0x70]  (32-bit reload: only low bits, NOT the ptr)
        //           movzx ecx, [rax+0x11]
        let (rbp, rdi, eax, ecx) = (r(5, 64), r(7, 64), r(0, 32), r(1, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(eax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 4)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(ecx),
            Operand::Memory(MemoryRef::base_disp(r(0, 64), 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn compare_of_arg_before_spill_still_detects() {
        // entry: test rdi, rdi ; mov [rbp-0x70], rdi ; jmp dispatch
        // The compare only reads rdi (writes flags), so the following spill is valid.
        let (rbp, rdi, rax, al) = (r(5, 64), r(7, 64), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(
            Instruction::new(0, 3, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(rdi), Operand::Register(rdi)]),
        );
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_some());
    }

    #[test]
    fn spill_after_arg_modification_is_not_a_frame_slot() {
        // entry: add rdi, 0x10 ; mov [rbp-0x70], rdi ; jmp dispatch
        // The slot holds frame+0x10, not the frame, so it must not be recorded and
        // detection declines (no genuine frame slot to reload the resume index from).
        let (rbp, rdi, rax, al) = (r(5, 64), r(7, 64), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);

        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(
            Instruction::new(0, 4, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(rdi), Operand::imm(0x10, 8)]),
        );
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);

        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));

        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn reload_from_wrong_base_same_disp_is_not_matched() {
        // entry: mov [rbp-0x70], rdi ; jmp dispatch   (spilled to rbp slot)
        // dispatch: mov rax, [rsp-0x70] ; movzx ecx, [rax+0x11]  (reload from RSP)
        // Same displacement but a different stack base -> not the coroutine frame.
        let (rbp, rsp, rdi, rax, ecx) = (r(5, 64), r(4, 64), r(7, 64), r(0, 64), r(1, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rsp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(ecx),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn overwritten_frame_slot_is_dropped() {
        // entry: mov [rbp-0x70], rdi ; add rdi,0x10 ; mov [rbp-0x70], rdi ; jmp dispatch
        // The slot is re-stored with frame+0x10, so it must not remain a frame slot.
        let (rbp, rdi, rax, al) = (r(5, 64), r(7, 64), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.instructions.push(
            Instruction::new(0, 4, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(rdi), Operand::imm(0x10, 8)]),
        );
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn last_small_frame_read_is_the_resume_index() {
        // dispatch: mov rax,[rbp-0x70] ; movzx edx,[rax+8] ; movzx ecx,[rax+0x11] ; branch
        // An earlier small frame read (offset 8) must NOT be taken; the resume index
        // is the LAST one (offset 0x11) — the one feeding the dispatch.
        let (rbp, rdi, rax, edx, ecx) = (r(5, 64), r(7, 64), r(0, 64), r(2, 32), r(1, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(edx),
            Operand::Memory(MemoryRef::base_disp(rax, 8, 1)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(ecx),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        let d = detect_clang_resume_dispatch(&cfg).expect("detected");
        assert_eq!(d.index_offset, 0x11);
    }

    #[test]
    fn writing_other_abi_arg_does_not_block_sysv_spill() {
        // entry: xor ecx, ecx ; mov [rbp-0x70], rdi ; jmp dispatch
        // Writing the Win64-candidate rcx must not invalidate the still-intact rdi
        // frame-pointer spill in a SysV clone.
        let (rbp, rdi, ecx, rax, al) = (r(5, 64), r(7, 64), r(1, 32), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(
            Instruction::new(0, 2, vec![], "xor")
                .with_operation(Operation::Xor)
                .with_operands(vec![Operand::Register(ecx), Operand::Register(ecx)]),
        );
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_some());
    }

    #[test]
    fn extending_reload_is_not_a_frame_pointer() {
        // aarch64: str x0,[sp,#0x28] ; ... ldrsw x8,[sp,#0x28] (4-byte read into 64-bit
        // x8, sign-extended) ; ldrb w8,[x8+0x11]. The extending reload truncates, so
        // it is not the frame pointer.
        let a = Architecture::Arm64;
        let gp = |id: u16, bits: u16| Register::new(a, RegisterClass::General, id, bits);
        let (sp, x0, x8, w8) = (gp(31, 64), gp(0, 64), gp(8, 64), gp(8, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x470);
        entry.instructions.push(
            Instruction::new(0, 4, vec![], "str")
                .with_operation(Operation::Store)
                .with_operands(vec![
                    Operand::Register(x0),
                    Operand::Memory(MemoryRef::base_disp(sp, 0x28, 8)),
                ]),
        );
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x7b8);
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldrsw")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(x8),
                    Operand::Memory(MemoryRef::base_disp(sp, 0x28, 4)),
                ]),
        );
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldrb")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x8, 0x11, 1)),
                ]),
        );
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x47c));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x7d4));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn narrow_arg_spill_is_not_a_frame_slot() {
        // entry: mov [rbp-0x70], edi  (32-bit store of arg0: only the low bits)
        // A later pointer-width reload must not treat this slot as the frame pointer.
        let (rbp, edi, rax, al) = (r(5, 64), r(7, 32), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 4)),
            Operand::Register(edi),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn detects_win64_rcx_arg_spill() {
        // Win64: the frame pointer arrives in rcx.
        // entry: mov [rbp-0x70], rcx ; jmp dispatch
        let (rbp, rcx, rax, al) = (r(5, 64), r(1, 64), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rcx),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_some());
    }

    #[test]
    fn non_register_store_overwrites_frame_slot() {
        // entry: mov [rbp-0x70], rdi ; mov qword [rbp-0x70], 0 ; jmp dispatch
        // The immediate store overwrites the frame slot, so it must be dropped.
        let (rbp, rdi, rax, al) = (r(5, 64), r(7, 64), r(0, 64), r(0, 8));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::imm(0, 8),
        ));
        entry.terminator = BlockTerminator::Jump {
            target: dispatch_id,
        };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0x82e);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(dispatch);
        cfg.add_block(BasicBlock::new(BasicBlockId::new(2), 0x50e));
        cfg.add_block(BasicBlock::new(BasicBlockId::new(3), 0x608));
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }

    #[test]
    fn declines_when_no_frame_spill() {
        // Entry doesn't spill the frame pointer -> not the clang pattern.
        let entry_id = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.terminator = BlockTerminator::Return;
        cfg.add_block(entry);
        assert!(detect_clang_resume_dispatch(&cfg).is_none());
    }
}
