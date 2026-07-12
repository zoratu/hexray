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

use hexray_core::{
    BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph, Operand, Operation,
};

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

/// Rewrite a clang coroutine resume-clone CFG so the tail resume-index dispatch
/// becomes an explicit `IndirectJump` over the resume states. The generic
/// structurer then recovers a `switch` whose cases are the real resume-point
/// bodies (through its `possible_targets` fallback, structurer/mod.rs) instead of
/// collapsing the scattered tail-dispatch goto flow to `return`.
///
/// Returns a rewritten owned CFG, or `None` if this is not a recognized clang
/// resume dispatch — in which case the caller keeps the original CFG. Only the
/// compare-chain shape is rewritten here: the jump-table shape already reaches
/// switch recovery through its native `IndirectJump` terminator (a following slice
/// handles its `.o` relocation gap), so disturbing it would be counterproductive.
/// A CFG rewritten so its clang resume dispatch is a switch region, plus the
/// resume-index frame offset (needed later to name the switch value
/// `frame->__resume_index`).
pub struct ClangResumeRewrite {
    pub cfg: ControlFlowGraph,
    pub index_offset: i64,
}

pub fn rewrite_clang_resume_dispatch(
    cfg: &ControlFlowGraph,
    relocations: Option<&super::RelocationTable>,
) -> Option<ClangResumeRewrite> {
    let disp = detect_clang_resume_dispatch(cfg)?;
    if !matches!(disp.shape, DispatchShape::CompareChain { .. }) {
        // The jump-table shape already reaches switch recovery through its native
        // IndirectJump terminator; only compare-chains are handled here.
        return None;
    }
    let dispatch_block = cfg.block(disp.dispatch)?;
    // The stack homes holding the frame pointer (arg0), so a reload in the dispatch is
    // recognized and only a read off a frame pointer is taken for the resume index.
    let frame_slots = frame_pointer_spill_slots(cfg.entry_block()?);

    // Only a genuine two-way dispatch is safe to rewrite as two cases. For >2 resume
    // states clang emits a compare CHAIN: the dispatch spills the freshly-read index
    // to a stack slot and its false edge routes to another block that reloads and
    // re-tests it. Rewriting that as a 2-case switch would turn a continuation-compare
    // into a bogus case and drop the later states. A dispatch that spills its index is
    // therefore a chain we don't yet flatten — decline it (a dedicated multi-state
    // slice can walk the chain). A true two-state dispatch tests the index in-register
    // and never spills it.
    if dispatch_spills_index(dispatch_block, disp.index_offset, disp.index_size, &frame_slots) {
        return None;
    }

    // The structurer's switch fallback labels `possible_targets` by POSITION (case 0,
    // case 1, ...), so they must be ordered by resume-index VALUE, not branch position.
    // clang tests the index against zero and takes the equal edge to state 0, but may
    // emit either branch sense (`je state0` / `jne state1`); trusting branch order
    // would swap the case bodies. Derive [state0, state1] from the condition, and
    // decline anything that isn't a proven zero-comparison of the index.
    // (This operand is also reused, honestly, as the synthetic IndirectJump target.)
    let index_operand =
        resume_index_operand(dispatch_block, disp.index_offset, disp.index_size)?;
    if !matches!(index_operand, Operand::Register(_)) {
        return None;
    }
    let ordered = ordered_two_state_targets(
        dispatch_block,
        disp.index_offset,
        disp.index_size,
        &frame_slots,
    )?;

    // Deduplicate while preserving index order (a degenerate branch could list the
    // same target twice). Need >=2 distinct states to form a switch.
    let mut states: Vec<BasicBlockId> = Vec::new();
    for t in ordered {
        if !states.contains(&t) {
            states.push(t);
        }
    }
    if states.len() < 2 {
        return None;
    }

    // Reject multi-state compare CHAINS conservatively. A genuine two-state dispatch
    // reads the resume-index field EXACTLY once (in the dispatch) and tests it once; a
    // longer chain re-tests the index for each further state, which clang -O0 does by
    // EITHER spilling the index and reloading it, OR re-reading the frame field in a
    // continuation block. Decline both forms:
    //   * `dispatch_spills_index` rejects the spill-and-reload form.
    //   * a field read anywhere but the dispatch rejects the re-read form.
    // This is a deliberately conservative, provenance-free guard (a dedicated
    // multi-state slice can flatten longer chains). A chain that instead CARRIES the
    // index in a register with neither a spill nor a re-read cannot be distinguished
    // here without whole-function dataflow, but clang -O0 does not emit that shape, so
    // it is out of scope.
    if !index_field_read_only_in_dispatch(cfg, disp.dispatch, disp.index_offset, disp.index_size)
    {
        return None;
    }

    // Rebuild the CFG: clone every block, swap the dispatch terminator for the
    // synthetic IndirectJump, then re-derive ALL edges from the (rewritten)
    // terminators so successor/predecessor sets stay consistent. `add_block`
    // seeds empty edge sets, so rebuilding from terminators cannot double-count.
    let mut rewritten = ControlFlowGraph::new(cfg.entry);
    for block in cfg.blocks() {
        rewritten.add_block(block.clone());
    }
    repair_nop_jump_returns(&mut rewritten, relocations);
    {
        let d = rewritten.block_mut(disp.dispatch)?;
        d.terminator = BlockTerminator::IndirectJump {
            target: index_operand,
            possible_targets: states,
        };
    }
    let ids: Vec<BasicBlockId> = rewritten.block_ids().collect();
    for id in ids {
        let succs = rewritten
            .block(id)
            .map(|b| b.terminator.successors())
            .unwrap_or_default();
        for succ in succs {
            rewritten.add_edge(id, succ);
        }
    }
    Some(ClangResumeRewrite {
        cfg: rewritten,
        index_offset: disp.index_offset,
    })
}

/// Undo the CFG builder's `__x86_return_thunk` heuristic within a coroutine resume
/// clone: clang at -O0 emits `e9 00000000` (a `jmp` to the immediately-following
/// instruction) as a plain no-op jump between logical blocks, but the generic CFG
/// builder (cfg_builder.rs) misreads that encoding as an unresolved return-thunk
/// relocation and rewrites the terminator to `Return`, severing a resume-point body
/// from its entry (and internal body blocks from each other). That heuristic targets
/// unlinked kernel modules; it never applies to a userspace clang coroutine (whose
/// relocations are already resolved), so re-establish the fallthrough for every such
/// block whose no-op jump lands on a real successor block. Terminal no-op jumps (no
/// following block) are left as `Return`.
fn repair_nop_jump_returns(cfg: &mut ControlFlowGraph, relocations: Option<&super::RelocationTable>) {
    use std::collections::HashMap;
    let start_to_id: HashMap<u64, BasicBlockId> =
        cfg.blocks().map(|b| (b.start, b.id)).collect();
    let ids: Vec<BasicBlockId> = cfg.block_ids().collect();
    for id in ids {
        let fallthrough = match cfg.block(id) {
            Some(b) if matches!(b.terminator, BlockTerminator::Return) => match b
                .instructions
                .last()
            {
                // A `jmp` with a relocation anchored at it is a real branch to a
                // symbol (e.g. an unresolved `jmp __x86_return_thunk` return under
                // `-mfunction-return=thunk-extern`), which shares the `e9 00000000`
                // encoding but is genuinely a return — never a no-op jump. Only a
                // relocation-free no-op jump is a severed fallthrough to repair.
                Some(inst)
                    if is_nop_jump(inst)
                        && !relocations
                            .is_some_and(|r| r.has_relocation_at(inst.address)) =>
                {
                    start_to_id.get(&inst.end_address()).copied()
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(target) = fallthrough {
            if let Some(b) = cfg.block_mut(id) {
                b.terminator = BlockTerminator::Fallthrough { target };
            }
        }
    }
}

/// `e9 00 00 00 00`: a near `jmp` with a zero relative displacement, i.e. a jump to
/// the immediately-following instruction (a no-op jump / unresolved-reloc placeholder).
fn is_nop_jump(inst: &hexray_core::Instruction) -> bool {
    inst.bytes.len() >= 5 && inst.bytes[0] == 0xe9 && inst.bytes[1..5] == [0, 0, 0, 0]
}

/// Whether the dispatch block spills the freshly-read resume index to memory. clang
/// does this only when the index is reused across a multi-way compare CHAIN (`sub
/// al,K; je stateK; ...` reloads for each subsequent test); a genuine two-state
/// dispatch tests the in-register index directly (`test al,al; je`) and never spills
/// it. Used to decline the 2-case rewrite on chains it cannot represent.
fn dispatch_spills_index(
    dispatch: &BasicBlock,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> bool {
    // Registers holding a reloaded frame pointer and the live resume index (read off it,
    // then copied/masked) — the same provenance model used everywhere in the guard, so a
    // masked index (`ldrb w8,..; and w8,w8,#3; strb w8,..`) is still recognized as
    // spilled, and a same-offset load off a non-frame base is not taken for the index.
    let mut frame_regs: Vec<String> = Vec::new();
    let mut holders: Vec<(String, u16)> = Vec::new();
    for inst in &dispatch.instructions {
        // Spill: `mov [mem], idxreg` (x86) or `str idxreg, [mem]` (aarch64) writes an
        // index-holding register back to a stack slot. Checked before the holder update
        // (a store's source register is not a redefinition of the index). Width does not
        // matter here — a spill of any part of the index is a multi-state signal.
        let stored_src = match inst.operation {
            Operation::Move => match (inst.operands.first(), inst.operands.get(1)) {
                (Some(Operand::Memory(_)), Some(Operand::Register(s))) => Some(s),
                _ => None,
            },
            Operation::Store => match (inst.operands.first(), inst.operands.get(1)) {
                (Some(Operand::Register(s)), Some(Operand::Memory(_))) => Some(s),
                _ => None,
            },
            _ => None,
        };
        if let Some(s) = stored_src {
            if holder_width(&holders, &canon_reg(s.name())).is_some() {
                return true;
            }
        }
        update_index_holders(
            inst,
            index_offset,
            index_size,
            frame_slots,
            &mut frame_regs,
            &mut holders,
        );
    }
    false
}

/// Whether the resume-index field `frame[index_offset]` (of `index_size` bytes) is
/// re-read by a CONTINUATION-DISPATCH block other than the dispatch. A multi-state
/// compare chain re-reads the field in a further block that then branches on it for each
/// extra state test, so a same-offset read in a block ending in a conditional branch
/// means this is not a genuine two-state dispatch. The conditional-branch restriction
/// stops an unrelated same-offset load in a straight-line resume body (`obj->field_0x11`)
/// from spuriously declining a valid two-state dispatch. Provenance-free and
/// deliberately conservative (see the caller's note).
fn index_field_read_only_in_dispatch(
    cfg: &ControlFlowGraph,
    dispatch_id: BasicBlockId,
    index_offset: i64,
    index_size: u8,
) -> bool {
    for block in cfg.blocks() {
        if block.id == dispatch_id
            || !matches!(block.terminator, BlockTerminator::ConditionalBranch { .. })
        {
            continue;
        }
        for inst in &block.instructions {
            if matches!(inst.operation, Operation::Move | Operation::Load) {
                if let (Some(Operand::Register(_)), Some(Operand::Memory(m))) =
                    (inst.operands.first(), inst.operands.get(1))
                {
                    if m.index.is_none()
                        && m.displacement == index_offset
                        && u16::from(m.size) == u16::from(index_size)
                    {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Order a two-state dispatch's resume targets by index value `[state0, state1]`, or
/// return `None` to decline. clang tests the resume index against zero and branches to
/// state 0 on equality; either branch sense may be emitted:
///   `test idx,idx; je state0`  (Equal:    the taken/true edge is idx==0 = state0)
///   `test idx,idx; jne state1` (NotEqual: the fall-through/false edge is idx==0 = state0)
/// so the value-0 edge is state 0 regardless of sense. Only a proven zero-comparison of
/// the index yields this mapping; a compare against a non-zero value (`cmp idx,1`) is
/// declined so case bodies are never swapped.
fn ordered_two_state_targets(
    dispatch: &BasicBlock,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> Option<Vec<BasicBlockId>> {
    let (condition, true_target, false_target) = match &dispatch.terminator {
        BlockTerminator::ConditionalBranch {
            condition,
            true_target,
            false_target,
        } => (*condition, *true_target, *false_target),
        _ => return None,
    };
    if !dispatch_zero_compares_index(dispatch, index_offset, index_size, frame_slots) {
        return None;
    }
    match condition {
        Condition::Equal => Some(vec![true_target, false_target]),
        Condition::NotEqual => Some(vec![false_target, true_target]),
        _ => None,
    }
}

/// Whether the dispatch's flag-setting instruction compares the resume index against
/// zero: `test idx,idx` (x86), `cmp idx,0`, or `subs idx,idx,zreg` (aarch64, where
/// `zreg` is the zero register or a register the block has proven to be zero, e.g.
/// `mov w9,wzr; and w9,w9,#3`). This distinguishes the value-0 edge (state 0) from a
/// non-zero comparison whose true edge would be a later state.
fn dispatch_zero_compares_index(
    dispatch: &BasicBlock,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> bool {
    // Canonical names of registers the block has proven to hold zero.
    let mut zero_regs: Vec<String> = Vec::new();
    // Registers currently holding a reloaded frame pointer, and those holding the LIVE
    // resume index (read off a frame pointer, then copied/masked). Frame-base provenance
    // ensures a same-offset load off an unrelated pointer is not taken for the index, and
    // a register overwritten after the read (`mov al,[frame+off]; mov al,0; test al,al`)
    // is dropped.
    let mut frame_regs: Vec<String> = Vec::new();
    // Each holder is (canonical register, bit-width DEFINED by the read/copy/mask), so a
    // byte index in `al` (width 8) is not accepted when a WIDER `test eax,eax` (width 32)
    // reads its undefined upper bits.
    let mut holders: Vec<(String, u16)> = Vec::new();
    let is_zero_operand = |op: &Operand, zero: &[String]| -> bool {
        match op {
            Operand::Immediate(imm) => imm.value == 0,
            Operand::Register(r) => is_zero_register(r.name()) || zero.contains(&canon_reg(r.name())),
            _ => false,
        }
    };
    // The flags the branch tests come from the LAST flag-setting instruction, so
    // recompute at every flag-setter: an index zero-test sets the result, and any OTHER
    // flag-setter (`and`, `xor`, `add`, `inc`, an unrelated `cmp`, ...) after it clears
    // the result, since the branch would then be testing those flags, not the index.
    let mut result = false;
    for inst in &dispatch.instructions {
        let index_zero_test = matches!(
            inst.operation,
            Operation::Test | Operation::Compare | Operation::Sub
        ) && {
            // A register operand IS the index when it holds the index AND is not read
            // WIDER than the holder was defined (an over-wide read pulls in undefined
            // upper bits, so the test is not `index == 0`).
            let reg_is_index = |o: &Operand| {
                matches!(o, Operand::Register(r)
                    if holder_width(&holders, &canon_reg(r.name())).is_some_and(|w| r.size <= w))
            };
            let mentions_index = inst.operands.iter().any(&reg_is_index);
            // `test idx,idx`: every register operand holds the index -> a zero test.
            let reg_count = inst
                .operands
                .iter()
                .filter(|o| matches!(o, Operand::Register(_)))
                .count();
            let is_self_test = matches!(inst.operation, Operation::Test)
                && reg_count >= 2
                && inst
                    .operands
                    .iter()
                    .filter(|o| matches!(o, Operand::Register(_)))
                    .all(&reg_is_index);
            let against_zero = inst.operands.iter().any(|o| is_zero_operand(o, &zero_regs));
            mentions_index && (is_self_test || against_zero)
        };
        if index_zero_test {
            result = true;
        } else if instruction_sets_flags(inst.operation) {
            result = false;
        }
        // Update frame-pointer and index provenance.
        update_index_holders(
            inst,
            index_offset,
            index_size,
            frame_slots,
            &mut frame_regs,
            &mut holders,
        );
        // Track registers proven zero for the aarch64 `subs idx,idx,zreg` form.
        update_zero_regs(inst, &mut zero_regs);
    }
    result
}

/// Update, across one instruction, the registers holding a reloaded FRAME POINTER
/// (`frame_regs`) and those holding the LIVE resume index (`holders`).
///
/// A frame reload (`mov reg,[framebase - K]` for a recorded spill slot, full pointer
/// width) makes `reg` a frame pointer. An index read (`mov(zx) reg,[framereg + off]` of
/// the detected width, off a register that currently holds the frame pointer) makes
/// `reg` hold the index — crucially, a same-offset load off a NON-frame base (e.g.
/// `mov dl,[rcx+0x11]`) is NOT treated as the index. A copy or index mask propagates the
/// respective status; any other write drops both.
fn update_index_holders(
    inst: &hexray_core::Instruction,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
    frame_regs: &mut Vec<String>,
    holders: &mut Vec<(String, u16)>,
) {
    // The DEFINED bit-width of the index in a source register, capped at the destination
    // width (a copy/mask into a wider dest still only defines the source's bits).
    let src_holder_width = |name: &str, dst_bits: u16| -> Option<u16> {
        holder_width(holders, name).map(|w| w.min(dst_bits))
    };
    match inst.operation {
        Operation::Move | Operation::Load => {
            let Some(Operand::Register(d)) = inst.operands.first() else {
                return;
            };
            let dc = canon_reg(d.name());
            match inst.operands.get(1) {
                Some(Operand::Memory(m)) => {
                    let base = m.base.as_ref();
                    // Frame reload: `mov reg, [framebase - K]` for a recorded slot.
                    let is_frame_reload = base.is_some_and(|b| {
                        is_frame_base_register(b.name())
                            && m.index.is_none()
                            && frame_slots.contains(&(canon_reg(b.name()), m.displacement))
                            && d.size >= b.size
                            && u16::from(m.size) * 8 >= b.size
                    });
                    // Index read: small field off a register currently holding the frame.
                    let is_index_read = base.is_some_and(|b| {
                        m.index.is_none()
                            && m.displacement == index_offset
                            && u16::from(m.size) == u16::from(index_size)
                            && frame_regs.contains(&canon_reg(b.name()))
                    });
                    holders.retain(|(r, _)| r != &dc);
                    frame_regs.retain(|r| r != &dc);
                    if is_frame_reload {
                        frame_regs.push(dc);
                    } else if is_index_read {
                        // The read defines the destination register's bits (a byte load
                        // into `al` defines 8 bits; `movzx`/`ldrb` into a 32-bit dest
                        // defines 32).
                        holders.push((dc, d.size));
                    }
                }
                // Register copy: the destination inherits both statuses from the source.
                Some(Operand::Register(s)) => {
                    let sc = canon_reg(s.name());
                    let src_width = src_holder_width(&sc, d.size);
                    let src_frame = frame_regs.contains(&sc);
                    holders.retain(|(r, _)| r != &dc);
                    frame_regs.retain(|r| r != &dc);
                    if let Some(w) = src_width {
                        holders.push((dc.clone(), w));
                    }
                    if src_frame {
                        frame_regs.push(dc);
                    }
                }
                _ => {
                    holders.retain(|(r, _)| r != &dc);
                    frame_regs.retain(|r| r != &dc);
                }
            }
        }
        // A mask of the index (`and idx, #imm`) keeps its zero-ness for the small
        // resume-state range; the destination stays a holder iff any operand is one.
        // (A `sub` is NOT preserved: `sub idx, K` yields `idx - K`, so a later
        // `test idx,idx` would test `idx == K`, not `idx == 0` — falling through to the
        // clobber branch keeps that from being mistaken for an index-zero dispatch.)
        Operation::And => {
            if let Some(Operand::Register(d)) = inst.operands.first() {
                let dc = canon_reg(d.name());
                let inherited = inst.operands.iter().find_map(|o| match o {
                    Operand::Register(r) => src_holder_width(&canon_reg(r.name()), d.size),
                    _ => None,
                });
                holders.retain(|(r, _)| r != &dc);
                frame_regs.retain(|r| r != &dc);
                if let Some(w) = inherited {
                    holders.push((dc, w));
                }
            }
        }
        // Flag-only ops leave registers untouched.
        Operation::Compare | Operation::Test => {}
        _ => {
            if let Some(Operand::Register(d)) = inst.operands.first() {
                let dc = canon_reg(d.name());
                holders.retain(|(r, _)| r != &dc);
                frame_regs.retain(|r| r != &dc);
            }
        }
    }
}

/// The bit-width at which `name` currently holds the resume index, or `None`.
fn holder_width(holders: &[(String, u16)], name: &str) -> Option<u16> {
    holders.iter().find(|(r, _)| r == name).map(|(_, w)| *w)
}

/// Whether an operation writes the condition flags (over-approximated as anything that
/// is not a pure data-move / address computation or a control transfer that reads —
/// rather than writes — the flags). Used so a flag-setter after the index zero-test
/// invalidates it: the branch would test the newer flags. `Call` is treated as
/// flag-clobbering (a callee may leave the flags undefined).
fn instruction_sets_flags(op: Operation) -> bool {
    !matches!(
        op,
        Operation::Move
            | Operation::Load
            | Operation::Store
            | Operation::LoadEffectiveAddress
            | Operation::Jump
            | Operation::ConditionalJump
            | Operation::Return
    )
}

/// Maintain the set of registers proven to hold zero within a block. Recognizes the
/// clang-emitted forms: `mov reg, 0` / `mov reg, wzr` (and copies of a zero register),
/// and `and reg, zsrc, #imm` (`0 & x == 0`). Any other write clears the register.
fn update_zero_regs(inst: &hexray_core::Instruction, zero: &mut Vec<String>) {
    let source_is_zero = |op: Option<&Operand>| -> bool {
        match op {
            Some(Operand::Immediate(imm)) => imm.value == 0,
            Some(Operand::Register(r)) => is_zero_register(r.name()) || zero.contains(&canon_reg(r.name())),
            _ => false,
        }
    };
    let (dst, becomes_zero) = match inst.operation {
        Operation::Move => (inst.operands.first(), source_is_zero(inst.operands.get(1))),
        // `and dst, src, #imm` (or reg): zero if any source is zero.
        Operation::And => (
            inst.operands.first(),
            inst.operands.iter().skip(1).any(|o| source_is_zero(Some(o))),
        ),
        // Flag-only ops leave registers untouched.
        Operation::Compare | Operation::Test => return,
        _ => (inst.operands.first(), false),
    };
    if let Some(Operand::Register(d)) = dst {
        let dc = canon_reg(d.name());
        zero.retain(|r| r != &dc);
        if becomes_zero {
            zero.push(dc);
        }
    }
}

/// The architectural zero register (`wzr`/`xzr` on aarch64), which always reads as 0.
fn is_zero_register(name: &str) -> bool {
    matches!(name.to_lowercase().as_str(), "wzr" | "xzr")
}

/// The register operand holding the resume index in the dispatch block — the last
/// small frame-field read matching the detected `(offset, size)` — reused as the
/// synthetic IndirectJump target operand.
fn resume_index_operand(dispatch: &BasicBlock, offset: i64, size: u8) -> Option<Operand> {
    let mut found: Option<Operand> = None;
    for inst in &dispatch.instructions {
        if matches!(inst.operation, Operation::Move | Operation::Load) {
            if let (Some(dst), Some(Operand::Memory(m))) =
                (inst.operands.first(), inst.operands.get(1))
            {
                if matches!(dst, Operand::Register(_))
                    && m.index.is_none()
                    && m.displacement == offset
                    && m.size == size
                {
                    found = Some(dst.clone());
                }
            }
        }
    }
    found
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

    /// A near `jmp` with a zero displacement at `addr` (`e9 00000000`), 5 bytes.
    fn jmp_nop(addr: u64) -> Instruction {
        Instruction::new(addr, 5, vec![0xe9, 0, 0, 0, 0], "jmp").with_operation(Operation::Move)
    }

    /// Build the shape-A entry+dispatch skeleton with two resume-state blocks.
    fn shape_a_cfg(r0: BasicBlockId, r1: BasicBlockId) -> ControlFlowGraph {
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
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
        // `test al, al` (zero-test of the resume index) feeds the `je`.
        dispatch.instructions.push(
            Instruction::new(0, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(al), Operand::Register(al)]),
        );
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: r0,
            false_target: r1,
        };
        cfg.add_block(dispatch);
        cfg
    }

    #[test]
    fn rewrite_shape_a_produces_indirect_switch_dispatch() {
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));

        let rewritten = rewrite_clang_resume_dispatch(&cfg, None).expect("rewritten").cfg;
        let dispatch = rewritten.block(BasicBlockId::new(1)).unwrap();
        match &dispatch.terminator {
            BlockTerminator::IndirectJump {
                possible_targets, ..
            } => assert_eq!(possible_targets, &vec![r0, r1]),
            other => panic!("expected IndirectJump, got {other:?}"),
        }
        // Edges re-derived from the rewritten terminator point at the resume states.
        let succ = rewritten.successors(BasicBlockId::new(1));
        assert!(succ.contains(&r0) && succ.contains(&r1));
    }

    #[test]
    fn rewrite_declines_jump_table_shape() {
        // A native IndirectJump dispatch (shape B) already reaches switch recovery;
        // the rewrite must leave it alone.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));
        cfg.block_mut(BasicBlockId::new(1)).unwrap().terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(r(0, 64)),
            possible_targets: vec![r0, r1],
        };
        assert!(rewrite_clang_resume_dispatch(&cfg, None).is_none());
    }

    #[test]
    fn rewrite_orders_cases_by_index_for_inverted_branch_sense() {
        // clang can invert the sense: `test al,al; jne state1` (NotEqual), so the
        // TRUE edge is idx!=0 (state 1) and the FALSE edge is idx==0 (state 0). The
        // switch cases must still be ordered [state0, state1], not by branch position.
        let (state0, state1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(state1, state0); // true=state1, false=state0
        cfg.add_block(BasicBlock::new(state0, 0x50e));
        cfg.add_block(BasicBlock::new(state1, 0x608));
        // Flip the condition to `jne`.
        if let BlockTerminator::ConditionalBranch { condition, .. } =
            &mut cfg.block_mut(BasicBlockId::new(1)).unwrap().terminator
        {
            *condition = Condition::NotEqual;
        }
        let rewritten = rewrite_clang_resume_dispatch(&cfg, None).expect("rewritten").cfg;
        match &rewritten.block(BasicBlockId::new(1)).unwrap().terminator {
            BlockTerminator::IndirectJump {
                possible_targets, ..
            } => assert_eq!(possible_targets, &vec![state0, state1]),
            other => panic!("expected IndirectJump, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_declines_non_zero_index_compare() {
        // `cmp al, 1; je state1` compares against 1, so the true edge is NOT state 0;
        // the value->target mapping is ambiguous for a 2-case rewrite -> decline.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));
        let al = r(0, 8);
        // Replace the `test al,al` with `cmp al, 1`.
        let dispatch = cfg.block_mut(BasicBlockId::new(1)).unwrap();
        dispatch.instructions.pop();
        dispatch.instructions.push(
            Instruction::new(0, 2, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![
                    Operand::Register(al),
                    Operand::Immediate(hexray_core::Immediate {
                        value: 1,
                        size: 8,
                        signed: false,
                    }),
                ]),
        );
        assert!(!dispatch_zero_compares_index(
            cfg.block(BasicBlockId::new(1)).unwrap(),
            0x11,
            1,
            &x_frame_slots()
        ));
        assert!(rewrite_clang_resume_dispatch(&cfg, None).is_none());
    }

    #[test]
    fn arm64_subs_against_computed_zero_is_a_zero_compare() {
        // aarch64 clang: `ldrb w8,[..]; and w8,w8,#3; mov w9,wzr; and w9,w9,#3;
        // subs w8,w8,w9; b.eq state0`. `w9` is a computed zero, so this IS a zero
        // comparison of the (masked) index and must map the equal edge to state 0.
        let a = Architecture::Arm64;
        let gp = |id: u16, bits: u16| Register::new(a, RegisterClass::General, id, bits);
        // arm64::XZR is register id 32 (names as `wzr`/`xzr`).
        let (x8, w8, w9, wzr, x29) = (gp(8, 64), gp(8, 32), gp(9, 32), gp(32, 32), gp(29, 64));
        let mut dispatch = BasicBlock::new(BasicBlockId::new(1), 0x7b8);
        // ldur x8, [x29 - 0x38] — reload the coroutine frame pointer into x8.
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldur")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(x8),
                    Operand::Memory(MemoryRef::base_disp(x29, -0x38, 8)),
                ]),
        );
        let and = |d: Register, s: Register, imm: i128| {
            Instruction::new(0, 4, vec![], "and")
                .with_operation(Operation::And)
                .with_operands(vec![
                    Operand::Register(d),
                    Operand::Register(s),
                    Operand::Immediate(hexray_core::Immediate {
                        value: imm,
                        size: 32,
                        signed: false,
                    }),
                ])
        };
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "ldrb")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x8, 0x11, 1)),
                ]),
        );
        dispatch.instructions.push(and(w8, w8, 0x3));
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(w9), Operand::Register(wzr)]),
        );
        dispatch.instructions.push(and(w9, w9, 0x3));
        dispatch.instructions.push(
            Instruction::new(0, 4, vec![], "subs")
                .with_operation(Operation::Sub)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Register(w8),
                    Operand::Register(w9),
                ]),
        );
        dispatch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        let slots = vec![("x29".to_string(), -0x38)];
        assert!(dispatch_zero_compares_index(&dispatch, 0x11, 1, &slots));
        assert_eq!(
            ordered_two_state_targets(&dispatch, 0x11, 1, &slots),
            Some(vec![BasicBlockId::new(2), BasicBlockId::new(3)])
        );
    }

    #[test]
    fn rewrite_declines_multi_state_chain_that_spills_index() {
        // A >2-state dispatch reloads the index for later compares, so it spills the
        // freshly-read index to a stack slot: `mov al,[rax+0x11]; mov [rbp-0xd5],al;
        // sub al,2; je state2`. The two immediate targets are NOT the full state set,
        // so the 2-case rewrite must decline.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));
        let (rbp, al) = (r(5, 64), r(0, 8));
        // Insert the index spill right after the `mov al,[rax+0x11]` read.
        let dispatch = cfg.block_mut(BasicBlockId::new(1)).unwrap();
        dispatch.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0xd5, 1)),
            Operand::Register(al),
        ));
        assert!(dispatch_spills_index(
            cfg.block(BasicBlockId::new(1)).unwrap(),
            0x11,
            1,
            &x_frame_slots()
        ));
        assert!(rewrite_clang_resume_dispatch(&cfg, None).is_none());
    }

    fn imm1(bits: u8) -> Operand {
        Operand::Immediate(hexray_core::Immediate {
            value: 1,
            size: bits,
            signed: false,
        })
    }

    #[test]
    fn field_read_guard_ignores_straightline_body_load() {
        // A resume body loading an unrelated same-offset field (`obj->field_0x11`) in a
        // NON-branch block must NOT disable recovery.
        let dispatch = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(dispatch);
        cfg.add_block(BasicBlock::new(dispatch, 0x82e));
        let mut body = BasicBlock::new(BasicBlockId::new(1), 0x600);
        body.instructions.push(mov(
            Operand::Register(r(0, 8)),
            Operand::Memory(MemoryRef::base_disp(r(1, 64), 0x11, 1)),
        ));
        body.terminator = BlockTerminator::Return;
        cfg.add_block(body);
        assert!(index_field_read_only_in_dispatch(&cfg, dispatch, 0x11, 1));
    }

    #[test]
    fn field_read_guard_rejects_continuation_reread() {
        // A same-offset read in a block that then branches is a continuation dispatch.
        let dispatch = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(dispatch);
        cfg.add_block(BasicBlock::new(dispatch, 0x82e));
        let mut cont = BasicBlock::new(BasicBlockId::new(1), 0x600);
        cont.instructions.push(mov(
            Operand::Register(r(0, 8)),
            Operand::Memory(MemoryRef::base_disp(r(1, 64), 0x11, 1)),
        ));
        cont.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(cont);
        assert!(!index_field_read_only_in_dispatch(&cfg, dispatch, 0x11, 1));
    }

    #[test]
    fn spill_detected_for_masked_then_stored_index() {
        // aarch64: `ldrb w8,[frame+0x11]; and w8,w8,#3; strb w8,[x29-0x38]` spills the
        // masked resume index — must count as a spill (a multi-state chain).
        let a = Architecture::Arm64;
        let gp = |id: u16, bits: u16| Register::new(a, RegisterClass::General, id, bits);
        let (x8, w8, x29) = (gp(8, 64), gp(8, 32), gp(29, 64));
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x7b8);
        // ldur x8, [x29 - 0x38] — reload the coroutine frame pointer.
        block.instructions.push(
            Instruction::new(0, 4, vec![], "ldur")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(x8),
                    Operand::Memory(MemoryRef::base_disp(x29, -0x38, 8)),
                ]),
        );
        block.instructions.push(
            Instruction::new(0, 4, vec![], "ldrb")
                .with_operation(Operation::Load)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x8, 0x11, 1)),
                ]),
        );
        block.instructions.push(
            Instruction::new(0, 4, vec![], "and")
                .with_operation(Operation::And)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Register(w8),
                    imm1(32),
                ]),
        );
        block.instructions.push(
            Instruction::new(0, 4, vec![], "strb")
                .with_operation(Operation::Store)
                .with_operands(vec![
                    Operand::Register(w8),
                    Operand::Memory(MemoryRef::base_disp(x29, -0x40, 1)),
                ]),
        );
        assert!(dispatch_spills_index(&block, 0x11, 1, &[("x29".to_string(), -0x38)]));
    }

    fn test_ii(reg: Register) -> Instruction {
        Instruction::new(0, 2, vec![], "test")
            .with_operation(Operation::Test)
            .with_operands(vec![Operand::Register(reg), Operand::Register(reg)])
    }

    fn je() -> Instruction {
        Instruction::new(0, 6, vec![], "je").with_operation(Operation::ConditionalJump)
    }

    /// `mov al, [rax + 0x11]` — the resume-index field read that establishes provenance.
    fn read_index() -> Instruction {
        mov(
            Operand::Register(r(0, 8)),
            Operand::Memory(MemoryRef::base_disp(r(0, 64), 0x11, 1)),
        )
    }

    /// `mov rax, [rbp - 0x70]` — establishes `rax` as the frame pointer, so the byte
    /// read `[rax + 0x11]` is recognized as the resume index.
    fn frame_reload() -> Instruction {
        mov(
            Operand::Register(r(0, 64)),
            Operand::Memory(MemoryRef::base_disp(r(5, 64), -0x70, 8)),
        )
    }

    fn x_frame_slots() -> Vec<SpillSlot> {
        vec![("rbp".to_string(), -0x70)]
    }

    #[test]
    fn zero_compare_recognizes_test_then_branch() {
        // `mov al,[frame+0x11]; test al,al; je` — je reads (not sets) flags.
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(test_ii(r(0, 8)));
        block.instructions.push(je());
        assert!(dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn zero_compare_invalidated_by_later_flag_setter() {
        // `mov al,[frame+0x11]; test al,al; add ecx,1; je` — the branch tests `add`'s
        // flags, not the index, so this must NOT be an index-zero dispatch.
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(test_ii(r(0, 8)));
        block.instructions.push(
            Instruction::new(0, 3, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(r(1, 32)), imm1(32)]),
        );
        block.instructions.push(je());
        assert!(!dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn zero_compare_rejects_nonzero_subtract_result() {
        // `mov al,[frame+0x11]; sub al,1; test al,al` tests (index-1)==0 (i.e. index==1),
        // NOT index==0, so it must not be accepted as an index-zero dispatch.
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(
            Instruction::new(0, 3, vec![], "sub")
                .with_operation(Operation::Sub)
                .with_operands(vec![Operand::Register(r(0, 8)), imm1(8)]),
        );
        block.instructions.push(test_ii(r(0, 8)));
        block.instructions.push(je());
        assert!(!dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn zero_compare_rejects_wider_test_of_byte_index() {
        // `mov al,[frame+0x11]` defines only the low 8 bits; a later `test eax,eax`
        // (32-bit) reads undefined upper bits, so it is NOT a byte-index zero-test.
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(test_ii(r(0, 32)));
        block.instructions.push(je());
        assert!(!dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn zero_compare_rejects_same_offset_read_off_non_frame_base() {
        // After the real `[rax+0x11]` read, a `mov dl,[rcx+0x11]; test dl,dl` at the same
        // offset but off a NON-frame base (rcx) must NOT be accepted as the index
        // dispatch — provenance requires the read to be off a frame pointer.
        let (rcx, dl) = (r(1, 64), r(2, 8));
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(mov(
            Operand::Register(dl),
            Operand::Memory(MemoryRef::base_disp(rcx, 0x11, 1)),
        ));
        block.instructions.push(test_ii(dl));
        block.instructions.push(je());
        assert!(!dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn zero_compare_rejects_overwritten_index_register() {
        // `mov al,[frame+0x11]; mov al,0; test al,al` — al no longer holds the live
        // index at the test, so this is not an index dispatch.
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(mov(Operand::Register(r(0, 8)), imm1(8)));
        block.instructions.push(test_ii(r(0, 8)));
        block.instructions.push(je());
        assert!(!dispatch_zero_compares_index(&block, 0x11, 1, &x_frame_slots()));
    }

    #[test]
    fn two_state_dispatch_does_not_count_as_spilling_index() {
        // The plain `test al,al; je` dispatch never stores the index to memory.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let cfg = shape_a_cfg(r0, r1);
        assert!(!dispatch_spills_index(
            cfg.block(BasicBlockId::new(1)).unwrap(),
            0x11,
            1,
            &x_frame_slots()
        ));
    }

    #[test]
    fn repair_skips_relocated_return_thunk_jump() {
        // A real `jmp __x86_return_thunk` shares the `e9 00000000` encoding but has a
        // relocation at its address; it must stay a return, not become a fallthrough.
        use super::super::RelocationTable;
        let a = BasicBlockId::new(0);
        let b = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(a);
        let mut ba = BasicBlock::new(a, 0x100);
        ba.instructions.push(jmp_nop(0x100));
        ba.terminator = BlockTerminator::Return;
        cfg.add_block(ba);
        cfg.add_block(BasicBlock::new(b, 0x105));

        let mut reloc = RelocationTable::new();
        reloc.insert_call(0x100, "__x86_return_thunk".to_string(), 0, true);
        repair_nop_jump_returns(&mut cfg, Some(&reloc));
        assert_eq!(cfg.block(a).unwrap().terminator, BlockTerminator::Return);
    }

    #[test]
    fn repair_reconnects_nop_jump_return_to_fallthrough() {
        // A block ending in `e9 00000000` at 0x100 (5 bytes) that the CFG builder
        // mislabeled `Return`; a real block starts at the fallthrough 0x105.
        let a = BasicBlockId::new(0);
        let b = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(a);
        let mut ba = BasicBlock::new(a, 0x100);
        ba.instructions.push(jmp_nop(0x100));
        ba.terminator = BlockTerminator::Return;
        cfg.add_block(ba);
        cfg.add_block(BasicBlock::new(b, 0x105));

        repair_nop_jump_returns(&mut cfg, None);
        assert_eq!(
            cfg.block(a).unwrap().terminator,
            BlockTerminator::Fallthrough { target: b }
        );
    }

    #[test]
    fn repair_leaves_terminal_nop_jump_as_return() {
        // No block at the fallthrough address -> keep it a return (kernel thunk tail).
        let a = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(a);
        let mut ba = BasicBlock::new(a, 0x100);
        ba.instructions.push(jmp_nop(0x100));
        ba.terminator = BlockTerminator::Return;
        cfg.add_block(ba);

        repair_nop_jump_returns(&mut cfg, None);
        assert_eq!(cfg.block(a).unwrap().terminator, BlockTerminator::Return);
    }

    #[test]
    fn repair_leaves_real_return_untouched() {
        // A genuine `ret` (0xc3) followed by a block must stay a return.
        let a = BasicBlockId::new(0);
        let b = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(a);
        let mut ba = BasicBlock::new(a, 0x100);
        ba.instructions
            .push(Instruction::new(0x100, 1, vec![0xc3], "ret"));
        ba.terminator = BlockTerminator::Return;
        cfg.add_block(ba);
        cfg.add_block(BasicBlock::new(b, 0x101));

        repair_nop_jump_returns(&mut cfg, None);
        assert_eq!(cfg.block(a).unwrap().terminator, BlockTerminator::Return);
    }
}
