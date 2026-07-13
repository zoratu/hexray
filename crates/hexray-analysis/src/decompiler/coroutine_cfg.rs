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

use super::{BinaryDataContext, SwitchRecovery};
use hexray_core::{
    BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph, MemoryRef, Operand,
    Operation, Register,
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
    /// Whether the recovered switch's nonzero edge should be shaped into `default`.
    /// True for the compare-chain 2-state shape (`test idx,idx; je state0` routes
    /// EVERY nonzero value to the false edge); false for a jump table, whose cases
    /// are already explicit `0..N-1` and must be left as-is.
    pub two_way_default: bool,
}

pub fn rewrite_clang_resume_dispatch(
    cfg: &ControlFlowGraph,
    relocations: Option<&super::RelocationTable>,
    binary_data: Option<&BinaryDataContext>,
) -> Option<ClangResumeRewrite> {
    let disp = detect_clang_resume_dispatch(cfg)?;
    let dispatch_block = cfg.block(disp.dispatch)?;
    // The stack homes holding the frame pointer (arg0), so a reload in the dispatch is
    // recognized and only a read off a frame pointer is taken for the resume index.
    let frame_slots = frame_pointer_spill_slots(cfg.entry_block()?);

    // Many-state dispatch: a `.rodata` jump table. It already reaches switch recovery
    // through its native `IndirectJump` — we do NOT rebuild the terminator; but clang's
    // `e9 00000000` no-op jumps still sever the resume-point bodies (the CFG builder
    // mislabels them `Return`), collapsing the recovered switch cases to bare `return`s.
    // Repair those (keeping the jump table) so the bodies survive structuring.
    //
    // Gate on the table actually RESOLVING here — run the same jump-table recovery the
    // structurer will (reading the `.rodata` table from binary data), and only proceed if
    // it yields a real multi-case switch. `possible_targets` alone can't be checked: the
    // CFG builder often leaves it empty for a resolvable table (resolution happens
    // downstream), so an emptiness check would wrongly decline linked tables — while an
    // unresolvable `.o` table (no binary data / unrelocated base) forms NO dispatch switch,
    // and proceeding there would run the naming pass with no dispatch to name, letting it
    // rename an unrelated user switch. Resolving up front guarantees the dispatch switch
    // exists before we claim recovery.
    if matches!(disp.shape, DispatchShape::JumpTable { .. }) {
        // Require a 1-byte resume index (clang's form). The table resolver has no bounds
        // check to size the table and falls back to a 256-entry default, which exactly
        // covers a 1-byte index (<= 256 states) but would silently TRUNCATE a wider one:
        // a 2-byte index with > 256 states would read as a dense `0..255` prefix and commit
        // with the higher states' edges/cases missing. Decline wider indices rather than
        // accept a truncated prefix.
        if disp.index_size != 1 {
            return None;
        }
        // Prove the indirect jump is DRIVEN by the resume-index field (not an unrelated
        // computed jump that merely happens to sit after a small frame read), and that the
        // table actually resolves to a multi-case switch. Both must hold before we claim
        // recovery — otherwise the naming pass could rename an unrelated switch.
        if !dispatch_jump_indexed_by_resume_read(
            dispatch_block,
            disp.index_offset,
            disp.index_size,
            &frame_slots,
        ) {
            return None;
        }
        let targets = resolved_jump_table_targets(
            cfg,
            disp.dispatch,
            disp.index_offset,
            disp.index_size,
            &frame_slots,
            binary_data,
        )?;
        let mut rewritten = repaired_cfg(cfg, relocations);
        // Merge the resolved table targets into the dispatch's `possible_targets`, so
        // `rederive_edges` connects the dispatch to EVERY resume state — whether the CFG
        // builder left the list empty or populated it incompletely. Otherwise loop/dominator
        // analyses (run on CFG edges BEFORE switch recovery) would treat a table-only-
        // reachable state as unreachable and degrade its loops to gotos. Merge (not
        // overwrite) so any extra target the builder found — e.g. a bounds-check default — is
        // preserved.
        if let Some(block) = rewritten.block_mut(disp.dispatch) {
            if let BlockTerminator::IndirectJump {
                possible_targets, ..
            } = &mut block.terminator
            {
                for t in targets {
                    if !possible_targets.contains(&t) {
                        possible_targets.push(t);
                    }
                }
            }
        }
        rederive_edges(&mut rewritten);
        return Some(ClangResumeRewrite {
            cfg: rewritten,
            index_offset: disp.index_offset,
            two_way_default: false,
        });
    }

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
    if !index_field_read_only_in_dispatch(
        cfg,
        disp.dispatch,
        disp.index_offset,
        disp.index_size,
        &frame_slots,
    ) {
        return None;
    }

    // Rebuild the CFG (blocks cloned + no-op jumps repaired), swap the dispatch
    // terminator for the synthetic IndirectJump over the resume states, then re-derive
    // ALL edges from the (rewritten) terminators so successor/predecessor sets stay
    // consistent.
    let mut rewritten = repaired_cfg(cfg, relocations);
    {
        let d = rewritten.block_mut(disp.dispatch)?;
        d.terminator = BlockTerminator::IndirectJump {
            target: index_operand,
            possible_targets: states,
        };
    }
    rederive_edges(&mut rewritten);
    Some(ClangResumeRewrite {
        cfg: rewritten,
        index_offset: disp.index_offset,
        two_way_default: true,
    })
}

/// Whether the dispatch's indirect jump is INDEXED BY the resume-index field read — i.e.
/// the value read from `frame[index_offset]` reaches the jump-table index register
/// `[base + idx*scale]`. This proves the computed jump is the resume dispatch (driven by
/// the resume index) rather than an unrelated computed jump that merely follows a small
/// frame read. The value is followed within the dispatch block through register
/// copies/extends and a scratch-slot spill/reload (clang -O0 spills the index and reloads
/// it before the table load); the indexed table LOAD produces a jump-target address, and
/// the check succeeds only when the actual `IndirectJump` target is that table-derived
/// address (register, after the usual `add base` adjustment) or is itself a `jmp
/// *table(,idx,scale)` indexed by the resume index. Tying success to the terminator target
/// avoids both accepting an unrelated indexed load and missing a direct indexed jump.
fn dispatch_jump_indexed_by_resume_read(
    dispatch: &BasicBlock,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> bool {
    // Registers holding the reloaded frame pointer / the index value / a table-derived jump
    // target, and scratch stack slots holding a spilled copy of the index.
    let mut frame_regs: Vec<String> = Vec::new();
    let mut holders: Vec<String> = Vec::new();
    let mut target_regs: Vec<String> = Vec::new();
    let mut index_slots: Vec<SpillSlot> = Vec::new();

    // Whether a memory operand is indexed by a register currently holding the resume index.
    let uses_index = |m: &MemoryRef, holders: &[String]| {
        m.index
            .as_ref()
            .is_some_and(|i| holders.contains(&canon_reg(i.name())))
    };

    for inst in &dispatch.instructions {
        match inst.operation {
            // `SignExtend` covers `movsxd rax, [table + idx*4]` (the sign-extending
            // jump-table load) and register sign-extends of the index.
            Operation::Move | Operation::Load | Operation::SignExtend => {
                match (inst.operands.first(), inst.operands.get(1)) {
                    // `reg <- [mem]`: a frame reload, the index field read, a reload of the
                    // spilled index, or the jump-table load (indexed by the resume index).
                    (Some(Operand::Register(d)), Some(Operand::Memory(m))) => {
                        let dc = canon_reg(d.name());
                        let base = m.base.as_ref();
                        // Classify against the CURRENT state before clobbering `dc` — the
                        // index read `movzbl off(rax), eax` reuses its base register as the
                        // destination, so removing `dc` first would hide `base in frame_regs`.
                        let is_frame_reload = base.is_some_and(|b| {
                            is_frame_base_register(b.name())
                                && m.index.is_none()
                                && frame_slots.contains(&(canon_reg(b.name()), m.displacement))
                                && d.size >= b.size
                        });
                        // The index must land in a >= 32-bit destination so it fills the
                        // (32/64-bit) table-index register: reading the 1-byte field into a
                        // subregister (`mov al, [frame+off]`) leaves the upper bits stale, so
                        // a later `[table + rax*scale]` would be indexed by garbage. clang
                        // zero-extends (`movzbl ..., eax`), which x86 also clears rax's upper
                        // 32 bits, so a 32-bit destination is enough.
                        let defines_full_index = d.size >= 32;
                        let is_index_read = defines_full_index
                            && base.is_some_and(|b| {
                                m.index.is_none()
                                    && m.displacement == index_offset
                                    && u16::from(m.size) == u16::from(index_size)
                                    && frame_regs.contains(&canon_reg(b.name()))
                            });
                        let is_index_reload = defines_full_index
                            && base.is_some_and(|b| {
                                m.index.is_none()
                                    && index_slots.contains(&(canon_reg(b.name()), m.displacement))
                            });
                        // The jump-table load: `movslq dst, [base + idx*scale]`. Its result
                        // is a (relative) jump-target address, not the index any more.
                        let is_table_load = uses_index(m, &holders);
                        holders.retain(|r| r != &dc);
                        frame_regs.retain(|r| r != &dc);
                        target_regs.retain(|r| r != &dc);
                        if is_frame_reload {
                            frame_regs.push(dc);
                        } else if is_index_read || is_index_reload {
                            holders.push(dc);
                        } else if is_table_load {
                            target_regs.push(dc);
                        }
                    }
                    // `[mem] <- anything` (x86 `mov [slot], idx` / `mov [slot], 0`): a store.
                    // Any store to a scratch slot INVALIDATES a prior index spill there; only
                    // a store of the index register re-records it.
                    (Some(Operand::Memory(m)), src) => {
                        record_index_spill(m, register_operand(src), &holders, &mut index_slots);
                    }
                    // `reg <- reg`: a copy/extend propagates every status to the dest.
                    (Some(Operand::Register(d)), Some(Operand::Register(s))) => {
                        let dc = canon_reg(d.name());
                        let sc = canon_reg(s.name());
                        // A copy into a subregister (`mov cl, eax`) doesn't fully define the
                        // index register, so it doesn't carry index-holder status.
                        let src_holder = d.size >= 32 && holders.contains(&sc);
                        let src_frame = frame_regs.contains(&sc);
                        let src_target = target_regs.contains(&sc);
                        holders.retain(|r| r != &dc);
                        frame_regs.retain(|r| r != &dc);
                        target_regs.retain(|r| r != &dc);
                        if src_holder {
                            holders.push(dc.clone());
                        }
                        if src_frame {
                            frame_regs.push(dc.clone());
                        }
                        if src_target {
                            target_regs.push(dc);
                        }
                    }
                    // `reg <- immediate` / any other form still WRITES the destination
                    // register (e.g. `mov eax, 0`), so its stale provenance must be cleared.
                    (Some(Operand::Register(d)), _) => {
                        clobber_register(&canon_reg(d.name()), &mut holders, &mut frame_regs, &mut target_regs);
                    }
                    _ => {}
                }
            }
            // aarch64 `str idx, [sp, #slot]`: operands are `[src, Memory(dst)]` (source
            // FIRST), so this is a spill (or slot-invalidating store), not a clobber.
            Operation::Store => {
                if let Some(Operand::Memory(m)) = inst.operands.get(1) {
                    record_index_spill(m, register_operand(inst.operands.first()), &holders, &mut index_slots);
                }
            }
            // Address arithmetic on the table-loaded value keeps it a jump-target register,
            // but ONLY `add` (`add rax, table_base`, turning the relative offset into the
            // absolute target). `SwitchRecovery` models table entries as absolute addresses
            // or `table_base + entry` — never `table_base - entry` — so a `sub` would compute
            // a jump target the resolver does not model; let it fall through to the clobber
            // arm so the mismatch is declined rather than wired to the wrong address.
            Operation::Add => {
                if let Some(Operand::Register(d)) = inst.operands.first() {
                    let dc = canon_reg(d.name());
                    // Two-operand `add dst, src` (x86) reads its destination, so the dest's
                    // own table-target status carries; three-operand `add dst, s1, s2`
                    // (aarch64) does NOT — it fully overwrites `dst`, so only the explicit
                    // source registers can make the result a jump target.
                    let dst_is_source = inst.operands.len() == 2;
                    let stays_target = (dst_is_source && target_regs.contains(&dc))
                        || inst.operands.iter().skip(1).any(|o| {
                            matches!(o, Operand::Register(r) if target_regs.contains(&canon_reg(r.name())))
                        });
                    clobber_register(&dc, &mut holders, &mut frame_regs, &mut target_regs);
                    if stays_target {
                        target_regs.push(dc);
                    }
                }
            }
            // clang can fuse the base-add into the address computation: `lea reg,
            // [table_base + table_result]` (or `[table_result + base]`). The dest is the
            // absolute jump target iff the address arithmetic combines a table-loaded
            // register (as base or index).
            Operation::LoadEffectiveAddress => {
                if let Some(Operand::Register(d)) = inst.operands.first() {
                    let dc = canon_reg(d.name());
                    // Only a `[base + index]` computation combining a table-loaded register
                    // makes the dest a jump target; any other LEA form still WRITES the dest,
                    // so it must at least clear that register's stale provenance.
                    let from_target = matches!(inst.operands.get(1), Some(Operand::Memory(m))
                        if m.base.as_ref().is_some_and(|b| target_regs.contains(&canon_reg(b.name())))
                            || m.index.as_ref().is_some_and(|i| target_regs.contains(&canon_reg(i.name()))));
                    clobber_register(&dc, &mut holders, &mut frame_regs, &mut target_regs);
                    if from_target {
                        target_regs.push(dc);
                    }
                }
            }
            // Flag-only and control-transfer ops leave registers untouched — in
            // particular `jmp *rax` READS `rax` (the jump target) rather than writing it,
            // so it must not clear the target register just before the terminator check.
            Operation::Compare
            | Operation::Test
            | Operation::Jump
            | Operation::ConditionalJump
            | Operation::Return => {}
            // Any other write clobbers its destination register's status.
            _ => {
                if let Some(Operand::Register(d)) = inst.operands.first() {
                    clobber_register(&canon_reg(d.name()), &mut holders, &mut frame_regs, &mut target_regs);
                }
            }
        }
    }

    // The jump is driven by the resume index iff its target is a register holding the
    // table-derived address. A direct `jmp *table(,idx,scale)` (indexed memory on the
    // terminator) is deliberately NOT accepted: `SwitchRecovery` only scans block
    // instructions to find the table base, so it could not resolve that form anyway —
    // accepting it here would claim recovery the resolver then declines. clang -O0 loads the
    // target into a register first, so this costs no real coverage.
    match &dispatch.terminator {
        BlockTerminator::IndirectJump { target, .. } => {
            matches!(target, Operand::Register(r) if target_regs.contains(&canon_reg(r.name())))
        }
        _ => false,
    }
}

/// Update the index-spill slots for a store to `[base - K]`. ANY store to a scratch slot
/// first INVALIDATES a prior index spill recorded there (the value is now something else);
/// a store of a register that currently holds the index then re-records the slot, so a
/// later reload re-establishes the index. `src` is `None` for a non-register store (e.g.
/// `mov [slot], 0`), which only invalidates.
fn record_index_spill(
    m: &MemoryRef,
    src: Option<&Register>,
    holders: &[String],
    index_slots: &mut Vec<SpillSlot>,
) {
    if let Some(b) = &m.base {
        if m.index.is_none() {
            let key = (canon_reg(b.name()), m.displacement);
            index_slots.retain(|k| k != &key);
            if src.is_some_and(|s| holders.contains(&canon_reg(s.name()))) {
                index_slots.push(key);
            }
        }
    }
}

/// The register of an operand, if it is a register operand.
fn register_operand(op: Option<&Operand>) -> Option<&Register> {
    match op {
        Some(Operand::Register(r)) => Some(r),
        _ => None,
    }
}

/// Drop every index/frame/target provenance for a register that has just been written, so a
/// later use of the (now unrelated) value can't be mistaken for the resume index or a
/// table-derived jump target.
fn clobber_register(
    dc: &str,
    holders: &mut Vec<String>,
    frame_regs: &mut Vec<String>,
    target_regs: &mut Vec<String>,
) {
    holders.retain(|r| r != dc);
    frame_regs.retain(|r| r != dc);
    target_regs.retain(|r| r != dc);
}

/// The resume-state target blocks of the jump table at `dispatch`, IF it genuinely resolves
/// to the complete, dense resume dispatch `switch (0..N-1)` by READING the `.rodata` table
/// from binary data — the same read the structurer will perform downstream. Returns the
/// unique target blocks (ordered by ascending resume-state index), or `None` when the table
/// can't be read or isn't dense.
///
/// This proves the recovered switch will form AND that its case labels are complete: the
/// deduplicated `possible_targets` fallback is deliberately NOT accepted, because it
/// collapses duplicate table entries (two states resuming at the same block) into unique
/// targets with sequential labels, which would drop a state yet still look "dense" to the
/// naming pass. An unresolvable table (no binary data, or an unrelocated `.o` base) yields
/// no read, so the rewrite declines rather than commit an incorrect switch.
///
/// Completeness: a bounded table's read fails if any entry is unmapped (see
/// [`SwitchRecovery::try_recover_switch_read_from_binary`]); an unbounded table (clang's
/// coroutine form) has its length BOUNDED here by the largest resume-index the function
/// stores into the frame field (`mov [frame+off], N`) — the highest state the coroutine can
/// ever dispatch. That rejects a garbage word just past the real table that happens to
/// decode to an in-function block and would otherwise extend the dense labels by a spurious
/// case; the dense-`0..N-1` contiguity check catches a non-adjacent accidental map.
fn resolved_jump_table_targets(
    cfg: &ControlFlowGraph,
    dispatch: BasicBlockId,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
    binary_data: Option<&BinaryDataContext>,
) -> Option<Vec<BasicBlockId>> {
    let mut recovery = SwitchRecovery::new(cfg);
    if let Some(ctx) = binary_data {
        recovery = recovery.with_binary_context(ctx);
    }
    let info = recovery.try_recover_switch_read_from_binary(dispatch)?;

    // The read table must span the dense resume states `0..N-1` (N >= 2). Flatten grouped
    // labels — `read_jump_table` groups duplicate targets into one multi-label case.
    let mut labels: Vec<i128> = info.cases.iter().flat_map(|(vs, _)| vs.iter().copied()).collect();
    if labels.len() < 2 {
        return None;
    }
    labels.sort_unstable();
    if !labels.iter().enumerate().all(|(i, &v)| v == i as i128) {
        return None;
    }

    // Bound the (possibly unbounded) table by the highest resume index the function stores:
    // the dense states must run EXACTLY `0..=max_state`. A higher top label is a spurious
    // entry read past the real table's end; a lower one means the table's last state was
    // dropped (unmapped target / truncated section) — both are wrong, so require an exact
    // match. (Skipped only when no such store is found — e.g. an aarch64 register store —
    // falling back to the contiguity check alone.)
    if let Some(max_state) = max_resume_index_store(cfg, index_offset, index_size, frame_slots) {
        let max_label = labels.last().copied().unwrap_or(0);
        if max_label != i128::from(max_state) {
            return None;
        }
    }

    // Unique target blocks, ordered by each case's smallest resume-state index, so the
    // dispatch's successors can be populated even when the CFG builder left them empty.
    let mut ordered: Vec<(i128, BasicBlockId)> = info
        .cases
        .iter()
        .filter_map(|(vs, block)| vs.iter().min().map(|&m| (m, *block)))
        .collect();
    ordered.sort_by_key(|(min_label, _)| *min_label);
    let mut targets: Vec<BasicBlockId> = Vec::new();
    for (_, block) in ordered {
        if !targets.contains(&block) {
            targets.push(block);
        }
    }
    Some(targets)
}

/// The largest resume-index value the function stores into the FRAME field
/// `frame->__resume_index` (`mov byte [framereg + index_offset], N`), i.e. the highest state
/// the coroutine ever arms for a later resume. Used to bound an unbounded resume jump table.
///
/// The store's base register must PROVABLY hold the frame pointer (reloaded from a frame
/// spill slot within the same block), so an unrelated `[obj + index_offset] = N` store to a
/// different object that merely shares the offset/width does not contribute. `None` if no
/// such frame-field immediate store is found (e.g. an aarch64 register store).
fn max_resume_index_store(
    cfg: &ControlFlowGraph,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> Option<i64> {
    let mut max: Option<i64> = None;
    for block in cfg.blocks() {
        // Registers currently holding a reloaded frame pointer, tracked per block.
        let mut frame_regs: Vec<String> = Vec::new();
        for inst in &block.instructions {
            match inst.operation {
                Operation::Move | Operation::Load => {
                    match (inst.operands.first(), inst.operands.get(1)) {
                        // `reg <- [framebase - K]`: a frame-pointer reload.
                        (Some(Operand::Register(d)), Some(Operand::Memory(m))) => {
                            let dc = canon_reg(d.name());
                            let is_frame_reload = m.base.as_ref().is_some_and(|b| {
                                is_frame_base_register(b.name())
                                    && m.index.is_none()
                                    && frame_slots.contains(&(canon_reg(b.name()), m.displacement))
                                    && d.size >= b.size
                            });
                            frame_regs.retain(|r| r != &dc);
                            if is_frame_reload {
                                frame_regs.push(dc);
                            }
                        }
                        // `[framereg + index_offset] <- imm`: a resume-index store.
                        (Some(Operand::Memory(m)), Some(Operand::Immediate(i))) => {
                            let to_frame_field = m.index.is_none()
                                && m.displacement == index_offset
                                && u16::from(m.size) == u16::from(index_size)
                                && (0..256).contains(&i.value)
                                && m.base
                                    .as_ref()
                                    .is_some_and(|b| frame_regs.contains(&canon_reg(b.name())));
                            if to_frame_field {
                                let v = i.value as i64;
                                max = Some(max.map_or(v, |mx: i64| mx.max(v)));
                            }
                        }
                        // `reg <- reg`: a copy propagates the frame-pointer status.
                        (Some(Operand::Register(d)), Some(Operand::Register(s))) => {
                            let dc = canon_reg(d.name());
                            let src_frame = frame_regs.contains(&canon_reg(s.name()));
                            frame_regs.retain(|r| r != &dc);
                            if src_frame {
                                frame_regs.push(dc);
                            }
                        }
                        // Any other `reg <- ...` write clears that register's frame status.
                        (Some(Operand::Register(d)), _) => {
                            let dc = canon_reg(d.name());
                            frame_regs.retain(|r| r != &dc);
                        }
                        _ => {}
                    }
                }
                Operation::Compare
                | Operation::Test
                | Operation::Jump
                | Operation::ConditionalJump
                | Operation::Return => {}
                _ => {
                    if let Some(Operand::Register(d)) = inst.operands.first() {
                        let dc = canon_reg(d.name());
                        frame_regs.retain(|r| r != &dc);
                    }
                }
            }
        }
    }
    max
}

/// Clone `cfg` and repair clang's no-op-jump `Return`s (reconnecting severed
/// resume-point bodies). Edges are NOT re-derived — the caller does that after any
/// terminator change, so a single `rederive_edges` pass cannot double-count.
fn repaired_cfg(
    cfg: &ControlFlowGraph,
    relocations: Option<&super::RelocationTable>,
) -> ControlFlowGraph {
    let mut rewritten = ControlFlowGraph::new(cfg.entry);
    for block in cfg.blocks() {
        rewritten.add_block(block.clone());
    }
    repair_nop_jump_returns(&mut rewritten, relocations);
    rewritten
}

/// Rebuild all successor/predecessor edges from each block's terminator.
fn rederive_edges(cfg: &mut ControlFlowGraph) {
    let ids: Vec<BasicBlockId> = cfg.block_ids().collect();
    for id in ids {
        let succs = cfg
            .block(id)
            .map(|b| b.terminator.successors())
            .unwrap_or_default();
        for succ in succs {
            cfg.add_edge(id, succ);
        }
    }
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

/// Whether the resume-index FRAME field is re-read by a CONTINUATION-DISPATCH block
/// other than the dispatch. A multi-state compare chain re-reads the field — off a
/// reloaded FRAME POINTER — in a further block that then branches on it for each extra
/// state test. So a block that ends in a conditional branch and reads `frame[off]` off a
/// frame pointer (reloaded from a spill slot in that block) is a continuation dispatch.
/// Requiring frame-base provenance (not merely the same offset/width) keeps an unrelated
/// same-offset load in a resume body (`obj->field_0x11` off some object) from spuriously
/// declining a valid two-state dispatch.
fn index_field_read_only_in_dispatch(
    cfg: &ControlFlowGraph,
    dispatch_id: BasicBlockId,
    index_offset: i64,
    index_size: u8,
    frame_slots: &[SpillSlot],
) -> bool {
    for block in cfg.blocks() {
        if block.id == dispatch_id
            || !matches!(block.terminator, BlockTerminator::ConditionalBranch { .. })
        {
            continue;
        }
        // Track frame reloads and index reads within the block; a frame-based index read
        // (which populates `holders`) marks this as a continuation dispatch.
        let mut frame_regs: Vec<String> = Vec::new();
        let mut holders: Vec<(String, u16)> = Vec::new();
        for inst in &block.instructions {
            update_index_holders(
                inst,
                index_offset,
                index_size,
                frame_slots,
                &mut frame_regs,
                &mut holders,
            );
            if !holders.is_empty() {
                return false;
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
                // The mask must PROVABLY preserve `index == 0`. A 2-state index uses
                // bit 0, so `& imm` keeps its zero-ness iff `imm` has bit 0 set; a
                // register mask (`and idx, reg`) or a bit-0-clearing immediate does not,
                // so drop the holder there. Every non-holder operand must be such a mask.
                let masks_preserve_zero = inst.operands.iter().all(|o| match o {
                    Operand::Register(r) => holder_width(holders, &canon_reg(r.name())).is_some(),
                    Operand::Immediate(imm) => (imm.value & 1) == 1,
                    _ => false,
                });
                holders.retain(|(r, _)| r != &dc);
                frame_regs.retain(|r| r != &dc);
                if let (Some(w), true) = (inherited, masks_preserve_zero) {
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

    /// Base address of the synthetic `.rodata` jump table used by the jump-table tests.
    const JT_BASE: u64 = 0x9000;

    /// A clang jump-table `.resume` dispatch:
    ///   entry:    mov [rbp-0x70], rdi ; jmp dispatch
    ///   dispatch: mov rax, [rbp-0x70]         ; frame reload
    ///             movzx eax, [rax + 0x11]     ; resume-index field read
    ///             mov   rax, [JT_BASE + rax*4]; jump-table load INDEXED BY the index
    ///             jmp   *rax                  ; IndirectJump(possible_targets)
    /// so the resume index provably drives the indirect jump.
    fn shape_jump_table_cfg(
        possible_targets: Vec<BasicBlockId>,
    ) -> ControlFlowGraph {
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let (rbp, rdi, rax, eax) = (r(5, 64), r(7, 64), r(0, 64), r(0, 32));
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

        let mut dispatch = BasicBlock::new(dispatch_id, 0xd12);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(eax),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        // `mov rax, [JT_BASE + rax*4]` — a readable absolute-SIB jump-table load, indexed by
        // the resume index (so `SwitchRecovery` can resolve the table from binary data).
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::sib(None, Some(rax), 4, JT_BASE as i64, 4)),
        ));
        dispatch.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets,
        };
        cfg.add_block(dispatch);
        cfg
    }

    /// A `BinaryDataContext` holding a 256-entry, 4-byte ABSOLUTE jump table at `JT_BASE`
    /// whose first entries point at `targets` (block start addresses); the rest are 0, which
    /// resolve to no block and are dropped, mirroring a real table read.
    /// Prepend `mov rax, [rbp-0x70]; mov byte [rax+0x11], value` to `block` so
    /// `max_resume_index_store` sees the frame reload + resume-index store (frame slot
    /// `(rbp, -0x70)`, matching `shape_jump_table_cfg`).
    fn set_max_resume_store(block: &mut BasicBlock, value: i128) {
        let (rbp, rax) = (r(5, 64), r(0, 64));
        block.instructions.insert(
            0,
            mov(
                Operand::Register(rax),
                Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            ),
        );
        block.instructions.insert(
            1,
            mov(
                Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
                Operand::Immediate(hexray_core::Immediate { value, size: 8, signed: false }),
            ),
        );
    }

    fn jump_table_binary(targets: &[u32]) -> BinaryDataContext {
        let mut data = vec![0u8; 256 * 4];
        for (i, &t) in targets.iter().enumerate() {
            data[i * 4..i * 4 + 4].copy_from_slice(&t.to_le_bytes());
        }
        let mut ctx = BinaryDataContext::new();
        ctx.add_section(JT_BASE, data);
        ctx
    }

    #[test]
    fn rewrite_shape_a_produces_indirect_switch_dispatch() {
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1);
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));

        let rewritten = rewrite_clang_resume_dispatch(&cfg, None, None).expect("rewritten").cfg;
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
    fn rewrite_repairs_jump_table_but_keeps_terminator() {
        // A native IndirectJump dispatch (jump table) reaches switch recovery on its own, so
        // the rewrite repairs the (no-op-jump-severed) resume bodies but must NOT rebuild the
        // terminator. The table is READ from binary data (entries 0/1 -> r0/r1), proving the
        // dispatch switch will form with complete case labels.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_jump_table_cfg(vec![]);
        // Give the resume blocks a non-zero span so the read table's target addresses map.
        let mut b0 = BasicBlock::new(r0, 0x50e);
        b0.end = 0x510;
        let mut b1 = BasicBlock::new(r1, 0x608);
        b1.end = 0x610;
        cfg.add_block(b0);
        cfg.add_block(b1);
        let ctx = jump_table_binary(&[0x50e, 0x608]);
        let out = rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx))
            .expect("jump-table repaired");
        // The dispatch keeps its original IndirectJump terminator, now with its
        // `possible_targets` populated from the resolved table.
        match &out.cfg.block(BasicBlockId::new(1)).unwrap().terminator {
            BlockTerminator::IndirectJump { possible_targets, .. } => {
                assert!(possible_targets.contains(&r0) && possible_targets.contains(&r1));
            }
            other => panic!("expected IndirectJump preserved, got {other:?}"),
        }
        // Edges are rederived so the dispatch connects to every resume state (otherwise
        // loop/dominator analysis would treat table-only-reachable states as unreachable).
        let succ = out.cfg.successors(BasicBlockId::new(1));
        assert!(succ.contains(&r0) && succ.contains(&r1), "dispatch must reach resume states");
        assert!(!out.two_way_default, "jump table keeps explicit cases");
    }

    #[test]
    fn rewrite_declines_table_longer_than_max_resume_store() {
        // The function only ever stores resume index 1 (`mov byte [rax+0x11], 1`), so the
        // highest dispatchable state is 1. A read table with a THIRD entry (state 2, from a
        // garbage word past the real table that happens to map) exceeds that bound and must
        // be declined rather than committing a spurious case.
        let (r0, r1, r2) = (BasicBlockId::new(2), BasicBlockId::new(3), BasicBlockId::new(4));
        let mut cfg = shape_jump_table_cfg(vec![]);
        for (id, start) in [(r0, 0x50e_u64), (r1, 0x608), (r2, 0x700)] {
            let mut b = BasicBlock::new(id, start);
            b.end = start + 2;
            cfg.add_block(b);
        }
        // A body block arms resume index 1 (`mov rax, [rbp-0x70]; mov byte [rax+0x11], 1`),
        // so the max dispatchable state is 1.
        set_max_resume_store(cfg.block_mut(r0).unwrap(), 1);
        let ctx = jump_table_binary(&[0x50e, 0x608, 0x700]); // 3 states, but max store is 1
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx)).is_none(),
            "a table longer than the max resume-index store must decline"
        );
    }

    #[test]
    fn rewrite_declines_table_shorter_than_max_resume_store() {
        // The function stores resume index 2 (`mov byte [rax+0x11], 2`), so state 2 exists —
        // but the read table only reaches state 1 (its last entry was dropped/unmapped). The
        // dense `[0,1]` prefix must be rejected rather than committing a switch missing state 2.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_jump_table_cfg(vec![]);
        let mut b0 = BasicBlock::new(r0, 0x50e);
        b0.end = 0x510;
        let mut b1 = BasicBlock::new(r1, 0x608);
        b1.end = 0x610;
        cfg.add_block(b0);
        cfg.add_block(b1);
        // A body block arms resume index 2, so state 2 exists.
        set_max_resume_store(cfg.block_mut(r0).unwrap(), 2);
        // Only 2 mapped entries (states 0,1); state 2's target (0x700) has no block.
        let ctx = jump_table_binary(&[0x50e, 0x608, 0x700]);
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx)).is_none(),
            "a table missing the max resume state must decline"
        );
    }

    #[test]
    fn rewrite_completes_incomplete_possible_targets() {
        // The CFG builder populated `possible_targets` but MISSED r1. The resolved table
        // (r0, r1) must be merged in so every resume state is connected.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_jump_table_cfg(vec![r0]); // incomplete: r1 missing
        let mut b0 = BasicBlock::new(r0, 0x50e);
        b0.end = 0x510;
        let mut b1 = BasicBlock::new(r1, 0x608);
        b1.end = 0x610;
        cfg.add_block(b0);
        cfg.add_block(b1);
        let ctx = jump_table_binary(&[0x50e, 0x608]);
        let out = rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx)).expect("resolved");
        let succ = out.cfg.successors(BasicBlockId::new(1));
        assert!(
            succ.contains(&r0) && succ.contains(&r1),
            "the missing resolved target must be merged in, got {succ:?}"
        );
    }

    #[test]
    fn rewrite_reads_grouped_duplicate_table_entries() {
        // States 0 and 2 both resume at r0, state 1 at r1: `[r0, r1, r0]`. Reading the table
        // groups the duplicate into `case [0,2] -> r0`, so all three states are covered
        // (dense 0..2) — the deduped-`possible_targets` path would have dropped state 2.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_jump_table_cfg(vec![]);
        let mut b0 = BasicBlock::new(r0, 0x50e);
        b0.end = 0x510;
        let mut b1 = BasicBlock::new(r1, 0x608);
        b1.end = 0x610;
        cfg.add_block(b0);
        cfg.add_block(b1);
        let ctx = jump_table_binary(&[0x50e, 0x608, 0x50e]);
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx)).is_some(),
            "a dense table with duplicate targets must resolve via the real read"
        );
    }

    #[test]
    fn rewrite_declines_unresolvable_jump_table() {
        // A jump table indexed by the resume field (linkage holds) but with no binary data to
        // read the `.rodata` table from is genuinely unresolvable: the deduped
        // `possible_targets` fallback is NOT accepted (it can drop states), so no complete
        // dispatch switch is proven. The rewrite must decline rather than commit an incorrect
        // `frame->__resume_index` switch.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_jump_table_cfg(vec![r0, r1]); // targets known, but table unreadable
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, None).is_none(),
            "a jump table whose entries can't be read must decline, not use deduped targets"
        );
    }

    #[test]
    fn rewrite_declines_jump_table_not_indexed_by_resume_field() {
        // A `.resume` clone whose tail reads a small frame field but whose indirect jump is
        // driven by something ELSE (no table load indexed by the resume index) is not a real
        // resume dispatch. Even with resolvable targets, the rewrite must decline so the
        // naming pass can't rename an unrelated computed switch as `frame->__resume_index`.
        let (r0, r1) = (BasicBlockId::new(2), BasicBlockId::new(3));
        let mut cfg = shape_a_cfg(r0, r1); // reads [rax+0x11] but no table load using it
        cfg.add_block(BasicBlock::new(r0, 0x50e));
        cfg.add_block(BasicBlock::new(r1, 0x608));
        cfg.block_mut(BasicBlockId::new(1)).unwrap().terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(r(1, 64)), // jumps on rcx, unrelated to the index read
            possible_targets: vec![r0, r1],
        };
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, None).is_none(),
            "a jump not indexed by the resume field must decline"
        );
    }

    // A dispatch block that reloads the frame ptr and reads the resume index into `eax`,
    // then runs `tail`, with `terminator`. `frame_slots` = [(rbp, -0x70)].
    fn index_read_dispatch(tail: Vec<Instruction>, terminator: BlockTerminator) -> (BasicBlock, Vec<SpillSlot>) {
        let (rbp, rax, eax) = (r(5, 64), r(0, 64), r(0, 32));
        let mut b = BasicBlock::new(BasicBlockId::new(1), 0xd12);
        b.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        b.instructions.push(mov(
            Operand::Register(eax),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        b.instructions.extend(tail);
        b.terminator = terminator;
        (b, vec![(canon_reg(rbp.name()), -0x70)])
    }

    fn op(mnem: &str, operation: Operation, operands: Vec<Operand>) -> Instruction {
        Instruction::new(0, 1, vec![], mnem)
            .with_operation(operation)
            .with_operands(operands)
    }

    #[test]
    fn linkage_declines_direct_indexed_jump_terminator() {
        // `jmp *table(,%idx,8)` — the indexed memory operand is on the terminator itself.
        // `SwitchRecovery` only scans block instructions for the table base, so it can't
        // resolve this form; the linkage must therefore not accept it (else the rewrite would
        // claim recovery the resolver then declines). clang -O0 never emits this form.
        let (rcx, rax) = (r(1, 64), r(0, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![],
            BlockTerminator::IndirectJump {
                target: Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 8, 0, 8)),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_follows_aarch64_store_spill_reload() {
        // aarch64 spills the index via `str`/`Store` (source-first operands), reloads it,
        // then loads the table. The Store must be recorded as a spill, not a clobber.
        let (rbp, rax, rcx) = (r(5, 64), r(0, 64), r(1, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                // str rax, [rbp-0x120]   (Store: [src, mem])
                op(
                    "str",
                    Operation::Store,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::base_disp(rbp, -0x120, 8)),
                    ],
                ),
                // ldr rax, [rbp-0x120]
                op(
                    "ldr",
                    Operation::Load,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::base_disp(rbp, -0x120, 8)),
                    ],
                ),
                // ldr rax, [rcx + rax*8]  (table load indexed by the index)
                op(
                    "ldr",
                    Operation::Load,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 8, 0, 8)),
                    ],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_accepts_lea_materialized_target() {
        // clang can fuse the base-add: `movsxd rax,[rcx+rax*4]; lea rax,[rcx+rax]; jmp *rax`.
        // The LEA (not an `add`) forms the absolute target from the table-loaded value.
        let (rcx, rax) = (r(1, 64), r(0, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                // movsxd rax, [rcx + rax*4]  (table load)
                op(
                    "movsxd",
                    Operation::SignExtend,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                    ],
                ),
                // lea rax, [rcx + rax]  (absolute target = base + table result)
                op(
                    "lea",
                    Operation::LoadEffectiveAddress,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 1, 0, 8)),
                    ],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_when_target_overwritten_by_immediate_move() {
        // `movsxd rax,[table+idx*4]; mov rax, 0; jmp *rax` — the immediate move overwrites
        // the table target, so the jump is no longer index-driven.
        let (rcx, rax) = (r(1, 64), r(0, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                op(
                    "movsxd",
                    Operation::SignExtend,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                    ],
                ),
                // mov rax, 0  (immediate source: still writes rax, clearing its target status)
                mov(
                    Operand::Register(rax),
                    Operand::Immediate(hexray_core::Immediate { value: 0, size: 8, signed: false }),
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_when_target_overwritten_by_non_memory_lea() {
        // An `lea` whose second operand is not a `[base+index]` memory form still writes its
        // destination, so a table target previously there is cleared.
        let (rcx, rax, rbx) = (r(1, 64), r(0, 64), r(3, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                op(
                    "movsxd",
                    Operation::SignExtend,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                    ],
                ),
                // lea rax, rbx  (non-memory second operand — clobbers rax)
                op(
                    "lea",
                    Operation::LoadEffectiveAddress,
                    vec![Operand::Register(rax), Operand::Register(rbx)],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_sub_target_adjustment() {
        // `movsxd rax,[table+idx*4]; sub rax, rcx; jmp rax` — the resolver models
        // `table_base + entry`, never a subtraction, so a `sub` adjustment must not keep the
        // register as a jump target (the resolver would wire cases to the wrong addresses).
        let (rcx, rax) = (r(1, 64), r(0, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                op(
                    "movsxd",
                    Operation::SignExtend,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                    ],
                ),
                op(
                    "sub",
                    Operation::Sub,
                    vec![Operand::Register(rax), Operand::Register(rcx)],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_subregister_index_read() {
        // `mov al, [frame+0x11]` defines only the low 8 bits; using the full `rax` as the
        // table index would read stale upper bits, so this is not a valid index.
        let (rax, al, rcx, rbp) = (r(0, 64), r(0, 8), r(1, 64), r(5, 64));
        let mut b = BasicBlock::new(BasicBlockId::new(1), 0xd12);
        b.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        // mov al, [rax+0x11]  — subregister (8-bit) read
        b.instructions.push(mov(
            Operand::Register(al),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 1)),
        ));
        // mov rax, [rcx + rax*4]  (table load indexed by the full, partly-stale rax)
        b.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
        ));
        b.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        let slots = vec![(canon_reg(rbp.name()), -0x70)];
        assert!(!dispatch_jump_indexed_by_resume_read(&b, 0x11, 1, &slots));
    }

    #[test]
    fn rewrite_declines_two_byte_index_jump_table() {
        // A 2-byte resume index could address > 256 states, but the resolver has no bounds
        // check and defaults to 256 entries — committing would truncate the higher states.
        // Build a jump-table dispatch whose index read is 2 bytes and confirm it declines.
        let (rbp, rdi, rax, eax) = (r(5, 64), r(7, 64), r(0, 64), r(0, 32));
        let entry_id = BasicBlockId::new(0);
        let dispatch_id = BasicBlockId::new(1);
        let mut cfg = ControlFlowGraph::new(entry_id);
        let mut entry = BasicBlock::new(entry_id, 0x400);
        entry.instructions.push(mov(
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
            Operand::Register(rdi),
        ));
        entry.terminator = BlockTerminator::Jump { target: dispatch_id };
        cfg.add_block(entry);
        let mut dispatch = BasicBlock::new(dispatch_id, 0xd12);
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::base_disp(rbp, -0x70, 8)),
        ));
        // movzwl eax, [rax+0x11]  — a 2-byte index read
        dispatch.instructions.push(mov(
            Operand::Register(eax),
            Operand::Memory(MemoryRef::base_disp(rax, 0x11, 2)),
        ));
        dispatch.instructions.push(mov(
            Operand::Register(rax),
            Operand::Memory(MemoryRef::sib(None, Some(rax), 4, JT_BASE as i64, 4)),
        ));
        dispatch.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(dispatch);
        let mut b0 = BasicBlock::new(BasicBlockId::new(2), 0x50e);
        b0.end = 0x510;
        let mut b1 = BasicBlock::new(BasicBlockId::new(3), 0x608);
        b1.end = 0x610;
        cfg.add_block(b0);
        cfg.add_block(b1);
        let ctx = jump_table_binary(&[0x50e, 0x608]);
        assert!(
            rewrite_clang_resume_dispatch(&cfg, None, Some(&ctx)).is_none(),
            "a 2-byte index jump table must decline (table size can't be bounded)"
        );
    }

    #[test]
    fn linkage_declines_three_operand_add_overwriting_target() {
        // aarch64 `add x0, x2, #8` fully OVERWRITES x0 (it is not read), so a table target
        // previously in x0 is gone. `br x0` then jumps to an unrelated address.
        let (rcx, rax, rdx) = (r(1, 64), r(0, 64), r(2, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                // ldr rax, [rcx + rax*8]  (table load -> rax is a target)
                op(
                    "ldr",
                    Operation::Load,
                    vec![
                        Operand::Register(rax),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 8, 0, 8)),
                    ],
                ),
                // add rax, rdx, #8  (3-operand: rax := rdx + 8, overwriting the target)
                op(
                    "add",
                    Operation::Add,
                    vec![
                        Operand::Register(rax),
                        Operand::Register(rdx),
                        Operand::Immediate(hexray_core::Immediate { value: 8, size: 8, signed: false }),
                    ],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_reload_after_slot_overwritten() {
        // `mov [slot], idx ; mov [slot], 0 ; mov rax, [slot]` — the slot no longer holds the
        // index when reloaded, so the reload must NOT be treated as the resume index.
        let (rbp, rax, rcx) = (r(5, 64), r(0, 64), r(1, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                // mov [rbp-0x120], eax  (spill index)
                mov(
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x120, 8)),
                    Operand::Register(r(0, 32)),
                ),
                // mov [rbp-0x120], 0   (overwrite the slot with a non-index value)
                mov(
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x120, 8)),
                    Operand::Immediate(hexray_core::Immediate { value: 0, size: 8, signed: false }),
                ),
                // mov rax, [rbp-0x120]  (reload — NOT the index any more)
                mov(
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x120, 8)),
                ),
                // mov rax, [rcx + rax*4]  (indexed load using the stale value)
                mov(
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rax),
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
    }

    #[test]
    fn linkage_declines_unrelated_indexed_load_then_other_jump() {
        // An indexed load USES the index register but its result never reaches the jump; the
        // indirect jump goes through an unrelated register. Must NOT be taken as a dispatch.
        let (rcx, rax, rdx, rsi) = (r(1, 64), r(0, 64), r(2, 64), r(6, 64));
        let (dispatch, slots) = index_read_dispatch(
            vec![
                // mov rdx, [rcx + rax*4]  — an indexed load into rdx (unrelated to the jump)
                op(
                    "mov",
                    Operation::Move,
                    vec![
                        Operand::Register(rdx),
                        Operand::Memory(MemoryRef::sib(Some(rcx), Some(rax), 4, 0, 4)),
                    ],
                ),
            ],
            BlockTerminator::IndirectJump {
                target: Operand::Register(rsi), // jumps through rsi, not the table result
                possible_targets: vec![],
            },
        );
        assert!(!dispatch_jump_indexed_by_resume_read(&dispatch, 0x11, 1, &slots));
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
        let rewritten = rewrite_clang_resume_dispatch(&cfg, None, None).expect("rewritten").cfg;
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
        assert!(rewrite_clang_resume_dispatch(&cfg, None, None).is_none());
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
        assert!(rewrite_clang_resume_dispatch(&cfg, None, None).is_none());
    }

    fn imm1(bits: u8) -> Operand {
        Operand::Immediate(hexray_core::Immediate {
            value: 1,
            size: bits,
            signed: false,
        })
    }

    #[test]
    fn field_read_guard_ignores_unrelated_conditional_load() {
        // A same-offset load off a NON-frame object (`obj->field_0x11` via rcx), even in
        // a conditional-branch block, must NOT disable recovery — it is not the index.
        let dispatch = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(dispatch);
        cfg.add_block(BasicBlock::new(dispatch, 0x82e));
        let mut body = BasicBlock::new(BasicBlockId::new(1), 0x600);
        body.instructions.push(mov(
            Operand::Register(r(2, 8)),
            Operand::Memory(MemoryRef::base_disp(r(1, 64), 0x11, 1)),
        ));
        body.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(body);
        assert!(index_field_read_only_in_dispatch(
            &cfg,
            dispatch,
            0x11,
            1,
            &x_frame_slots()
        ));
    }

    #[test]
    fn field_read_guard_rejects_frame_based_continuation_reread() {
        // A block that reloads the frame and re-reads `frame[0x11]` then branches is a
        // continuation dispatch (a multi-state chain) -> decline.
        let dispatch = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(dispatch);
        cfg.add_block(BasicBlock::new(dispatch, 0x82e));
        let mut cont = BasicBlock::new(BasicBlockId::new(1), 0x600);
        cont.instructions.push(frame_reload()); // mov rax,[rbp-0x70]
        cont.instructions.push(read_index()); // mov al,[rax+0x11]
        cont.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(cont);
        assert!(!index_field_read_only_in_dispatch(
            &cfg,
            dispatch,
            0x11,
            1,
            &x_frame_slots()
        ));
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
    fn zero_compare_rejects_register_masked_index() {
        // `mov al,[frame+0x11]; and al, dl; test al,al` tests (index & dl)==0 — an
        // unproven register mask, so it must NOT be accepted as an index-zero dispatch.
        let dl = r(2, 8);
        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x82e);
        block.instructions.push(frame_reload());
        block.instructions.push(read_index());
        block.instructions.push(
            Instruction::new(0, 2, vec![], "and")
                .with_operation(Operation::And)
                .with_operands(vec![Operand::Register(r(0, 8)), Operand::Register(dl)]),
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
