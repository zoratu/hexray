//! Function signature recovery from calling conventions.
//!
//! This module provides:
//! - Calling convention definitions for x86_64 System V, Windows x64, and ARM64 AAPCS
//! - Function signature recovery by analyzing register usage patterns
//! - Parameter location tracking (register vs. stack)
//! - Return type inference from return register usage
//!
//! # Calling Conventions
//!
//! ## x86_64 System V ABI (Linux/macOS/BSD)
//! - Integer args: RDI, RSI, RDX, RCX, R8, R9
//! - Float args: XMM0-XMM7
//! - Return: RAX (int), XMM0 (float)
//! - Callee-saved: RBX, RBP, R12-R15
//!
//! ## x86_64 Windows ABI
//! - Integer args: RCX, RDX, R8, R9
//! - Float args: XMM0-XMM3
//! - Return: RAX (int), XMM0 (float)
//! - Callee-saved: RBX, RBP, RDI, RSI, R12-R15
//!
//! ## ARM64 AAPCS
//! - Integer args: X0-X7
//! - Float args: V0-V7 (D0-D7)
//! - Return: X0 (int), V0/D0 (float)
//! - Callee-saved: X19-X28, X29 (FP), X30 (LR)
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::decompiler::signature::{SignatureRecovery, CallingConvention};
//!
//! let recovery = SignatureRecovery::new(CallingConvention::SystemV);
//! let signature = recovery.analyze(&cfg);
//!
//! // Produces: int64_t function(int64_t arg0, int64_t arg1, int32_t arg2)
//! ```

use super::expression::{BinOpKind, Expr, ExprKind, VarKind, Variable};
use super::structurer::{StructuredCfg, StructuredNode};
use super::{BinaryDataContext, RelocationTable, SymbolTable};
use hexray_core::{ControlFlowGraph, Operand, Operation, SymbolKind};
use hexray_types::{
    builtin::{load_libc_functions, load_linux_types, load_posix_types},
    CType, TypeDatabase,
};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;

mod known_funcs;
mod types;
use known_funcs::get_known_function_params;
pub(crate) use known_funcs::known_function_param_count;
pub use types::{
    CallingConvention, FunctionSignature, ParamType, Parameter, ParameterLocation,
    ParameterUsageHints,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrintfLengthModifier {
    None,
    CharChar,
    Short,
    Long,
    LongLong,
    IntMax,
    Size,
    PtrDiff,
}

/// Signature recovery engine.
///
/// Analyzes a structured CFG to recover function signatures by:
/// 1. Identifying which argument registers are read before being written
/// 2. Tracking register sizes to infer parameter types
/// 3. Detecting return value usage before the return instruction
/// 4. Analyzing usage patterns for better type inference
#[derive(Debug)]
pub struct SignatureRecovery {
    /// The calling convention to use.
    convention: CallingConvention,
    /// Registers that have been read (used as arguments).
    read_regs: HashSet<String>,
    /// Registers that have been written (clobbered).
    written_regs: HashSet<String>,
    /// Size hints for registers (from memory operations).
    reg_sizes: HashMap<String, u8>,
    /// Best-effort value-width hints for lifted locals/temporaries.
    value_sizes: HashMap<String, u8>,
    /// Whether a return register was set before return.
    return_value_set: bool,
    /// Size of the return value.
    return_size: u8,
    /// Whether a float return register was used.
    float_return: bool,
    /// An explicit `return ...` expression referenced a float ABI register.
    float_abi_return_expr_observed: bool,
    /// Float ABI registers observed in expressions even if the value was rewritten before use.
    observed_float_arg_regs: HashSet<String>,
    /// Float argument registers detected by scanning the raw instruction stream
    /// (`(index, reg_name, size_bytes)`). Seeds the float-parameter recovery for
    /// the `-O0` spill-only case where the xmm spill is pruned before structured
    /// analysis runs. Set via [`with_float_arg_seeds`]; survives `analyze`'s reset.
    float_arg_seeds: Vec<(usize, String, u8)>,
    /// Float return size (bytes) detected from the raw instruction stream, for
    /// the spill-only case where the `xmm0` result is pruned before structured
    /// analysis. Set via [`with_float_return_seed`]; survives `analyze`'s reset.
    float_return_seed: Option<u8>,
    /// Integer SSE/AVX-style opaque operations observed in the function body.
    integer_simd_ops_observed: bool,
    /// The final scalar result is extracted from a float ABI register into the integer return.
    return_from_integer_simd_lane: bool,
    /// Explicit scalar-literal returns seen alongside opaque integer SIMD returns.
    integer_simd_scalar_literal_return_size_hint: Option<u8>,
    /// Explicit non-float scalar returns seen alongside opaque integer SIMD returns.
    integer_simd_scalar_return_size_hint: Option<u8>,
    /// Direct argument-register copies that shadow an earlier ABI parameter.
    arg_register_copy_sources: HashMap<usize, usize>,
    /// x87 stack operations were observed in the function body.
    x87_ops_observed: bool,
    /// Entry-like x87 input was observed via ST(0).
    x87_st0_input_observed: bool,
    /// Width of the float-bank destination during the current RHS
    /// walk (4 = single, 8 = double, 16 = SIMD width), or 0 when the
    /// current assignment's destination isn't a float-bank register.
    /// Used by the Deref / ArrayAccess hint propagation to pick
    /// `Float(n)` element types for SSE-loaded pointer args instead
    /// of the default `SignedInt(64)` — so `movsd xmm2, [arr+i*8]`
    /// recovers as `double *arr`, not `int64_t *arr`.
    current_rhs_float_dest_size: u8,
    /// Stack argument offsets consumed by x87 operations.
    x87_stack_arg_offsets: BTreeSet<i64>,
    /// Recovered function-pointer return type when applicable.
    return_function_pointer: Option<ParamType>,
    /// Candidate return type inferred from tail-position call forwarding.
    tail_call_return_type: Option<ParamType>,
    /// Minimum arity required by a pure known tail-call wrapper.
    tail_call_min_arity: Option<usize>,
    /// Whether the return value is likely a pointer based on usage patterns.
    return_is_pointer: bool,
    /// Human-readable reasons that led to return type inference.
    return_provenance: Vec<String>,
    /// Confidence in return type inference.
    return_confidence: u8,
    /// Parameter names assigned from stack slot analysis.
    param_names: HashMap<usize, String>,
    /// Stack offsets each argument register was spilled to in the prologue
    /// (pattern `*(sp + offset) = argN` while the register is still unwritten).
    /// Used to gate the `var_{offset}` parameter renaming so it only fires on
    /// reloads of the actual home slot, not on later reuse of the register as
    /// a scratch temp for an unrelated stack local (e.g. a loop counter).
    arg_spill_offsets: HashMap<usize, HashSet<i128>>,
    /// Stack offsets where the prologue arg-spill slot has been
    /// overwritten by a non-spill store later in the body. Once a
    /// slot is invalidated, the spill-slot → param bridge in
    /// [`Self::spilled_arg_register_from_var_name`] must stop using
    /// it: subsequent loads from that offset are NOT the original
    /// argument value. Codex review on PR #32 pass 9.
    invalidated_spill_offsets: HashSet<i128>,
    /// Prologue spill observations from the raw CFG, used to recover
    /// the mixed int/float source declaration order — at `-O0` the
    /// compiler spills every parameter register in source order, so
    /// `double scale_sum(double x, int n)` puts xmm0 at `[rbp-8]`
    /// (source-first) and edi at `[rbp-12]` (source-second), and
    /// the recovered signature must follow. Seeded via
    /// [`Self::with_param_spill_order`] before [`Self::analyze`].
    /// See [`scan_param_spill_order`] for the producer.
    param_spill_order: Vec<ParamSpillObservation>,
    /// Named-float count read from the raw `__va_list_tag` `fp_offset`
    /// initialiser, seeded via [`Self::with_va_list_float_count_seed`]. Used as
    /// a fallback when the structurer has already collapsed the `va_arg`
    /// diamonds (deleting the `fp_offset` store the structured-body resolver
    /// reads). See [`scan_sysv_va_list_named_float_count`].
    va_list_float_count_seed: Option<usize>,
    /// aarch64 AAPCS variadic `(named_gp, named_fp)` counts recovered from the
    /// `__va_list` tag in the prologue (see [`scan_aapcs_va_list`]). `Some`
    /// marks the function variadic; the named counts cap the recovered integer
    /// and float parameters so the GP/SIMD register-save area isn't surfaced.
    aapcs_va_list_counts: Option<(usize, usize)>,
    /// Explicit parameter type overrides inferred from wrappers/patterns.
    param_type_overrides: HashMap<usize, ParamType>,
    /// DWARF parameter names in declaration order.
    dwarf_param_names: Vec<String>,
    /// Usage hints for parameters (indexed by arg register index).
    param_hints: HashMap<usize, ParameterUsageHints>,
    /// Aliases from local variable name to candidate function-pointer parameter indices.
    ///
    /// A single alias can map to multiple argument indices when lifted temporaries are reused.
    /// We only treat alias mappings as precise when the candidate set is unambiguous.
    function_pointer_aliases: HashMap<String, BTreeSet<usize>>,
    /// Most recently observed alias-to-parameter mapping for flow-sensitive disambiguation.
    function_pointer_alias_latest: HashMap<String, usize>,
    /// Latest value-copy edge (`lhs = rhs`) used for alias-chain parameter recovery.
    value_alias_latest: HashMap<String, String>,
    /// Names assigned within the recovered body (for local alias affinity checks).
    assigned_value_names: HashSet<String>,
    /// Pointer-typed locals derived from allocator and alias tracking.
    value_pointer_hints: HashSet<String>,
    /// Function-pointer typed locals derived from assignments/returns.
    value_function_pointer_types: HashMap<String, ParamType>,
    /// String functions for detection.
    string_functions: HashSet<&'static str>,
    /// Optional relocation table for resolving IndirectGot call targets.
    relocation_table: Option<RelocationTable>,
    /// Optional symbol table for resolving direct-call targets.
    symbol_table: Option<SymbolTable>,
    /// Optional inter-procedural summary database for signature hints.
    summary_database: Option<Arc<super::interprocedural::SummaryDatabase>>,
    /// Optional read-only binary data for resolving string-literal arguments.
    binary_data: Option<Arc<BinaryDataContext>>,
    /// Function name being analyzed (for known function lookup).
    current_func_name: Option<String>,
    /// Symbol kind for the function being analyzed when known.
    current_func_kind: Option<SymbolKind>,
    /// SysV `va_list.gp_offset` field slots initialized in the body.
    sysv_va_list_gp_offset_slots: HashSet<String>,
    /// SysV `va_list.fp_offset` field slots initialized in the body.
    sysv_va_list_fp_offset_slots: HashSet<String>,
    /// SysV `va_list` pointer field slots initialized in the body.
    sysv_va_list_pointer_slots: HashSet<String>,
    /// Set when a recovered `va_start(ap, last)` call is observed. The structurer
    /// collapses the SysV `va_arg` state machine and rewrites the slot setup into
    /// this call, which then stands in for the raw slot stores as the variadic
    /// (`...`) materialization signal.
    sysv_va_start_seen: bool,
    /// Fixed non-variadic prefix inferred for the current function.
    variadic_fixed_param_count: Option<usize>,
    /// Integer constants stored to frame slots, keyed by frame offset. Used to
    /// locate the SysV `__va_list_tag` by its full shape — `gp_offset` (8*k)
    /// at base `b`, `fp_offset` (48+16*f) at `b+4` — so the `fp_offset` value
    /// is read only from a genuine va_list, not an unrelated adjacent pair of
    /// constants that merely look like one (codex P2 on PR #46).
    sysv_stack_const_stores: HashMap<i64, i128>,
    /// Frame offsets of slots assigned a `stack_base + const` pointer (the
    /// `overflow_arg_area` / `reg_save_area` fields at `b+8` / `b+16` of the
    /// `__va_list_tag`), used to corroborate a candidate tag base.
    sysv_stack_pointer_stores: HashSet<i64>,
}

/// One observation of an argument register being spilled to a
/// stack slot in the function prologue. The vector returned by
/// [`scan_param_spill_order`] preserves instruction order, so the
/// FIRST entry is the FIRST source parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSpillObservation {
    /// Lowercase register name (`xmm0`, `rdi`, `edi`, `d0`, ...).
    pub register: String,
    /// Frame-relative stack offset where the spill landed.
    pub offset: i64,
}

/// Scan the raw instruction stream for parameter-register spills
/// in the function prologue.
///
/// At `-O0`, the compiler emits one spill per parameter register in
/// source-declaration order. By returning the spill observations in
/// instruction order, callers can reconstruct the mixed int/float
/// source order — `double scale_sum(double x, int n)` produces
/// `[(xmm0, -8), (edi, -16)]`, indicating the float arg was
/// source-first even though both `xmm0` (float bank index 0) and
/// `edi` (int bank index 0) would otherwise look interchangeable.
///
/// Conservative: stops scanning as soon as a non-spill, non-prologue
/// instruction is seen, so loop bodies don't pollute the ordering.
pub fn scan_param_spill_order(
    cfg: &ControlFlowGraph,
    convention: CallingConvention,
) -> Vec<ParamSpillObservation> {
    let mut result = Vec::new();
    let int_regs: HashSet<String> = convention
        .integer_arg_registers()
        .iter()
        .chain(convention.integer_arg_registers_32().iter())
        .map(|r| r.to_lowercase())
        .collect();
    let float_regs: HashSet<String> = convention
        .float_arg_registers()
        .iter()
        .map(|r| r.to_lowercase())
        .collect();
    let Some(entry) = cfg.entry_block() else {
        return result;
    };
    let mut seen_regs: HashSet<String> = HashSet::new();
    for inst in &entry.instructions {
        // Whitelist prologue scaffolding: push/pop, frame setup
        // (`mov rbp, rsp`), and stack pointer adjust (`sub rsp,
        // K`). These don't produce spill observations but they're
        // the only things that can appear between spills.
        let mnemonic = inst.mnemonic.to_ascii_lowercase();
        let is_prologue_scaffold = matches!(
            inst.operation,
            Operation::Push | Operation::Pop | Operation::Nop
        ) || mnemonic.starts_with("nop")
            || mnemonic.starts_with("endbr")
            || is_frame_setup_or_sp_adjust(inst);

        // Frame setup (`mov rbp, rsp`) and stack adjust both look
        // like `Operation::Move` with two register operands or
        // a register + immediate — we must skip them BEFORE the
        // operand-layout check (which would treat reg-reg as a
        // body-work break).
        if is_prologue_scaffold {
            continue;
        }

        let is_potential_spill = matches!(inst.operation, Operation::Store | Operation::Move);
        if !is_potential_spill {
            // Hit non-prologue body — stop scanning. Codex review
            // on PR #27 pass 1.
            break;
        }

        // Spills emit one of two operand layouts depending on
        // architecture:
        //   x86 `mov [mem], reg`:    [Memory(dst), Register(src)]
        //   aarch64 `str reg, [mem]`: [Register(src), Memory(dst)]
        //   aarch64 `stp r1, r2, [mem]`: [Reg, Reg, Memory] (pair)
        // Convention disambiguates: a reg→mem ordering on x86 is
        // actually a RELOAD (`mov edi, [rbp-12]`), not a spill, so
        // we'd misread it as an aarch64 STR if we accepted both
        // forms unconditionally. Codex review on PR #27 pass 3.
        let is_aarch64 = matches!(convention, CallingConvention::Aarch64);
        let observations = match (inst.operands.first(), inst.operands.get(1)) {
            (Some(Operand::Memory(mem)), Some(Operand::Register(src))) if !is_aarch64 => {
                if !is_frame_base_memory(mem) {
                    // Body store to a heap/global — stop scanning.
                    break;
                }
                vec![(mem.displacement, src.name().to_lowercase())]
            }
            (Some(Operand::Register(src)), Some(Operand::Memory(mem))) if is_aarch64 => {
                // aarch64 STR form.
                if !is_frame_base_memory(mem) {
                    break;
                }
                vec![(mem.displacement, src.name().to_lowercase())]
            }
            (Some(Operand::Register(src1)), Some(Operand::Register(src2))) if is_aarch64 => {
                // aarch64 STP — third operand is the memory dest.
                match inst.operands.get(2) {
                    Some(Operand::Memory(mem)) if is_frame_base_memory(mem) => {
                        let base = mem.displacement;
                        vec![
                            (base, src1.name().to_lowercase()),
                            (base + 8, src2.name().to_lowercase()),
                        ]
                    }
                    _ => break,
                }
            }
            // Everything else (x86 reload `mov reg, [mem]`, x86
            // reg-reg, aarch64 reg-imm, etc.) is body work — stop.
            _ => break,
        };

        for (offset, raw_reg_name) in observations {
            // Normalize register-file aliases to the ABI name:
            //   aarch64 `s0`/`q0`/`v0` → `d0` (float bank)
            //   x86_64  `dil`/`di`/`edi`/`rdi` → `rdi` (int bank
            //                                  ABI name)
            // Without normalization a `mov [rbp-8], dil` (narrow
            // char spill) would be silently dropped because
            // `dil` doesn't match any ABI argument-register name.
            // Codex review on PR #27 pass 7.
            let reg_name = if int_regs.contains(&raw_reg_name) || float_regs.contains(&raw_reg_name)
            {
                raw_reg_name
            } else if let Some(canonical) = canonicalize_int_arg_register(&raw_reg_name) {
                canonical
            } else {
                float_arg_abi_register(&raw_reg_name, convention)
            };
            if !int_regs.contains(&reg_name) && !float_regs.contains(&reg_name) {
                continue;
            }
            // De-dup: a reg spilled to multiple slots only counts
            // once (the FIRST observation, which is the prologue
            // spill).
            if seen_regs.insert(reg_name.clone()) {
                result.push(ParamSpillObservation {
                    register: reg_name,
                    offset,
                });
            }
        }
    }
    result
}

/// Whether `mem` is rbp/rsp/sp-relative (a frame-local stack slot,
/// not an arbitrary heap/global address).
fn is_frame_base_memory(mem: &hexray_core::MemoryRef) -> bool {
    if mem.index.is_some() {
        return false;
    }
    mem.base
        .as_ref()
        .map(|r| r.name().to_lowercase())
        .is_some_and(|n| {
            matches!(
                n.as_str(),
                // x86_64 / x86
                "rbp" | "ebp" | "bp" | "rsp" | "esp" | "sp"
                // aarch64: x29/fp is the frame pointer, x31 = sp.
                // `-O0` spills land at `[x29, #N]` after the
                // `mov x29, sp` setup. Codex review on PR #27
                // pass 5.
                | "x29" | "fp" | "x31"
            )
        })
}

/// Canonicalize an x86_64 integer argument register alias to its
/// 64-bit ABI name. Returns `Some("rdi")` for any of
/// `dil`/`di`/`edi`/`rdi`, and `None` for non-arg-register names.
/// Codex review on PR #27 pass 7.
fn canonicalize_int_arg_register(name: &str) -> Option<String> {
    let canonical = match name {
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdx" | "edx" | "dx" | "dl" => "rdx",
        "rcx" | "ecx" | "cx" | "cl" => "rcx",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        _ => return None,
    };
    Some(canonical.to_string())
}

/// Quick check for the standard x86_64 prologue setup instructions
/// `mov rbp, rsp` and `sub rsp, K`. Used to distinguish prologue
/// scaffolding from function-body work in [`scan_param_spill_order`].
fn is_frame_setup_or_sp_adjust(inst: &hexray_core::Instruction) -> bool {
    let mnemonic = inst.mnemonic.to_ascii_lowercase();
    if mnemonic != "mov" && mnemonic != "sub" && mnemonic != "add" {
        return false;
    }
    let Some(Operand::Register(dst)) = inst.operands.first() else {
        return false;
    };
    let dst_name = dst.name().to_lowercase();
    let is_frame_or_stack_dst = matches!(
        dst_name.as_str(),
        // x86_64 / x86 stack/frame
        "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp"
        // aarch64 stack/frame
        | "x29" | "fp" | "x31" | "wsp"
    );
    if !is_frame_or_stack_dst {
        return false;
    }
    // Verify the SOURCE is the stack pointer (for frame setup) or
    // an immediate (for stack adjustment). Without this, body work
    // like `mov rbp, rdi` (using rbp as a GPR under -fomit-frame-
    // pointer) would be misread as scaffolding and the scanner
    // would keep running into body stores. Codex review on PR #27
    // pass 6.
    match (
        mnemonic.as_str(),
        inst.operands.get(1),
        inst.operands.get(2),
    ) {
        // `mov frame_reg, stack_reg` — frame-pointer setup.
        ("mov", Some(Operand::Register(src)), _) => {
            matches!(
                src.name().to_lowercase().as_str(),
                "rsp" | "esp" | "sp" | "x31" | "wsp" | "rbp" | "x29"
            )
        }
        // `sub rsp, K` (x86 stack adjust, 2-operand).
        ("sub" | "add", Some(Operand::Immediate(_)), _) => true,
        // `add sp, sp, K` (aarch64 3-operand form).
        ("sub" | "add", Some(Operand::Register(src1)), Some(Operand::Immediate(_))) => {
            matches!(
                src1.name().to_lowercase().as_str(),
                "rsp" | "esp" | "sp" | "x31" | "wsp"
            )
        }
        _ => false,
    }
}

/// Scan the entry block's prologue for the SysV `__va_list_tag` initializer and
/// return the named-float parameter count encoded in its `fp_offset` field
/// (`fp_offset = 48 + 16 * named_floats`).
///
/// This reads the RAW instructions so the count survives even after the
/// structurer collapses the `va_arg` diamonds — that collapse deletes the
/// `fp_offset` store the structured-body resolver
/// ([`SignatureRecovery::resolve_sysv_named_float_count`]) relies on, which
/// would otherwise let the variadic FP register-save area leak back into the
/// signature (`int sum_ints(int n, ...)` regaining a spurious `double farg0`).
///
/// The tag is identified by an adjacent immediate-store pair in the prologue:
/// `gp_offset = 8*k` at frame slot `b` and `fp_offset = 48 + 16*f` at `b + 4`.
/// First-write-wins per slot, so a later `va_arg` mutation of the same field is
/// ignored. Returns `None` on non-SysV targets or when no tag is found.
pub fn scan_sysv_va_list_named_float_count(
    cfg: &ControlFlowGraph,
    convention: CallingConvention,
) -> Option<usize> {
    if !matches!(convention, CallingConvention::SystemV) {
        return None;
    }
    // Scan every block, not just the entry: a stack-protector or other early
    // branch splits the prologue, so the va_list-tag initializer stores can
    // land in a successor block rather than the entry.
    //
    // Collect, by frame offset, the immediate stores (the `gp_offset`/
    // `fp_offset` fields) and the register stores (the `overflow_arg_area` /
    // `reg_save_area` pointer fields — written from a register after a `lea`).
    let mut const_stores: HashMap<i64, i128> = HashMap::new();
    let mut pointer_offsets: HashSet<i64> = HashSet::new();
    for block in cfg.blocks() {
        for inst in &block.instructions {
            if !matches!(inst.operation, Operation::Store | Operation::Move) {
                continue;
            }
            let (Some(Operand::Memory(mem)), Some(src)) =
                (inst.operands.first(), inst.operands.get(1))
            else {
                continue;
            };
            if !is_frame_base_memory(mem) {
                continue;
            }
            match src {
                // First write wins: the `va_start` initialiser precedes any
                // later `va_arg` mutation of the same field.
                Operand::Immediate(imm) => {
                    const_stores.entry(mem.displacement).or_insert(imm.value);
                }
                Operand::Register(_) => {
                    pointer_offsets.insert(mem.displacement);
                }
                _ => {}
            }
        }
    }
    // Require the full 24-byte `__va_list_tag` shape — `gp_offset` (8*k) at base
    // `b`, `fp_offset` (48+16*f) at `b+4`, and pointer fields at `b+8`/`b+16` —
    // so an unrelated adjacent constant pair like `{8, 48}` can't be mistaken
    // for the tag (codex P2 on PR #48). Scan bases in sorted order so the
    // recovered count is deterministic.
    let mut bases: Vec<i64> = const_stores.keys().copied().collect();
    bases.sort_unstable();
    for base in bases {
        let Some(&gp) = const_stores.get(&base) else {
            continue;
        };
        if !(0..48).contains(&gp) || gp % 8 != 0 {
            continue;
        }
        let Some(&fp) = const_stores.get(&(base + 4)) else {
            continue;
        };
        if !((48..=176).contains(&fp) && fp % 16 == 0) {
            continue;
        }
        if pointer_offsets.contains(&(base + 8)) && pointer_offsets.contains(&(base + 16)) {
            return usize::try_from((fp - 48) / 16).ok();
        }
    }
    None
}

/// Canonicalize an aarch64 GP register name to its 64-bit form: `w{n}` and
/// `x{n}` alias the same physical register, so the `mov w0, …; str x0, …`
/// sequences that build the va_list tag must be tracked as one register.
fn aarch64_canon_reg(name: &str) -> String {
    let lower = name.to_lowercase();
    if let Some(num) = lower.strip_prefix('w') {
        if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
            return format!("x{num}");
        }
    }
    lower
}

/// True if `name` is an aarch64 frame/stack base register (`sp`, `x29`/`fp`).
fn is_aarch64_frame_base_register(name: &str) -> bool {
    matches!(name.to_lowercase().as_str(), "sp" | "x31" | "x29" | "fp")
}

/// Scan the prologue for the aarch64 AAPCS `__va_list` tag and recover the
/// named (non-variadic) GP and FP/SIMD parameter counts as `(named_gp,
/// named_fp)`. Returns `None` for a non-variadic function (no tag found).
///
/// The 32-byte tag is `{ void* __stack; void* __gr_top; void* __vr_top;
/// int __gr_offs; int __vr_offs; }`. `va_start` initialises
/// `__gr_offs = -(8 - named_gp) * 8` and `__vr_offs = -(8 - named_fp) * 16`, so
/// `named_gp = 8 - (-__gr_offs)/8` and `named_fp = 8 - (-__vr_offs)/16`.
///
/// Unlike the SysV tag, the offset fields are materialised via a register
/// (`movn w, #k` loads the negative `!k`; `str w, [slot]`) and the pointers via
/// `add x, sp, #N; str x, [slot]`, so this tracks simple per-block register
/// values. The full tag shape (three frame-pointer fields + the two offset
/// fields at the right relative positions) is required so an unrelated constant
/// can't be mistaken for the tag.
pub fn scan_aapcs_va_list(cfg: &ControlFlowGraph) -> Option<(usize, usize)> {
    #[derive(Clone, Copy)]
    enum RegVal {
        Imm(i128),
        FrameAddr,
    }
    let mut const_stores: HashMap<i64, i128> = HashMap::new();
    let mut pointer_offsets: HashSet<i64> = HashSet::new();
    for block in cfg.blocks() {
        let mut regs: HashMap<String, RegVal> = HashMap::new();
        for inst in &block.instructions {
            match inst.operation {
                Operation::Move => {
                    if let Some(Operand::Register(dst)) = inst.operands.first() {
                        let name = aarch64_canon_reg(dst.name());
                        if let Some(Operand::Immediate(imm)) = inst.operands.get(1) {
                            let mnemonic = inst.mnemonic.to_ascii_lowercase();
                            if mnemonic == "movk" {
                                // `movk reg, #k, lsl #s` overwrites the 16-bit
                                // field at shift `s`, keeping the rest — used to
                                // pack the two 32-bit offset fields into one
                                // x register (`mov x8, #-56; movk x8, #.., lsl #32`).
                                let shift = match inst.operands.get(2) {
                                    Some(Operand::Immediate(s)) => (s.value as u32) & 63,
                                    _ => 0,
                                };
                                let prev = match regs.get(&name) {
                                    Some(RegVal::Imm(v)) => *v as u64,
                                    _ => 0,
                                };
                                let field = (imm.value as u64 & 0xffff) << shift;
                                let merged = (prev & !(0xffff_u64 << shift)) | field;
                                regs.insert(name, RegVal::Imm(merged as i128));
                            } else {
                                // `movn reg, #k` loads `!k`; `mov`/`movz` load `k`.
                                let value = if mnemonic == "movn" {
                                    !imm.value
                                } else {
                                    imm.value
                                };
                                regs.insert(name, RegVal::Imm(value));
                            }
                        } else {
                            regs.remove(&name);
                        }
                    }
                }
                Operation::Add => {
                    if let (Some(Operand::Register(dst)), Some(Operand::Register(base))) =
                        (inst.operands.first(), inst.operands.get(1))
                    {
                        let name = aarch64_canon_reg(dst.name());
                        // The result is a frame address when `base` is a frame
                        // register OR already holds a frame address — so chained
                        // `add x8, sp, #32; add x8, x8, #112` (clang) propagates.
                        let base_is_frame = is_aarch64_frame_base_register(base.name())
                            || matches!(
                                regs.get(&aarch64_canon_reg(base.name())),
                                Some(RegVal::FrameAddr)
                            );
                        if base_is_frame {
                            regs.insert(name, RegVal::FrameAddr);
                        } else {
                            regs.remove(&name);
                        }
                    }
                }
                Operation::Store => {
                    let record = |off: i64,
                                  reg: &hexray_core::Register,
                                  consts: &mut HashMap<i64, i128>,
                                  ptrs: &mut HashSet<i64>| {
                        match regs.get(&aarch64_canon_reg(reg.name())) {
                            Some(RegVal::FrameAddr) => {
                                ptrs.insert(off);
                            }
                            Some(RegVal::Imm(v)) => {
                                if reg.size >= 64 {
                                    // A 64-bit register may pack the two adjacent
                                    // 32-bit offset fields (`mov`/`movk` then a
                                    // 64-bit store): low half at `off`, high half
                                    // at `off + 4`. (The tag-shape check below
                                    // discards an incidental split.)
                                    let bits = *v as u64;
                                    consts.entry(off).or_insert((bits as u32) as i128);
                                    consts
                                        .entry(off + 4)
                                        .or_insert(((bits >> 32) as u32) as i128);
                                } else {
                                    consts.entry(off).or_insert(*v);
                                }
                            }
                            None => {}
                        }
                    };
                    match (
                        inst.operands.first(),
                        inst.operands.get(1),
                        inst.operands.get(2),
                    ) {
                        // `str reg, [frame+disp]`.
                        (Some(Operand::Register(src)), Some(Operand::Memory(mem)), None) => {
                            if is_frame_base_memory(mem) {
                                record(
                                    mem.displacement,
                                    src,
                                    &mut const_stores,
                                    &mut pointer_offsets,
                                );
                            }
                        }
                        // `stp r1, r2, [frame+disp]` — r1 at disp, r2 at the next
                        // element (optimized prologues initialise the tag this
                        // way). The element stride is the register width: 8 for
                        // `stp x.., x..`, 4 for the 32-bit `stp w.., w..`.
                        (
                            Some(Operand::Register(r1)),
                            Some(Operand::Register(r2)),
                            Some(Operand::Memory(mem)),
                        ) => {
                            if is_frame_base_memory(mem) {
                                let stride = i64::from(r1.size / 8).max(1);
                                record(
                                    mem.displacement,
                                    r1,
                                    &mut const_stores,
                                    &mut pointer_offsets,
                                );
                                record(
                                    mem.displacement + stride,
                                    r2,
                                    &mut const_stores,
                                    &mut pointer_offsets,
                                );
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    // 32-bit offset fields may arrive sign-extended or as a raw u32; normalize.
    let as_i32 = |v: i128| -> i128 { (v as i32) as i128 };
    let mut gr_slots: Vec<i64> = const_stores.keys().copied().collect();
    gr_slots.sort_unstable();
    for gr_slot in gr_slots {
        let base = gr_slot - 24; // __gr_offs sits at tag base + 24
        let gr_offs = as_i32(*const_stores.get(&gr_slot)?);
        // Require STRICTLY-negative canonical offsets (`-(8 - named) * stride`
        // with `named < 8`). `0` would mean all 8 registers are named — which
        // is implausible for a variadic — and is also the sentinel gcc -O2
        // writes (`stp …, wzr`) for a COMPACTED save area when the matching
        // varargs class isn't consumed; treating that as `named = 8` would
        // fabricate eight fixed parameters (codex P1). Decline instead.
        if !(-64..0).contains(&gr_offs) || gr_offs % 8 != 0 {
            continue;
        }
        let Some(&vr_raw) = const_stores.get(&(base + 28)) else {
            continue;
        };
        let vr_offs = as_i32(vr_raw);
        if !(-128..0).contains(&vr_offs) || vr_offs % 16 != 0 {
            continue;
        }
        if pointer_offsets.contains(&base)
            && pointer_offsets.contains(&(base + 8))
            && pointer_offsets.contains(&(base + 16))
        {
            let named_gp = 8usize.checked_sub(usize::try_from(-gr_offs / 8).ok()?)?;
            let named_fp = 8usize.checked_sub(usize::try_from(-vr_offs / 16).ok()?)?;
            return Some((named_gp, named_fp));
        }
    }
    None
}

/// Scan the raw instruction stream for floating-point argument registers.
///
/// Returns the contiguous `xmm0..xmmN` prefix that is read before being written,
/// as `(index, reg_name, size_bytes)`. This recovers float parameters in the
/// `-O0` spill-only case (`movsd %xmm0, -8(%rbp)`) where the spill store is
/// pruned before the structured form that [`SignatureRecovery::analyze`] sees.
///
/// Detection is deliberately conservative — it only counts an xmm register used
/// as the *source* operand (operand 1) before any write — so it cannot mistake a
/// written-then-read temporary for an argument, and the contiguous-prefix rule
/// mirrors the SysV rule that float arguments fill `xmm0, xmm1, …` in order.
pub fn scan_float_arg_registers(
    cfg: &ControlFlowGraph,
    convention: CallingConvention,
) -> Vec<(usize, String, u8)> {
    // Float ABI scan is implemented for System V (xmm0-xmm7) and
    // Aarch64 AAPCS (d0-d7 / s0-s7 / q0-q7 / v0-v7 — all aliases of
    // the same vector-register file). Win64 shares the integer/float
    // arg slot and uses the integer scan; RiscV would need its own
    // scan if/when float-ABI work extends there.
    if !matches!(
        convention,
        CallingConvention::SystemV | CallingConvention::Aarch64
    ) {
        return Vec::new();
    }
    let float_regs = convention.float_arg_registers();
    let mut detected: Vec<Option<u8>> = vec![None; float_regs.len()];
    let mut written: HashSet<String> = HashSet::new();

    for block_id in cfg.block_ids() {
        let Some(block) = cfg.block(block_id) else {
            continue;
        };
        for inst in &block.instructions {
            // Classify the operand layout for this instruction. Three
            // shapes matter for float-arg recovery:
            //
            // * MEMORY STORE (str/stp/movsd [mem],xmm0) — every register
            //   operand is a source value being written to memory; no
            //   destination register write. `stp d0, d1, [sp, #N]`
            //   carries TWO float-arg sources.
            // * REG-TO-REG STORE (movdqa xmm1, xmm0) — operand[0] is
            //   the destination, operand[1..] are sources. Without
            //   this distinction `movdqa xmm1, xmm0` (copy of the
            //   single float arg) would falsely register xmm1 as a
            //   2nd arg. Codex review on PR #25 pass 9.
            // * LOAD (ldr/ldp/mov reg,[mem]) — every leading register
            //   operand before any memory operand is a DESTINATION
            //   write, no source register reads. Codex review on
            //   PR #25 pass 7 fixed `ldp d0, d1, [sp, #N]`.
            // * COMPARE/TEST (cmp/fcmp/test) — operand[0] is ALSO a
            //   source read, not a destination. Skipping operand[0]
            //   would miss `fcmp d0, d1` cases where the only use of
            //   d0 in the function is the compare. Codex review on
            //   PR #25 pass 9.
            // * DEFAULT (add/mul/move-reg-reg/etc.) — operand[0] is
            //   destination, operand[1..] are sources. Iterating all
            //   `operand[1..]` covers 3-operand FP `fadd d0, d0, d1`
            //   and x86 AVX VEX-encoded `vfmadd231sd xmm0,xmm1,xmm2`
            //   (codex review on PR #25 pass 3).
            let has_memory_operand = inst
                .operands
                .iter()
                .any(|o| matches!(o, Operand::Memory(_)));
            let is_memory_store = matches!(inst.operation, Operation::Store) && has_memory_operand;
            let is_load = matches!(inst.operation, Operation::Load);
            let is_compare_or_test = matches!(inst.operation, Operation::Compare | Operation::Test);

            if is_load {
                // Only aarch64 `ldp` writes two leading register
                // operands. For every other Load (x86 mov reg,[mem];
                // x86 VEX `vmaskmovps xmm2, xmm0, [rdi]` whose middle
                // operand is a SOURCE/mask not a destination; aarch64
                // ldr) operand[0] is the only destination — the
                // remaining register operands before the memory are
                // SOURCES that may carry argument reads. Codex review
                // on PR #25 pass 10.
                let mnemonic = inst.mnemonic.to_ascii_lowercase();
                let multi_dest = mnemonic == "ldp" || mnemonic == "ldnp" || mnemonic == "ldpsw";
                if multi_dest {
                    for operand in &inst.operands {
                        match operand {
                            Operand::Register(reg) => {
                                let name = reg.name().to_lowercase();
                                let abi_name = float_arg_abi_register(&name, convention);
                                written.insert(abi_name);
                            }
                            _ => break,
                        }
                    }
                    continue;
                }
                // Single-destination load: mark operand[0] as written,
                // then fall through so operand[1..] (before the memory
                // operand) get scanned as source reads.
                if let Some(Operand::Register(dst)) = inst.operands.first() {
                    let name = dst.name().to_lowercase();
                    let abi_name = float_arg_abi_register(&name, convention);
                    written.insert(abi_name);
                }
                for operand in inst.operands.iter().skip(1) {
                    let Operand::Register(src) = operand else {
                        break;
                    };
                    let name = src.name().to_lowercase();
                    let abi_name = float_arg_abi_register(&name, convention);
                    if let Some(idx) = float_regs
                        .iter()
                        .position(|r| r.eq_ignore_ascii_case(&abi_name))
                    {
                        if detected[idx].is_none() && !written.contains(&abi_name) {
                            detected[idx] = Some(scalar_float_operand_size_with_reg(inst, &name));
                        }
                    }
                }
                continue;
            }

            // Source-operand slice for arg-read detection.
            //   memory-store / compare-or-test → all operands are sources
            //   default                         → operand[1..] are sources
            let source_skip = if is_memory_store || is_compare_or_test {
                0
            } else {
                1
            };

            let is_self_zero = matches!(inst.operation, Operation::Xor)
                && operands_are_same_register(&inst.operands);
            if !is_self_zero {
                for operand in inst.operands.iter().skip(source_skip) {
                    let Operand::Register(src) = operand else {
                        continue;
                    };
                    let name = src.name().to_lowercase();
                    // Normalise across the aarch64 register-file aliases so a
                    // `d0` use is recognised when the convention's arg list
                    // is `d0..d7`. The aarch64 ABI reuses the same vector
                    // register at different element widths (`s0`/`d0`/`q0`/`v0`
                    // all alias bank 0); pick the matching ABI name.
                    let abi_name = float_arg_abi_register(&name, convention);
                    if let Some(idx) = float_regs
                        .iter()
                        .position(|r| r.eq_ignore_ascii_case(&abi_name))
                    {
                        if detected[idx].is_none() && !written.contains(&abi_name) {
                            detected[idx] = Some(scalar_float_operand_size_with_reg(inst, &name));
                        }
                    }
                }
            }
            // Memory stores have no destination register write, and
            // compare/test ops don't write the operand[0] register
            // either. Only mark operand[0] as written for ops that
            // genuinely write to it.
            if is_memory_store || is_compare_or_test {
                continue;
            }
            // The destination (operand 0), if a float-bank register, is
            // written by anything but a pure comparison/test. Over-counting
            // writes is safe: it only suppresses later (false) argument
            // detections.
            if let Some(Operand::Register(dst)) = inst.operands.first() {
                let name = dst.name().to_lowercase();
                let abi_name = float_arg_abi_register(&name, convention);
                let is_float_bank = match convention {
                    CallingConvention::SystemV => name.starts_with("xmm"),
                    CallingConvention::Aarch64 => {
                        // Half-precision `h*` deliberately omitted: the
                        // downstream `float_param_type_for_size` maps
                        // sizes 0..=4 to `Float(32)`, so an h0 arg
                        // would be wrongly recovered as 32-bit `float`
                        // rather than `_Float16`. Until a 16-bit float
                        // type lands, skip h*. Codex review on PR #25
                        // pass 12.
                        matches!(name.chars().next(), Some('s' | 'd' | 'q' | 'v'))
                            && name[1..].chars().all(|c| c.is_ascii_digit())
                    }
                    _ => false,
                };
                if is_float_bank && !matches!(inst.operation, Operation::Compare | Operation::Test)
                {
                    written.insert(abi_name);
                }
            }
        }
    }

    let mut result = Vec::new();
    for (idx, reg) in float_regs.iter().enumerate() {
        match detected[idx] {
            Some(size) => result.push((idx, reg.to_lowercase(), size)),
            // Float arguments are assigned contiguously; stop at the first gap.
            None => break,
        }
    }
    result
}

/// Map any float-bank register name (e.g. aarch64 `s3`, `d3`, `q3`, `v3`)
/// to the ABI-arg-register name the convention's `float_arg_registers()`
/// list uses (aarch64 → `d3`; System V passes through `xmm3`). Used to
/// recognise float-arg reads regardless of access width.
fn float_arg_abi_register(name: &str, convention: CallingConvention) -> String {
    match convention {
        CallingConvention::Aarch64 => {
            if name.len() >= 2 {
                let prefix = name.chars().next().unwrap();
                let suffix: String = name[1..].chars().collect();
                // `h*` (half-precision) intentionally NOT normalized:
                // see is_float_bank above for the rationale. Codex
                // review on PR #25 pass 12.
                if matches!(prefix, 's' | 'd' | 'q' | 'v')
                    && suffix.chars().all(|c| c.is_ascii_digit())
                {
                    return format!("d{suffix}");
                }
            }
            name.to_string()
        }
        _ => name.to_string(),
    }
}

/// Operand width derived from the destination/source register's prefix
/// (aarch64: `s*` = 4-byte single, `d*` = 8-byte double, `q*` = 16-byte
/// vector). Falls back to [`scalar_float_operand_size`] for x86 mnemonics
/// (`*ss` = single, `*sd` = double).
fn scalar_float_operand_size_with_reg(inst: &hexray_core::Instruction, reg: &str) -> u8 {
    if let Some(prefix) = reg.chars().next() {
        match prefix {
            's' => return 4,
            'd' => return 8,
            // Both `q*` (the 128-bit-register name) and `v*` (the
            // 128-bit vector-form name) map to 16 bytes. The aarch64
            // register renderer uses `v*` for the 128-bit form, not
            // `q*`, so missing `v` here would silently round a vector
            // arg/return down to 8 bytes (`double`). Codex review on
            // PR #25 pass 5.
            'q' | 'v' => return 16,
            _ => {}
        }
    }
    scalar_float_operand_size(inst)
}

/// Whether operands 0 and 1 are the same register (the self-xor zeroing idiom).
fn operands_are_same_register(operands: &[Operand]) -> bool {
    matches!(
        (operands.first(), operands.get(1)),
        (Some(Operand::Register(a)), Some(Operand::Register(b)))
            if a.name().eq_ignore_ascii_case(b.name())
    )
}

/// Scalar floating-point operand width from an instruction mnemonic: single
/// (`*ss`) is 4 bytes, double (`*sd`) is 8. Defaults to 8 (double) — the common
/// case — when the mnemonic is not a recognized scalar form.
fn scalar_float_operand_size(inst: &hexray_core::Instruction) -> u8 {
    let m = inst.mnemonic.to_ascii_lowercase();
    if m.ends_with("ss") || m.contains("ss2") {
        4
    } else {
        8
    }
}

/// Detect a floating-point return value by scanning the raw instruction stream.
///
/// Returns `Some(size_bytes)` if the function returns a float/double in `xmm0`.
/// Like [`scan_float_arg_registers`], this recovers the `-O0` spill-only case
/// where the `xmm0` result is pruned before the structured form. It is
/// conservative: any return path whose value is established in the integer
/// return register (`rax`/`eax`) vetoes a float classification, and the epilogue
/// stack-canary reload (`rax = *guard_slot`) is skipped so it does not look like
/// an integer return.
pub fn scan_float_return(cfg: &ControlFlowGraph, convention: CallingConvention) -> Option<u8> {
    if !matches!(
        convention,
        CallingConvention::SystemV | CallingConvention::Aarch64
    ) {
        return None;
    }
    let mut float_size: Option<u8> = None;
    for block_id in cfg.block_ids() {
        let Some(block) = cfg.block(block_id) else {
            continue;
        };
        let is_return_block = matches!(block.terminator, hexray_core::BlockTerminator::Return)
            || block
                .instructions
                .last()
                .is_some_and(|i| matches!(i.operation, Operation::Return));
        if !is_return_block {
            continue;
        }
        // Walk the return block, then single-predecessor chain, until the
        // return register is established (the `-O0` canary epilogue puts the
        // value-producing write a block before the bare `leave; ret`).
        let mut current = Some(block_id);
        let mut visited = HashSet::new();
        while let Some(bid) = current {
            if !visited.insert(bid) {
                break;
            }
            let Some(b) = cfg.block(bid) else { break };
            match block_return_register_class(b, convention) {
                Some(ReturnRegClass::Float(size)) => {
                    float_size = Some(float_size.map_or(size, |s| s.max(size)));
                    break;
                }
                // A definite integer return anywhere vetoes float classification.
                Some(ReturnRegClass::Integer) => return None,
                None => {
                    let preds = cfg.predecessors(bid);
                    current = (preds.len() == 1).then(|| preds[0]);
                }
            }
        }
    }
    float_size
}

#[derive(Debug, PartialEq, Eq)]
enum ReturnRegClass {
    Float(u8),
    Integer,
}

/// Classify the return register established by a block: the last write to a
/// return register (`xmm0` = float, `rax`/`eax` = integer), skipping the
/// epilogue and the stack-canary reload/compare.
fn block_return_register_class(
    block: &hexray_core::BasicBlock,
    convention: CallingConvention,
) -> Option<ReturnRegClass> {
    let mut saw_guard = false;
    for inst in block.instructions.iter().rev() {
        // Skip epilogue scaffolding.
        let m = inst.mnemonic.to_ascii_lowercase();
        // Stack-canary guard compare against %fs:0x28 has to be
        // detected BEFORE the Compare/Test skip below, otherwise the
        // pass-4 fix swallows it and the preceding canary reload into
        // rax is misread as the integer return value. Codex review on
        // PR #25 pass 8. The guard helper covers `cmp`/`sub` shapes.
        if instruction_references_stack_guard(inst) {
            saw_guard = true;
            continue;
        }
        if matches!(
            inst.operation,
            Operation::Return | Operation::Push | Operation::Pop | Operation::Nop
            // Compare/Test set flags, not the operand[0] register. On
            // aarch64 `fcmp d0, d1` carries d0 as operand[0] purely as
            // a source read, so without skipping these the return
            // classifier would seed a double return on void functions
            // that only compare FP args. Codex review on PR #25 pass 4.
            | Operation::Compare
            | Operation::Test
        ) || m == "leave"
            || m.starts_with("nop")
            || m.starts_with("endbr")
            || m.starts_with("stp")
        {
            continue;
        }
        // Store ops with a memory destination: on aarch64
        // `str d0, [sp, #N]` (an arg spill, common in the entry block
        // when the return block happens to be the entry block too)
        // carries d0 as operand[0] — the SOURCE being stored, not a
        // destination write. Without skipping these stores the return
        // classifier would treat the spill as a `d0 = ...` and
        // mistakenly seed a float return on integer/void leaf
        // functions whose only float reference is the incoming arg
        // spill. Codex review on PR #25 pass 2.
        //
        // But the skip MUST be narrowed to memory-destination stores
        // only: x86 `movd r32, xmm0` / `vmovd r32, xmm0` is classified
        // as `Operation::Store` even though operand[0] is the integer
        // DESTINATION (register-to-register move from the SSE bank).
        // Skipping all stores would drop the eax write and let the
        // classifier walk back to an earlier xmm0 write, falsely
        // seeding a float return on integer-returning functions. Use
        // the presence of a Memory operand to distinguish: only skip
        // when there's a memory destination involved. Codex review on
        // PR #25 pass 7.
        if matches!(inst.operation, Operation::Store)
            && inst
                .operands
                .iter()
                .any(|o| matches!(o, Operand::Memory(_)))
        {
            continue;
        }
        // aarch64 epilogue restore `ldp x29, x30, [sp, #N]` isn't a
        // value-producing write — but `ldp x0, x1, ...` or `ldp d0, d1,
        // ...` immediately before `ret` IS a return-register load.
        // Restrict the skip to frame-restore shape only (operand[0] is
        // x29/fp), so non-frame ldp falls through to the classifier.
        // Codex review on PR #25 pass 5.
        if m == "ldp" {
            if let Some(Operand::Register(first)) = inst.operands.first() {
                let n = first.name().to_lowercase();
                if n == "x29" || n == "fp" {
                    continue;
                }
            }
        }
        let Some(Operand::Register(dst)) = inst.operands.first() else {
            continue;
        };
        let name = dst.name().to_lowercase();
        match convention {
            CallingConvention::SystemV | CallingConvention::Win64 => {
                if name == "xmm0" {
                    return Some(ReturnRegClass::Float(scalar_float_operand_size(inst)));
                }
                if matches!(name.as_str(), "rax" | "eax" | "ax" | "al") {
                    if saw_guard {
                        saw_guard = false;
                        continue;
                    }
                    return Some(ReturnRegClass::Integer);
                }
            }
            CallingConvention::Aarch64 => {
                // d0 / s0 / q0 / v0 — all aliases of the same float
                // return register at different widths. Use the operand
                // width for size; q0 (vector) defaults to 16 but we
                // generally won't see that in scalar-double leaf fns.
                if matches!(name.as_str(), "d0" | "s0" | "q0" | "v0") {
                    return Some(ReturnRegClass::Float(scalar_float_operand_size_with_reg(
                        inst, &name,
                    )));
                }
                // x0 / w0 = integer return.
                if matches!(name.as_str(), "x0" | "w0") {
                    if saw_guard {
                        saw_guard = false;
                        continue;
                    }
                    return Some(ReturnRegClass::Integer);
                }
            }
            CallingConvention::RiscV => {
                // RiscV float-return scan would land here; left for a
                // dedicated effort.
            }
        }
    }
    None
}

fn instruction_references_stack_guard(inst: &hexray_core::Instruction) -> bool {
    use hexray_core::register::x86;
    inst.operands.iter().any(|operand| {
        matches!(operand, Operand::Memory(mem)
            if mem.segment.as_ref().is_some_and(|seg| seg.id == x86::FS)
                && mem.displacement == 0x28)
    })
}

impl SignatureRecovery {
    /// Creates a new signature recovery engine with the given calling convention.
    pub fn new(convention: CallingConvention) -> Self {
        let string_functions: HashSet<&'static str> = [
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strchr",
            "strrchr", "strstr", "strtok", "strdup", "strndup", "sprintf", "snprintf", "sscanf",
            "printf", "fprintf", "puts", "fputs", "gets", "fgets", "atoi", "atol", "atof",
            "strtol", "strtoul", "strtod",
        ]
        .into_iter()
        .collect();

        Self {
            convention,
            read_regs: HashSet::new(),
            written_regs: HashSet::new(),
            reg_sizes: HashMap::new(),
            value_sizes: HashMap::new(),
            return_value_set: false,
            return_size: 8,
            float_return: false,
            float_abi_return_expr_observed: false,
            observed_float_arg_regs: HashSet::new(),
            float_arg_seeds: Vec::new(),
            float_return_seed: None,
            integer_simd_ops_observed: false,
            return_from_integer_simd_lane: false,
            integer_simd_scalar_literal_return_size_hint: None,
            integer_simd_scalar_return_size_hint: None,
            arg_register_copy_sources: HashMap::new(),
            x87_ops_observed: false,
            x87_st0_input_observed: false,
            current_rhs_float_dest_size: 0,
            x87_stack_arg_offsets: BTreeSet::new(),
            return_function_pointer: None,
            tail_call_return_type: None,
            tail_call_min_arity: None,
            return_is_pointer: false,
            return_provenance: Vec::new(),
            return_confidence: 0,
            param_names: HashMap::new(),
            arg_spill_offsets: HashMap::new(),
            invalidated_spill_offsets: HashSet::new(),
            param_spill_order: Vec::new(),
            va_list_float_count_seed: None,
            aapcs_va_list_counts: None,
            param_type_overrides: HashMap::new(),
            dwarf_param_names: Vec::new(),
            param_hints: HashMap::new(),
            function_pointer_aliases: HashMap::new(),
            function_pointer_alias_latest: HashMap::new(),
            value_alias_latest: HashMap::new(),
            assigned_value_names: HashSet::new(),
            value_pointer_hints: HashSet::new(),
            value_function_pointer_types: HashMap::new(),
            string_functions,
            relocation_table: None,
            symbol_table: None,
            summary_database: None,
            binary_data: None,
            current_func_name: None,
            current_func_kind: None,
            sysv_va_list_gp_offset_slots: HashSet::new(),
            sysv_va_list_fp_offset_slots: HashSet::new(),
            sysv_va_list_pointer_slots: HashSet::new(),
            sysv_va_start_seen: false,
            variadic_fixed_param_count: None,
            sysv_stack_const_stores: HashMap::new(),
            sysv_stack_pointer_stores: HashSet::new(),
        }
    }

    /// Sets the function name for known function signature lookup.
    pub fn with_function_name(mut self, name: &str) -> Self {
        self.current_func_name = Some(name.to_string());
        self
    }

    /// Sets the current function's symbol kind when known.
    pub fn with_current_function_kind(mut self, kind: Option<SymbolKind>) -> Self {
        self.current_func_kind = kind;
        self
    }

    /// Seeds float-argument registers detected from the raw instruction stream.
    /// Use [`scan_float_arg_registers`] to compute the argument from a CFG.
    pub fn with_float_arg_seeds(mut self, seeds: Vec<(usize, String, u8)>) -> Self {
        self.float_arg_seeds = seeds;
        self
    }

    /// Seeds a float return value (size in bytes) detected from the raw
    /// instruction stream. Use [`scan_float_return`] to compute it from a CFG.
    pub fn with_float_return_seed(mut self, size: Option<u8>) -> Self {
        self.float_return_seed = size;
        self
    }

    /// Seeds prologue parameter-spill observations from the raw CFG.
    /// Use [`scan_param_spill_order`] to compute them. Carries the
    /// source-declaration order across the int/float bank split.
    pub fn with_param_spill_order(mut self, order: Vec<ParamSpillObservation>) -> Self {
        self.param_spill_order = order;
        self
    }

    /// Seeds the named-float count read from the raw `__va_list_tag`
    /// initialiser (see [`scan_sysv_va_list_named_float_count`]), used as a
    /// fallback when the `va_arg` diamonds were collapsed before signature
    /// recovery ran.
    pub fn with_va_list_float_count_seed(mut self, count: Option<usize>) -> Self {
        self.va_list_float_count_seed = count;
        self
    }

    /// Seeds the aarch64 AAPCS variadic `(named_gp, named_fp)` counts
    /// (see [`scan_aapcs_va_list`]).
    pub fn with_aapcs_va_list_counts(mut self, counts: Option<(usize, usize)>) -> Self {
        self.aapcs_va_list_counts = counts;
        self
    }

    /// Provides DWARF parameter names in declaration order.
    pub fn with_dwarf_param_names(mut self, names: Vec<String>) -> Self {
        self.dwarf_param_names = names;
        self
    }

    /// Provides relocation data for resolving indirect GOT call targets.
    pub fn with_relocation_table(mut self, relocation_table: Option<RelocationTable>) -> Self {
        self.relocation_table = relocation_table;
        self
    }

    /// Provides symbol names for resolving direct call targets.
    pub fn with_symbol_table(mut self, symbol_table: Option<SymbolTable>) -> Self {
        self.symbol_table = symbol_table;
        self
    }

    /// Provides inter-procedural summaries for additional signature hints.
    pub fn with_summary_database(
        mut self,
        summary_database: Option<Arc<super::interprocedural::SummaryDatabase>>,
    ) -> Self {
        self.summary_database = summary_database;
        self
    }

    /// Provides read-only binary data for resolving string-literal arguments.
    pub fn with_binary_data(mut self, binary_data: Option<&BinaryDataContext>) -> Self {
        self.binary_data = binary_data.cloned().map(Arc::new);
        self
    }

    /// Analyzes a structured CFG to recover the function signature.
    pub fn analyze(&mut self, cfg: &StructuredCfg) -> FunctionSignature {
        // Reset state
        self.read_regs.clear();
        self.written_regs.clear();
        self.reg_sizes.clear();
        self.value_sizes.clear();
        self.return_value_set = false;
        self.return_size = 8;
        self.float_return = false;
        self.float_abi_return_expr_observed = false;
        self.observed_float_arg_regs.clear();
        self.integer_simd_ops_observed = false;
        self.return_from_integer_simd_lane = false;
        self.integer_simd_scalar_literal_return_size_hint = None;
        self.integer_simd_scalar_return_size_hint = None;
        self.arg_register_copy_sources.clear();
        self.x87_ops_observed = false;
        self.x87_st0_input_observed = false;
        self.x87_stack_arg_offsets.clear();
        self.return_function_pointer = None;
        self.tail_call_return_type = None;
        self.tail_call_min_arity = None;
        self.return_is_pointer = false;
        self.return_provenance.clear();
        self.return_confidence = 0;
        self.param_names.clear();
        self.arg_spill_offsets.clear();
        self.invalidated_spill_offsets.clear();
        self.param_type_overrides.clear();
        self.param_hints.clear();
        self.function_pointer_aliases.clear();
        self.function_pointer_alias_latest.clear();
        self.value_alias_latest.clear();
        self.assigned_value_names.clear();
        self.value_pointer_hints.clear();
        self.value_function_pointer_types.clear();
        self.sysv_va_list_gp_offset_slots.clear();
        self.sysv_va_list_fp_offset_slots.clear();
        self.sysv_va_list_pointer_slots.clear();
        self.sysv_va_start_seen = false;
        self.variadic_fixed_param_count = None;
        self.sysv_stack_const_stores.clear();
        self.sysv_stack_pointer_stores.clear();

        // Seed float argument registers detected from the raw instruction stream
        // (the `-O0` spill of an xmm arg is pruned before this structured form,
        // so direct observation alone misses spill-only float parameters).
        for (idx, reg, size) in self.float_arg_seeds.clone() {
            self.observed_float_arg_regs.insert(reg.clone());
            if size > 0 {
                self.record_value_size_hint(&reg, size);
                self.record_value_size_hint(&format!("xmm{idx}"), size);
                self.record_value_size_hint(&format!("farg{idx}"), size);
            }
        }

        // Analyze the function body
        self.analyze_nodes(&cfg.body, false);

        // Seed a float return detected from the raw instruction stream when the
        // structured analysis did not establish a (non-float) return — the
        // `-O0` `xmm0` result spill is pruned before this form.
        if let Some(size) = self.float_return_seed {
            if !self.return_from_integer_simd_lane
                && self.return_function_pointer.is_none()
                && !self.return_is_pointer
            {
                self.return_value_set = true;
                self.float_return = true;
                self.return_size = size;
                if !self
                    .return_provenance
                    .iter()
                    .any(|r| r == "float return register (xmm0) from instruction scan")
                {
                    self.return_provenance
                        .push("float return register (xmm0) from instruction scan".to_string());
                }
            }
        }

        // Recover "return callee(...);" style wrappers where only a tail-position call is present.
        if !self.return_value_set {
            if let Some(candidate) = self.tail_call_return_type.clone() {
                if !matches!(candidate, ParamType::Void | ParamType::Unknown) {
                    self.return_value_set = true;
                    self.return_size = candidate.size().max(1);
                    if matches!(candidate, ParamType::Float(_)) {
                        self.float_return = true;
                    }
                    if matches!(candidate, ParamType::Pointer | ParamType::TypedPointer(_)) {
                        self.return_is_pointer = true;
                        self.return_size = self.return_size.max(8);
                    }
                    if matches!(candidate, ParamType::FunctionPointer { .. }) {
                        self.return_function_pointer = Some(candidate);
                    } else {
                        self.return_confidence = self.return_confidence.max(140);
                    }
                    self.return_provenance
                        .push("tail-position call return forwarding".to_string());
                }
            }
        }

        self.reconcile_integer_simd_scalar_return();

        if self.float_return
            && self.return_size == 8
            && !self.return_from_integer_simd_lane
            && !self
                .return_provenance
                .iter()
                .any(|reason| reason.contains("width inferred as"))
        {
            if let Some(size) = self.consistent_observed_float_arg_size() {
                self.return_size = size;
                self.return_provenance.push(format!(
                    "float return width matched observed float argument width of {} byte(s)",
                    size
                ));
            }
        }

        // Build the signature
        self.build_signature()
    }

    /// Records a usage hint for a parameter.
    fn record_usage_hint(
        &mut self,
        reg_name: &str,
        hint_fn: impl FnOnce(&mut ParameterUsageHints),
    ) {
        let name = reg_name.to_lowercase();
        if let Some(idx) = self.resolve_param_index_from_name_internal(&name, false) {
            let hints = self.param_hints.entry(idx).or_default();
            hint_fn(hints);
        }
    }

    /// Variant of [`Self::record_usage_hint`] that bypasses the
    /// "written-before-read" clobber filter in
    /// [`Self::resolve_param_index_from_name_shallow`].
    ///
    /// Use this only when we already have HARD evidence that the
    /// register name maps to a specific parameter — e.g. the spill
    /// offset matched the prologue scan's record of where this
    /// arg's home slot lives. In that case, even if the register
    /// has been reused as a scratch (so `written_regs` contains it
    /// and `read_regs` doesn't), the slot's identity as the
    /// parameter's home is preserved by the offset evidence. The
    /// regular clobber filter is meant for ambiguous register
    /// references in the body, which is the wrong filter here.
    /// Codex review on PR #32 pass 8.
    fn record_hint_for_arg_register(
        &mut self,
        reg_name: &str,
        hint_fn: impl FnOnce(&mut ParameterUsageHints),
    ) {
        let name = reg_name.to_lowercase();
        if let Some(idx) = self.arg_register_index(&name) {
            let hints = self.param_hints.entry(idx).or_default();
            hint_fn(hints);
        }
    }

    fn copied_arg_root(&self, idx: usize) -> usize {
        let mut current = idx;
        let mut seen = HashSet::new();
        while let Some(next) = self.arg_register_copy_sources.get(&current).copied() {
            if !seen.insert(current) || next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn note_direct_arg_register_copy(&mut self, lhs_reg: &str, rhs: &Expr) {
        let Some(lhs_idx) = self.direct_arg_register_index(lhs_reg) else {
            return;
        };
        let lhs_read =
            self.read_regs.contains(lhs_reg) || self.read_regs.contains(&format!("arg{}", lhs_idx));
        if lhs_read {
            return;
        }

        let Some(rhs_idx) = self.resolve_param_index_from_expr_shallow(rhs) else {
            self.arg_register_copy_sources.remove(&lhs_idx);
            return;
        };
        if lhs_idx == rhs_idx {
            self.arg_register_copy_sources.remove(&lhs_idx);
            return;
        }

        self.arg_register_copy_sources
            .insert(lhs_idx, self.copied_arg_root(rhs_idx));
    }

    fn record_arg_register_read(&mut self, reg_name: &str, size: u8) {
        let name = reg_name.to_lowercase();
        let Some(idx) = self.direct_arg_register_index(&name) else {
            self.read_regs.insert(name.clone());
            if size > 0 {
                self.reg_sizes.insert(name, size);
            }
            return;
        };

        let root = self.copied_arg_root(idx);
        self.read_regs.insert(format!("arg{}", root));
        if size == 0 {
            return;
        }

        let size_key = if size >= 8 {
            self.convention
                .integer_arg_registers()
                .get(root)
                .map(|name| name.to_lowercase())
        } else {
            self.convention
                .integer_arg_registers_32()
                .get(root)
                .map(|name| name.to_lowercase())
        };
        if let Some(key) = size_key {
            self.reg_sizes
                .entry(key)
                .and_modify(|seen| *seen = (*seen).max(size))
                .or_insert(size);
        }
    }

    /// Checks if an expression is a null constant (0).
    fn is_null_constant(expr: &Expr) -> bool {
        matches!(expr.kind, ExprKind::IntLit(0))
    }

    /// Infers a basic type from a dereference/element size.
    fn infer_type_from_size(size: usize) -> ParamType {
        match size {
            1 => ParamType::SignedInt(8),  // int8_t
            2 => ParamType::SignedInt(16), // int16_t
            4 => ParamType::SignedInt(32), // int32_t
            8 => ParamType::SignedInt(64), // int64_t
            _ => ParamType::SignedInt(32), // Default to int32_t
        }
    }

    /// Variant of [`Self::infer_type_from_size`] that consults the
    /// `current_rhs_float_dest_size` flag set by the Assign handler.
    /// When the RHS of the current assignment lands in a float-bank
    /// register (`movsd xmm2, [arr+i*8]` lifts to
    /// `Var(xmm2) = ArrayAccess(arr, i, 8)`), pick `Float(64)` for an
    /// 8-byte element and `Float(32)` for a 4-byte element instead
    /// of the default signed-int. That makes the recovered base
    /// pointer come back as `double *arr` / `float *arr` rather
    /// than `int64_t *` / `int32_t *`.
    fn infer_deref_element_type(&self, size: usize) -> ParamType {
        if self.current_rhs_float_dest_size > 0 {
            match size {
                4 => return ParamType::Float(32),
                8 => return ParamType::Float(64),
                _ => {}
            }
        }
        Self::infer_type_from_size(size)
    }

    /// Merge a newly-inferred deref element type into an existing
    /// hint. Earlier-wins for matching kinds, but a Float observation
    /// PROMOTES a previously-stored int of the same width — the int
    /// default was the conservative fallback when no float context
    /// was available, and a later float-bank deref is strictly more
    /// informative.
    fn merge_deref_element_type(h: &mut ParameterUsageHints, new_ty: &ParamType) {
        match (&h.deref_element_type, new_ty) {
            (None, _) => {
                h.deref_element_type = Some(new_ty.clone());
            }
            (Some(ParamType::SignedInt(prev_bits)), ParamType::Float(new_bits))
                if prev_bits == new_bits =>
            {
                // Promote int → float when the widths match and the
                // new observation is float-context. The earlier int
                // was a default-from-size fallback; the float
                // context is harder evidence.
                h.deref_element_type = Some(new_ty.clone());
            }
            _ => {}
        }
    }

    /// Extracts a function name from a call target.
    fn extract_call_name(&self, target: &super::expression::CallTarget) -> Option<String> {
        match target {
            super::expression::CallTarget::Named(name) => Some(name.clone()),
            super::expression::CallTarget::Direct { target, call_site } => self
                .relocation_table
                .as_ref()
                .and_then(|t| t.get(*call_site).map(ToString::to_string))
                .or_else(|| {
                    self.symbol_table
                        .as_ref()
                        .and_then(|t| t.get(*target).map(ToString::to_string))
                }),
            super::expression::CallTarget::Indirect(_) => None,
            super::expression::CallTarget::IndirectGot { got_address, .. } => self
                .relocation_table
                .as_ref()
                .and_then(|t| t.get_got(*got_address).map(|s| s.to_string()))
                .or_else(|| {
                    self.symbol_table
                        .as_ref()
                        .and_then(|t| t.get(*got_address).map(ToString::to_string))
                }),
        }
    }

    fn is_tail_padding_statement(expr: &Expr) -> bool {
        matches!(&expr.kind, ExprKind::Unknown(name) if name.trim() == "/* nop */")
    }

    fn node_is_tail_padding(node: &StructuredNode) -> bool {
        match node {
            StructuredNode::Block { statements, .. } => {
                !statements.is_empty() && statements.iter().all(Self::is_tail_padding_statement)
            }
            StructuredNode::Sequence(nodes) => {
                !nodes.is_empty() && nodes.iter().all(Self::node_is_tail_padding)
            }
            _ => false,
        }
    }

    fn suffix_is_tail_return_path(nodes: &[StructuredNode]) -> bool {
        if nodes.is_empty() {
            return true;
        }

        let mut saw_bare_return = false;
        for node in nodes {
            match node {
                StructuredNode::Return(None) => {
                    saw_bare_return = true;
                }
                _ if saw_bare_return => return false,
                _ if Self::node_is_tail_padding(node) => {}
                _ => return false,
            }
        }

        true
    }

    /// Analyzes a list of structured nodes.
    fn analyze_nodes(&mut self, nodes: &[StructuredNode], in_return_path: bool) {
        for (i, node) in nodes.iter().enumerate() {
            let is_near_return =
                in_return_path || Self::suffix_is_tail_return_path(&nodes[i + 1..]);
            self.analyze_node(node, is_near_return);
        }
    }

    /// Analyzes a single structured node.
    fn analyze_node(&mut self, node: &StructuredNode, in_return_path: bool) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for (i, stmt) in statements.iter().enumerate() {
                    // For statements near the end of a block on a return path, check for
                    // return value setup and tail-call forwarding patterns.
                    let near_ret = in_return_path && i + 3 >= statements.len();
                    self.analyze_statement(stmt, near_ret);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                self.analyze_expr_reads(condition);
                self.analyze_nodes(then_body, in_return_path);
                if let Some(else_nodes) = else_body {
                    self.analyze_nodes(else_nodes, in_return_path);
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.analyze_expr_reads(condition);
                self.analyze_nodes(body, false);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(init_expr) = init {
                    self.analyze_statement(init_expr, false);
                }
                self.analyze_expr_reads(condition);
                if let Some(update_expr) = update {
                    self.analyze_statement(update_expr, false);
                }
                self.analyze_nodes(body, false);
            }
            StructuredNode::Loop { body, .. } => {
                self.analyze_nodes(body, false);
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
                ..
            } => {
                self.analyze_expr_reads(value);
                for (_, case_body) in cases {
                    self.analyze_nodes(case_body, in_return_path);
                }
                if let Some(def) = default {
                    self.analyze_nodes(def, in_return_path);
                }
            }
            StructuredNode::Return(Some(expr)) => {
                self.analyze_expr_reads(expr);
                self.return_value_set = true;
                if !self
                    .return_provenance
                    .iter()
                    .any(|r| r == "explicit return expression")
                {
                    self.return_provenance
                        .push("explicit return expression".to_string());
                }
                self.return_confidence = self.return_confidence.max(200);
                if let Some(candidate) = self.infer_tail_call_return_type(expr) {
                    match candidate {
                        ParamType::Pointer | ParamType::TypedPointer(_) => {
                            self.return_is_pointer = true;
                            self.return_size = self.return_size.max(8);
                            if !self
                                .return_provenance
                                .iter()
                                .any(|r| r == "return expression uses known pointer-valued call")
                            {
                                self.return_provenance.push(
                                    "return expression uses known pointer-valued call".to_string(),
                                );
                            }
                            self.return_confidence = self.return_confidence.max(215);
                        }
                        ParamType::FunctionPointer { .. } => {
                            self.return_function_pointer = Some(candidate);
                            self.return_is_pointer = true;
                            self.return_size = self.return_size.max(8);
                            if !self.return_provenance.iter().any(|r| {
                                r == "return expression uses known function-pointer-valued call"
                            }) {
                                self.return_provenance.push(
                                    "return expression uses known function-pointer-valued call"
                                        .to_string(),
                                );
                            }
                            self.return_confidence = self.return_confidence.max(230);
                        }
                        ParamType::Float(bits) => {
                            self.float_return = true;
                            self.return_size = self.return_size.max((bits / 8).max(1));
                        }
                        ParamType::UnsignedLongLong | ParamType::SizeT | ParamType::PtrDiffT => {
                            self.return_size = self.return_size.max(8);
                        }
                        ParamType::Named(_) => {
                            self.return_size = self.return_size.max(candidate.size().max(1));
                        }
                        ParamType::SignedInt(bits) | ParamType::UnsignedInt(bits) => {
                            self.return_size = self.return_size.max((bits / 8).max(1));
                        }
                        ParamType::Bool => {
                            self.return_size = self.return_size.max(1);
                        }
                        ParamType::Void
                        | ParamType::Unknown
                        | ParamType::SimdInt128
                        | ParamType::SimdFloat(_) => {}
                    }
                }
                if self.expr_uses_float_abi_value(expr) {
                    self.float_abi_return_expr_observed = true;
                    if !self.return_from_integer_simd_lane {
                        self.float_return = true;
                        if !self
                            .return_provenance
                            .iter()
                            .any(|r| r == "explicit return expression uses float ABI value")
                        {
                            self.return_provenance.push(
                                "explicit return expression uses float ABI value".to_string(),
                            );
                        }
                    }
                } else {
                    self.note_integer_simd_scalar_return_hint(expr);
                }
                if self.expr_is_x87_return_value(expr) {
                    self.x87_ops_observed = true;
                    self.float_return = true;
                    self.return_size = self.return_size.max(10);
                    if !self
                        .return_provenance
                        .iter()
                        .any(|r| r == "explicit return expression uses x87 fp80 value")
                    {
                        self.return_provenance
                            .push("explicit return expression uses x87 fp80 value".to_string());
                    }
                    self.return_confidence = self.return_confidence.max(215);
                }
                // Infer return type from expression
                if let Some(size) = self.infer_expr_size(expr) {
                    let inferred_size = if self.return_from_integer_simd_lane {
                        self.return_size.min(size).max(1)
                    } else if self.float_return && self.return_size >= 10 {
                        self.return_size
                    } else if self.float_return {
                        size
                    } else if matches!(expr.kind, ExprKind::IntLit(_)) {
                        size.max(4)
                    } else {
                        size
                    };
                    self.return_size = inferred_size;
                    let reason = format!(
                        "return expression width inferred as {} byte(s)",
                        inferred_size
                    );
                    if !self.return_provenance.iter().any(|r| r == &reason) {
                        self.return_provenance.push(reason);
                    }
                }
                // Check if return value is a pointer
                if self.is_expr_likely_pointer(expr) {
                    self.return_is_pointer = true;
                    self.return_size = self.return_size.max(8);
                    if !self
                        .return_provenance
                        .iter()
                        .any(|r| r == "return expression inferred as pointer")
                    {
                        self.return_provenance
                            .push("return expression inferred as pointer".to_string());
                    }
                    self.return_confidence = self.return_confidence.max(210);
                }
                if let Some(fp) = self.infer_return_function_pointer(expr) {
                    self.return_function_pointer = Some(fp);
                    if !self
                        .return_provenance
                        .iter()
                        .any(|r| r == "return expression inferred as function pointer")
                    {
                        self.return_provenance
                            .push("return expression inferred as function pointer".to_string());
                    }
                    self.return_confidence = self.return_confidence.max(240);
                }
            }
            StructuredNode::Return(None) => {
                // void return
            }
            StructuredNode::Expr(expr) => {
                self.analyze_statement(expr, in_return_path);
            }
            StructuredNode::Sequence(inner) => {
                self.analyze_nodes(inner, in_return_path);
            }
            _ => {}
        }
    }

    /// Analyzes a statement for register reads/writes.
    fn analyze_statement(&mut self, expr: &Expr, near_return: bool) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                self.observe_sysv_va_list_assignment(lhs, rhs);
                // Stash the float-bank-destination size during the
                // RHS walk so the Deref/ArrayAccess handlers can pick
                // `Float(n)` element types when the load lands in
                // an `xmm*` / `farg*` / aarch64 d-bank register. The
                // scalar SSE loads `movsd`/`movss` flow through here
                // as `Var(xmm*) = ArrayAccess(..., size)`.
                //
                // Only set the flag when the rhs is a DIRECT
                // ArrayAccess — an intervening `Cast` or `BinOp` is
                // evidence that the load isn't a raw scalar FP read:
                // `xmm0 = Cast(ArrayAccess(rdi, i, 4), Float)` is the
                // `cvtsi2sd` int→float conversion shape, where the
                // memory source is still INTEGER data. Codex review
                // on PR #38 pass 6.
                //
                // Known limitation (codex pass 7): an indexed
                // integer-SIMD load like `movq xmm0, [rdi+rcx*8]`
                // lifts to the SAME shape as scalar `movsd xmm2,
                // [arr+i*8]` and gets the same float-context
                // treatment. Without lift-time mnemonic annotation
                // (analogous to `GotRef.is_float_context`) we can't
                // distinguish them at this layer. The trade-off
                // favors the dramatically more common scalar-float
                // array case; the indexed-integer-SIMD pattern is
                // rare in compiled C code (compilers prefer general-
                // purpose registers for integer indexed loads).
                let prev_float_dest = self.current_rhs_float_dest_size;
                self.current_rhs_float_dest_size = if matches!(rhs.kind, ExprKind::ArrayAccess { .. }) {
                    self.float_dest_load_size(lhs)
                } else {
                    0
                };
                // First, analyze the RHS for reads
                self.analyze_expr_reads(rhs);
                self.current_rhs_float_dest_size = prev_float_dest;
                // Lvalue bases still contribute reads for parameter recovery, e.g.
                // *(arg1) = ret_0 should keep arg1 as a used pointer parameter.
                if !matches!(lhs.kind, ExprKind::Var(_) | ExprKind::Unknown(_)) {
                    self.analyze_expr_reads_with_context(lhs, false, false);
                }
                if let Some(lhs_name) = self.extract_var_name(lhs) {
                    if let Some(size) = self.infer_expr_size(rhs) {
                        if size > 0 {
                            let key = lhs_name.to_lowercase();
                            self.record_value_size_hint(&key, size);
                        }
                    }
                }
                if near_return && !self.return_value_set {
                    if let Some(candidate) = self.infer_tail_call_forwarded_return_type(rhs) {
                        self.tail_call_return_type = Some(candidate);
                    }
                }

                // When the structurer's stabilization renames a
                // scratch xmm to a `farg*` Unknown, the LHS Unknown
                // doesn't pass `extract_register_name`'s
                // `reg_size_from_name` check, so `record_register_write`
                // never runs and `written_regs` doesn't contain the
                // farg name. A later body read of that same farg
                // (e.g. `farg0 * farg2`) then unconditionally counts
                // as an arg observation and the recovered signature
                // grows a phantom param. Track the write explicitly
                // here so the use-before-write filter on the read
                // path can suppress the false observation.
                //
                // Record BOTH spellings (`farg2` AND the canonical
                // `xmm2`) so a write under one name and a read under
                // the other are correctly paired — codex review on
                // PR #37 pass 1 flagged the mixed-representation
                // failure mode.
                if let ExprKind::Unknown(name) = &lhs.kind {
                    let lower = name.to_lowercase();
                    if self.is_float_arg_register(&lower) || self.is_arg_register(&lower) {
                        if let Some(canonical) =
                            self.canonical_float_arg_register_name(&lower)
                        {
                            self.written_regs.insert(canonical);
                        }
                        self.written_regs.insert(lower);
                    }
                }

                // Check if LHS is a register being written
                if let Some(reg_name) = self.extract_register_name(lhs) {
                    let reg_lower = reg_name.to_lowercase();
                    self.note_direct_arg_register_copy(&reg_lower, rhs);
                    if (reg_lower == self.convention.integer_return_register()
                        || reg_lower == self.convention.integer_return_register_32())
                        && self.integer_simd_ops_observed
                        && self.expr_uses_float_abi_value(rhs)
                    {
                        self.return_from_integer_simd_lane = true;
                        if !self
                            .return_provenance
                            .iter()
                            .any(|r| r == "integer return extracted from SIMD lane")
                        {
                            self.return_provenance
                                .push("integer return extracted from SIMD lane".to_string());
                        }
                        self.return_confidence = self.return_confidence.max(205);
                    }
                    if self.is_float_return_register(&reg_lower)
                        && self.integer_simd_ops_observed
                        && self.expr_uses_integer_return_register(rhs)
                    {
                        self.return_from_integer_simd_lane = true;
                        if let Some(size) = match &rhs.kind {
                            ExprKind::Var(var) if var.size > 0 => Some(var.size),
                            _ => self.infer_expr_size(rhs),
                        } {
                            self.return_size = size.max(1);
                        }
                        if !self
                            .return_provenance
                            .iter()
                            .any(|r| r == "integer return forwarded through SIMD ABI register")
                        {
                            self.return_provenance.push(
                                "integer return forwarded through SIMD ABI register".to_string(),
                            );
                        }
                        self.return_confidence = self.return_confidence.max(205);
                    }
                    self.record_register_write(&reg_name, rhs, near_return);
                }

                // For parameter detection: check if an arg register is read and stored to stack
                // Pattern: *(rbp + offset) = rdi  means rdi is a parameter
                let mut rhs_is_matching_arg_spill = false;
                if let ExprKind::Var(rhs_var) = &rhs.kind {
                    let rhs_name = rhs_var.name.to_lowercase();
                    if self.is_arg_register(&rhs_name) && !self.written_regs.contains(&rhs_name) {
                        let rhs_size = self.effective_var_size(rhs_var);
                        let copy_size = if let ExprKind::Var(lhs_var) = &lhs.kind {
                            let lhs_size = self.effective_var_size(lhs_var);
                            match (lhs_size, rhs_size) {
                                (0, size) | (size, 0) => size,
                                (lhs_size, rhs_size) => lhs_size.min(rhs_size),
                            }
                        } else {
                            rhs_size
                        };
                        self.record_arg_register_read(&rhs_name, copy_size);

                        // Remember the stack slot this still-unwritten arg
                        // register was spilled to so that a later reload of
                        // the same slot into the same register can be
                        // confidently named after that slot — and a reload of
                        // an unrelated slot (the arg register being reused as
                        // a scratch temp, e.g. for a loop counter) is not.
                        if let Some(offset) = self.extract_stack_offset(lhs) {
                            if let Some(idx) = self.arg_register_index(&rhs_name) {
                                self.arg_spill_offsets
                                    .entry(idx)
                                    .or_default()
                                    .insert(offset);
                            }
                            // Mark a "matching" spill so the
                            // invalidation tracker below doesn't
                            // treat the prologue spill itself as a
                            // body-write of the slot.
                            if self
                                .param_spill_order
                                .iter()
                                .any(|obs| obs.offset as i128 == offset
                                    && obs.register == rhs_name)
                            {
                                rhs_is_matching_arg_spill = true;
                            }
                        }
                    }
                }

                // Slot-invalidation: if THIS write targets a stack
                // slot that the prologue scan recorded as an arg
                // spill home, AND the rhs is NOT that arg's register
                // (i.e. the slot is being reused for something
                // else), the original-parameter evidence is stale.
                // Subsequent loads from this offset should NOT
                // propagate to the original arg. Codex review on PR
                // #32 pass 9.
                //
                // Note: this is path-insensitive (same as
                // `written_regs` and other walker state in this
                // module) — a write in one branch invalidates the
                // slot for sibling branches analyzed afterward. The
                // failure mode is a false NEGATIVE (a pointer arg
                // misses recovery) rather than a false positive
                // (something becomes a pointer when it shouldn't),
                // matching the surrounding analysis's bias toward
                // conservative typing. Codex pass 10.
                if !rhs_is_matching_arg_spill {
                    if let Some(offset) = self.extract_stack_offset(lhs) {
                        if self
                            .param_spill_order
                            .iter()
                            .any(|obs| obs.offset as i128 == offset)
                        {
                            self.invalidated_spill_offsets.insert(offset);
                        }
                    }
                }

                if let Some(lhs_name) = self.extract_var_name(lhs) {
                    self.assigned_value_names.insert(lhs_name.clone());
                    if let Some(rhs_name) = self.extract_var_name(rhs) {
                        self.insert_value_alias(&lhs_name, &rhs_name);
                    }
                    let rhs_is_pointer_like = self.is_expr_likely_pointer(rhs)
                        || matches!(
                            self.infer_tail_call_return_type(rhs),
                            Some(
                                ParamType::Pointer
                                    | ParamType::TypedPointer(_)
                                    | ParamType::FunctionPointer { .. }
                            )
                        )
                        || self
                            .extract_var_name(rhs)
                            .is_some_and(|rhs_name| self.value_pointer_hints.contains(&rhs_name));
                    if rhs_is_pointer_like {
                        self.value_pointer_hints.insert(lhs_name.clone());
                    }
                    if let Some(idx) = self.resolve_param_index_from_expr_precise(rhs) {
                        self.insert_function_pointer_alias(&lhs_name, idx);
                    } else if let Some(rhs_name) = self.extract_var_name(rhs) {
                        if let Some(idx) = self.resolve_latest_alias_param_index(&rhs_name) {
                            self.insert_function_pointer_alias(&lhs_name, idx);
                        }
                    }
                    if let Some(rhs_name) = self.extract_var_name(rhs) {
                        if let Some(ty) = self.value_function_pointer_types.get(&rhs_name).cloned()
                        {
                            self.value_function_pointer_types
                                .insert(lhs_name.clone(), ty);
                        }
                    }
                    if let Some(fp_ty) = self.infer_return_function_pointer(rhs) {
                        self.value_function_pointer_types.insert(lhs_name, fp_ty);
                    }
                }
            }
            ExprKind::Call { .. } => {
                if near_return && !self.return_value_set {
                    self.tail_call_return_type = self.infer_tail_call_forwarded_return_type(expr);
                    if let ExprKind::Call { target, args } = &expr.kind {
                        if let Some(name) = self.extract_call_name(target) {
                            if let Some(params) = Self::known_function_params(&name) {
                                let mut resolved_args = Vec::with_capacity(args.len());
                                let mut is_pure_prefix_wrapper =
                                    !args.is_empty() && args.len() <= params.len();
                                for (arg_index, arg) in args.iter().enumerate() {
                                    let resolved_param_idx =
                                        self.resolve_param_index_from_expr_precise(arg);
                                    resolved_args.push(resolved_param_idx);
                                    is_pure_prefix_wrapper &= resolved_param_idx == Some(arg_index);
                                }

                                if is_pure_prefix_wrapper {
                                    self.tail_call_min_arity = Some(
                                        self.tail_call_min_arity.unwrap_or(0).max(params.len()),
                                    );
                                    for (param_idx, (param_name, param_type)) in
                                        params.iter().enumerate()
                                    {
                                        let wrapper_param_type =
                                            ParameterUsageHints::callback_signature(
                                                &name, param_idx,
                                            )
                                            .unwrap_or_else(|| param_type.clone());
                                        self.param_names
                                            .entry(param_idx)
                                            .or_insert_with(|| param_name.clone());
                                        self.param_type_overrides
                                            .entry(param_idx)
                                            .or_insert(wrapper_param_type);
                                    }
                                } else {
                                    for (arg_index, resolved_param_idx) in
                                        resolved_args.into_iter().enumerate()
                                    {
                                        let Some(param_idx) = resolved_param_idx else {
                                            continue;
                                        };
                                        let Some((param_name, param_type)) = params.get(arg_index)
                                        else {
                                            continue;
                                        };
                                        if let Some(wrapper_param_type) =
                                            ParameterUsageHints::callback_signature(
                                                &name, arg_index,
                                            )
                                        {
                                            self.param_names.insert(param_idx, param_name.clone());
                                            self.param_type_overrides
                                                .insert(param_idx, wrapper_param_type);
                                        } else {
                                            self.param_names
                                                .entry(param_idx)
                                                .or_insert_with(|| param_name.clone());
                                            self.param_type_overrides
                                                .entry(param_idx)
                                                .or_insert_with(|| param_type.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                self.analyze_expr_reads(expr);
            }
            ExprKind::CompoundAssign { lhs, rhs, .. } => {
                self.analyze_expr_reads_with_context(lhs, false, false);
                self.analyze_expr_reads(rhs);
                if let Some(lhs_name) = self.extract_var_name(lhs) {
                    if let Some(size) = self.infer_expr_size(rhs) {
                        if size > 0 {
                            let key = lhs_name.to_lowercase();
                            self.record_value_size_hint(&key, size);
                        }
                    }
                }
                if let Some(reg_name) = self.extract_register_name(lhs) {
                    if let Some(idx) = self.direct_arg_register_index(&reg_name.to_lowercase()) {
                        self.arg_register_copy_sources.remove(&idx);
                    }
                    self.record_register_write(&reg_name, rhs, near_return);
                }
            }
            _ => {
                self.analyze_expr_reads(expr);
            }
        }
    }

    fn record_register_write(&mut self, reg_name: &str, rhs: &Expr, near_return: bool) {
        let reg_lower = reg_name.to_lowercase();
        self.written_regs.insert(reg_lower.clone());
        // Also record the canonical ABI float-arg form so a write
        // under one vector-width alias (`ymm2` / `zmm2` / `farg2`)
        // gates a subsequent read under `xmm2` (and vice versa).
        // Without this, `vmovsd ymm2, ...` followed by `mulsd xmm0,
        // xmm2` would still record xmm2 as a float param. Codex
        // review on PR #37 pass 2.
        if let Some(canonical) = self.canonical_float_arg_register_name(&reg_lower) {
            if canonical != reg_lower {
                self.written_regs.insert(canonical);
            }
        }

        // If this is an argument register being reloaded from its prologue
        // spill slot, the slot is its home and naming the parameter after it
        // helps the reader. Reloads from a different slot are the arg
        // register being reused as a scratch temp (e.g. carrying a loop
        // counter) and must not steal the parameter's name — otherwise the
        // emitted parameter collides with that slot's stack-local name
        // (`var_18` etc.) and cascades the confusion through every use.
        if self.is_arg_register(&reg_lower) {
            if let Some(offset) = self.extract_stack_offset(rhs) {
                if let Some(idx) = self.arg_register_index(&reg_lower) {
                    if self
                        .arg_spill_offsets
                        .get(&idx)
                        .is_some_and(|slots| slots.contains(&offset))
                    {
                        self.param_names
                            .insert(idx, format!("var_{:x}", offset.unsigned_abs()));
                    }
                }
            }
        }

        if !near_return || !self.is_return_register(&reg_lower) {
            return;
        }

        self.return_value_set = true;
        let reason = format!(
            "value assigned to return register '{}' near return",
            reg_lower
        );
        if !self.return_provenance.iter().any(|r| r == &reason) {
            self.return_provenance.push(reason);
        }
        self.return_confidence = self.return_confidence.max(160);

        let reg_size = self.reg_size_from_name(&reg_lower);
        if reg_size > 0 {
            let mut inferred_size = reg_size;
            if let Some(rhs_size) = self.infer_expr_size(rhs) {
                if rhs_size > 0 && rhs_size < reg_size && !matches!(rhs.kind, ExprKind::IntLit(_)) {
                    inferred_size = rhs_size;
                }
            }
            self.return_size = inferred_size;
            let reason = format!(
                "return register value width inferred as {} byte(s)",
                inferred_size
            );
            if !self.return_provenance.iter().any(|r| r == &reason) {
                self.return_provenance.push(reason);
            }
            self.return_confidence = self.return_confidence.max(170);
        } else if let Some(size) = self.infer_expr_size(rhs) {
            self.return_size = size;
            let reason = format!("return register value width inferred as {} byte(s)", size);
            if !self.return_provenance.iter().any(|r| r == &reason) {
                self.return_provenance.push(reason);
            }
            self.return_confidence = self.return_confidence.max(170);
        }

        if self.is_expr_likely_pointer(rhs) {
            self.return_is_pointer = true;
            if !self
                .return_provenance
                .iter()
                .any(|r| r == "return register assignment inferred as pointer")
            {
                self.return_provenance
                    .push("return register assignment inferred as pointer".to_string());
            }
            self.return_confidence = self.return_confidence.max(190);
        }
        if let Some(fp) = self.infer_return_function_pointer(rhs) {
            self.return_function_pointer = Some(fp);
            if !self
                .return_provenance
                .iter()
                .any(|r| r == "return register assignment inferred as function pointer")
            {
                self.return_provenance
                    .push("return register assignment inferred as function pointer".to_string());
            }
            self.return_confidence = self.return_confidence.max(230);
        }
        if self.is_float_return_register(&reg_lower) {
            self.float_return = true;
            if !self
                .return_provenance
                .iter()
                .any(|r| r == "float return register observed")
            {
                self.return_provenance
                    .push("float return register observed".to_string());
            }
            self.return_confidence = self.return_confidence.max(200);
        }
        if (reg_lower == self.convention.integer_return_register()
            || reg_lower == self.convention.integer_return_register_32())
            && self.integer_simd_ops_observed
            && self.expr_uses_float_abi_value(rhs)
        {
            self.return_from_integer_simd_lane = true;
            if !self
                .return_provenance
                .iter()
                .any(|r| r == "integer return extracted from SIMD lane")
            {
                self.return_provenance
                    .push("integer return extracted from SIMD lane".to_string());
            }
            self.return_confidence = self.return_confidence.max(205);
        }
    }

    fn note_integer_simd_scalar_return_hint(&mut self, expr: &Expr) {
        if self.expr_uses_float_abi_value(expr) || self.is_expr_likely_pointer(expr) {
            return;
        }

        let Some(size) = self
            .infer_expr_size(expr)
            .filter(|size| *size > 0 && *size <= 8)
        else {
            return;
        };

        if matches!(expr.kind, ExprKind::IntLit(_)) {
            let current = self
                .integer_simd_scalar_literal_return_size_hint
                .unwrap_or_default();
            self.integer_simd_scalar_literal_return_size_hint = Some(current.max(size));
            return;
        }

        let current = self
            .integer_simd_scalar_return_size_hint
            .unwrap_or_default();
        self.integer_simd_scalar_return_size_hint = Some(current.max(size));
    }

    fn reconcile_integer_simd_scalar_return(&mut self) {
        if self.return_from_integer_simd_lane
            || !self.integer_simd_ops_observed
            || !self.float_return
            || !self.float_abi_return_expr_observed
        {
            return;
        }

        let Some(size) = self
            .integer_simd_scalar_literal_return_size_hint
            .or(self.integer_simd_scalar_return_size_hint)
        else {
            return;
        };

        self.return_from_integer_simd_lane = true;
        self.return_size = size;
        self.float_return = false;
        if !self
            .return_provenance
            .iter()
            .any(|r| r == "integer scalar return recovered from integer SIMD branches")
        {
            self.return_provenance
                .push("integer scalar return recovered from integer SIMD branches".to_string());
        }
        self.return_confidence = self.return_confidence.max(205);
    }

    /// Analyzes an expression for register reads (argument detection).
    fn analyze_expr_reads(&mut self, expr: &Expr) {
        self.analyze_expr_reads_with_context(expr, false, false);
    }

    /// Analyzes an expression with context about how it's being used.
    fn analyze_expr_reads_with_context(
        &mut self,
        expr: &Expr,
        is_dereferenced: bool,
        is_comparison: bool,
    ) {
        match &expr.kind {
            ExprKind::Var(var) => {
                let name = var.name.to_lowercase();
                if self.is_float_arg_register(&name) {
                    let observed_name = self
                        .canonical_float_arg_register_name(&name)
                        .unwrap_or_else(|| name.clone());
                    // Only count this read as a float-arg observation
                    // if the register hasn't been written first
                    // (mirrors the integer-arg use-before-write rule
                    // a few lines below). Without this gate, a scratch
                    // xmm renamed to `farg2` and assigned from `ys[i]`
                    // would still appear as the third float arg.
                    if !self.written_regs.contains(&name)
                        && !self.written_regs.contains(&observed_name)
                    {
                        self.observed_float_arg_regs.insert(observed_name.clone());
                    }
                    let size = self.observed_float_expr_size(var);
                    if size > 0 {
                        self.record_value_size_hint(&name, size);
                        self.record_value_size_hint(&observed_name, size);
                    }
                }
                // If this register is an argument register and hasn't been written yet,
                // it's being used as an argument
                if self.is_arg_register(&name) && !self.written_regs.contains(&name) {
                    self.record_arg_register_read(&name, self.effective_var_size(var));
                }

                // Record context hints for direct arguments and aliased arguments.
                if is_dereferenced {
                    self.record_usage_hint(&name, |h| h.is_dereferenced = true);
                }
                if is_comparison {
                    self.record_usage_hint(&name, |h| h.is_signed_comparison = true);
                }
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                if Self::is_opaque_x86_integer_simd_comment(name) {
                    self.integer_simd_ops_observed = true;
                }
                if self.is_float_arg_register(&lowered) {
                    let observed_name = self
                        .canonical_float_arg_register_name(&lowered)
                        .unwrap_or_else(|| lowered.clone());
                    // Same use-before-write guard as the Var path:
                    // a scratch-written `farg2` should NOT count as
                    // the third float arg just because the body
                    // reads it after the assignment.
                    if !self.written_regs.contains(&lowered)
                        && !self.written_regs.contains(&observed_name)
                    {
                        self.observed_float_arg_regs.insert(observed_name);
                    }
                }
                // Lifted IR often represents argument aliases as unknown identifiers
                // (e.g., arg0/arg_8); treat them as reads for use-before-def.
                if self.is_arg_register(&lowered) && !self.written_regs.contains(&lowered) {
                    self.record_arg_register_read(&lowered, self.reg_size_from_name(name));
                }

                if is_dereferenced {
                    self.record_usage_hint(&lowered, |h| h.is_dereferenced = true);
                }
                if is_comparison {
                    self.record_usage_hint(&lowered, |h| h.is_signed_comparison = true);
                }
            }
            ExprKind::BinOp { op, left, right } => {
                // Check for null comparison: arg == 0 or arg != 0
                let is_null_cmp = matches!(op, BinOpKind::Eq | BinOpKind::Ne)
                    && (Self::is_null_constant(left) || Self::is_null_constant(right));

                if is_null_cmp {
                    if let ExprKind::Var(var) = &left.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_null_checked = true
                        });
                    }
                    if let ExprKind::Var(var) = &right.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_null_checked = true
                        });
                    }
                }

                // Check for pointer arithmetic - only when adding/subtracting a scaled value
                // (e.g., ptr + i * sizeof(T) or ptr + constant offset)
                if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                    // Check if right side looks like an offset (scaled index or small constant)
                    let right_is_offset = match &right.kind {
                        ExprKind::BinOp {
                            op: BinOpKind::Mul | BinOpKind::Shl,
                            ..
                        } => true,
                        ExprKind::IntLit(n) => *n != 0 && (*n < 0x1000 || *n > 0), // Small offset
                        _ => false,
                    };

                    // `Add` is commutative — the structurer can emit
                    // either `spill + idx*S` or `idx*S + spill`.
                    // Detect the spill+scaled-index pattern in the
                    // operand we didn't already pick up, then fall
                    // through to the existing right-is-offset path
                    // with that same propagation.
                    // Codex review on PR #32 pass 7.
                    if matches!(op, BinOpKind::Add) && !right_is_offset {
                        let left_is_scaled_index = matches!(
                            &left.kind,
                            ExprKind::BinOp {
                                op: BinOpKind::Mul | BinOpKind::Shl,
                                ..
                            }
                        );
                        if left_is_scaled_index {
                            if let Some(reg) = self
                                .extract_var_name(right)
                                .as_deref()
                                .and_then(|n| self.spilled_arg_register_from_var_name(n))
                            {
                                let base_width = self.infer_expr_size(right).unwrap_or(0);
                                let ptr_width = self.convention.pointer_width();
                                if base_width >= ptr_width {
                                    self.record_hint_for_arg_register(&reg, |h| {
                                        h.is_pointer_arithmetic = true
                                    });
                                }
                            }
                        }
                    }
                    if right_is_offset {
                        if let ExprKind::Var(var) = &left.kind {
                            let base_width =
                                self.infer_expr_size(left).unwrap_or(var.size).max(var.size);
                            if base_width >= 8 {
                                self.record_usage_hint(&var.name.to_lowercase(), |h| {
                                    h.is_pointer_arithmetic = true
                                });
                            }
                        } else if let Some(reg) = self
                            .extract_var_name(left)
                            .as_deref()
                            .and_then(|n| self.spilled_arg_register_from_var_name(n))
                        {
                            // `left` is the spill-slot reload of a
                            // parameter register — the structurer
                            // folded `rax = *(rbp+offset)` into the
                            // pointer-arith expression so the
                            // register name is gone, but the prologue
                            // scan still tells us which arg lived at
                            // that offset. See
                            // `[[project_structurer_ordering_refactor]]`.
                            //
                            // Require BOTH: pointer-width address
                            // load AND a SCALED-INDEX right-hand side
                            // (`Mul` / `Shl`). A small IntLit offset
                            // alone — codex example
                            // `long n + 1` lifts to
                            // `Deref(rbp-8, 8) + 1` — is ambiguous
                            // between pointer-arith and 64-bit
                            // integer arithmetic, so we don't make
                            // the call without the stronger signal.
                            // The width threshold comes from the
                            // active ABI's `pointer_width()` so a
                            // future 32-bit convention (ILP32 RV32)
                            // can accept 4-byte reloads. Codex
                            // review on PR #32 passes 2+4+6.
                            let base_width = self.infer_expr_size(left).unwrap_or(0);
                            let ptr_width = self.convention.pointer_width();
                            let right_has_scaled_index = matches!(
                                &right.kind,
                                ExprKind::BinOp {
                                    op: BinOpKind::Mul | BinOpKind::Shl,
                                    ..
                                }
                            );
                            if base_width >= ptr_width && right_has_scaled_index {
                                self.record_hint_for_arg_register(&reg, |h| {
                                    h.is_pointer_arithmetic = true
                                });
                            }
                        }
                    }
                }

                // Check for signed comparisons
                let is_signed_cmp = matches!(
                    op,
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge
                );

                // Check for unsigned shift right (typically unsigned)
                if matches!(op, BinOpKind::Shr) {
                    if let ExprKind::Var(var) = &left.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_unsigned_ops = true
                        });
                    }
                }

                let left_is_dereferenced =
                    is_dereferenced && matches!(op, BinOpKind::Add | BinOpKind::Sub);
                self.analyze_expr_reads_with_context(left, left_is_dereferenced, is_signed_cmp);
                self.analyze_expr_reads_with_context(right, false, is_signed_cmp);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.analyze_expr_reads_with_context(operand, false, is_comparison);
            }
            ExprKind::Deref { addr, size } => {
                // The address expression is being dereferenced.
                // Clear the float-context override while walking the
                // ADDRESS — a nested ArrayAccess inside the addr is
                // an outer-pointer-to-pointer access; its element
                // type is the address being dereferenced, not the
                // float value the outer load eventually yields.
                // Same rationale as the ArrayAccess index scope —
                // codex review on PR #38 pass 3.
                let saved_float_dest = self.current_rhs_float_dest_size;
                self.current_rhs_float_dest_size = 0;
                self.analyze_expr_reads_with_context(addr, true, false);
                self.current_rhs_float_dest_size = saved_float_dest;

                // Track element type and dereference count for base variables.
                // Use the int default (not the float-context override) for
                // plain `Deref(base)` — `movq xmm0, [rdi]` lifts this way and
                // is an integer-SIMD load despite landing in an xmm register.
                // The float context only fires for ArrayAccess (indexed
                // load `arr[i]` — the canonical scalar SSE pattern).
                // Codex review on PR #38 pass 2.
                if let Some(base_name) = self.extract_var_name(addr) {
                    let elem_type = Self::infer_type_from_size(*size as usize);
                    self.record_usage_hint(&base_name, |h| {
                        h.deref_count += 1;
                        Self::merge_deref_element_type(h, &elem_type);
                    });
                    // Propagate to a spilled parameter only when the
                    // ADDRESS load (the spill reload itself) is wide
                    // enough to be a pointer. Use
                    // `infer_expr_size(addr)` rather than the outer
                    // `*size` — the outer size is the POINTEE width
                    // (the element being read through the pointer),
                    // while we want the WIDTH OF THE POINTER VALUE.
                    // For `int *p; return *p;` the IR is
                    // `Deref(Deref(rbp-8, 8), 4)`: outer size=4 (int)
                    // but the addr load is 8 (pointer). The width
                    // threshold comes from the ABI's `pointer_width()`
                    // — 8 today, 4 if a future ILP32 convention lands.
                    // Codex review on PR #32 passes 3+6.
                    let addr_width = self.infer_expr_size(addr).unwrap_or(0);
                    let ptr_width = self.convention.pointer_width();
                    if addr_width >= ptr_width {
                        if let Some(reg) = self.spilled_arg_register_from_var_name(&base_name) {
                            // Same as the parent Deref branch: do NOT use
                            // the float-context override here. The spill-
                            // slot bridge fires for plain pointer reloads
                            // (`mov rax, [rbp-16]`) too, where the float
                            // context isn't valid evidence.
                            let elem_type_inner = Self::infer_type_from_size(*size as usize);
                            self.record_hint_for_arg_register(&reg, |h| {
                                h.is_dereferenced = true;
                                h.deref_count += 1;
                                Self::merge_deref_element_type(h, &elem_type_inner);
                            });
                        }
                    }
                }
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                // Base is being used as a pointer/array.
                //
                // Clear the float-context override while walking the
                // BASE recursively — a nested `ArrayAccess(inner, j,
                // 8)` for a pointer table `ptrs[i][j]` should record
                // `inner` as a pointer-typed element, not the float
                // value the OUTER access eventually yields. The
                // IMMEDIATE element-type assignment below (the
                // extract_var_name + merge_deref_element_type lines)
                // still uses the float context for the outer base.
                // Codex review on PR #38 pass 4.
                let saved_float_dest = self.current_rhs_float_dest_size;
                self.current_rhs_float_dest_size = 0;
                self.analyze_expr_reads_with_context(base, true, false);
                self.current_rhs_float_dest_size = saved_float_dest;

                // Mark base as array access and track element type
                if let Some(base_name) = self.extract_var_name(base) {
                    let elem_type = self.infer_deref_element_type(*element_size);
                    self.record_usage_hint(&base_name, |h| {
                        h.is_array_access = true;
                        h.deref_count += 1;
                        Self::merge_deref_element_type(h, &elem_type);
                    });
                    if let Some(reg) = self.spilled_arg_register_from_var_name(&base_name) {
                        let elem_type_inner = self.infer_deref_element_type(*element_size);
                        self.record_hint_for_arg_register(&reg, |h| {
                            h.is_array_access = true;
                            h.is_pointer_arithmetic = true;
                            h.deref_count += 1;
                            Self::merge_deref_element_type(h, &elem_type_inner);
                        });
                    }
                }

                // Index might be an array index parameter
                if let ExprKind::Var(var) = &index.kind {
                    self.record_usage_hint(&var.name.to_lowercase(), |h| h.is_array_index = true);
                }
                // Scope the float-context override to the BASE only.
                // A nested ArrayAccess in the index subexpression
                // (`xs[idx[i]]`) is a separate integer load — its
                // base should NOT inherit the outer SSE float
                // context. Codex review on PR #38 pass 3.
                let saved_float_dest = self.current_rhs_float_dest_size;
                self.current_rhs_float_dest_size = 0;
                self.analyze_expr_reads_with_context(index, false, false);
                self.current_rhs_float_dest_size = saved_float_dest;
            }
            ExprKind::BitField { expr, .. } => {
                self.analyze_expr_reads_with_context(expr, false, false);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.analyze_expr_reads_with_context(rhs, false, false);
                // Don't analyze LHS reads - it's being written
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    self.analyze_expr_reads_with_context(addr, true, false);
                }
            }
            ExprKind::Call { target, args } => {
                self.observe_x87_call(target, args);
                if let super::expression::CallTarget::Indirect(inner) = target {
                    if let Some(idx) = self.resolve_param_index_from_expr_precise(inner) {
                        self.record_function_pointer_call_signature_by_index(idx, args);
                    } else if let ExprKind::Var(var) = &inner.kind {
                        let name = var.name.to_lowercase();
                        if self.arg_register_index(&name).is_some() {
                            self.record_function_pointer_call_signature(&name, args);
                        } else if let Some(idx) = self.resolve_alias_param_index(&name) {
                            self.record_function_pointer_call_signature_by_index(idx, args);
                        }
                    }
                    self.analyze_expr_reads_with_context(inner, false, false);
                } else if let super::expression::CallTarget::IndirectGot { expr, .. } = target {
                    if let Some(idx) = self.resolve_param_index_from_expr_precise(expr) {
                        self.record_function_pointer_call_signature_by_index(idx, args);
                    } else if let ExprKind::Var(var) = &expr.kind {
                        let name = var.name.to_lowercase();
                        if self.arg_register_index(&name).is_some() {
                            self.record_function_pointer_call_signature(&name, args);
                        } else if let Some(idx) = self.resolve_alias_param_index(&name) {
                            self.record_function_pointer_call_signature_by_index(idx, args);
                        }
                    }
                    self.analyze_expr_reads_with_context(expr, false, false);
                }

                // Check if calling a string function
                let func_name = self.extract_call_name(target);
                if let Some(fn_name) = &func_name {
                    self.observe_va_start_call(fn_name, args);
                    self.observe_variadic_forwarding_call(fn_name, args);
                    self.observe_printf_format_forwarding_call(fn_name, args);
                }
                let is_string_fn = func_name
                    .as_ref()
                    .map(|n| {
                        let clean_name = n.strip_prefix('_').unwrap_or(n);
                        self.string_functions.contains(clean_name)
                    })
                    .unwrap_or(false);

                for (i, arg) in args.iter().enumerate() {
                    // First arg to string functions is typically a string
                    if is_string_fn && i == 0 {
                        if let ExprKind::Var(var) = &arg.kind {
                            self.record_usage_hint(&var.name.to_lowercase(), |h| {
                                h.is_string_arg = true
                            });
                        }
                    }

                    // Record which functions parameters are passed to.
                    if let Some(fn_name) = &func_name {
                        let var_name = self.extract_var_name(arg);
                        if let Some(name) = &var_name {
                            self.record_usage_hint(name, |h| {
                                h.passed_to_functions.push(fn_name.clone())
                            });
                        }

                        let is_callback_slot = Self::is_callback_position(fn_name, i);
                        let mut resolved_param_idx =
                            self.resolve_param_index_from_expr_precise(arg);
                        let mut used_shape_fallback = false;
                        let mut used_slot_fallback = false;
                        let mut used_alias_latest_fallback = false;
                        let mut callback_excluded_indices = HashSet::new();
                        let mut callback_name_reused_non_callback_arg = false;
                        let mut var_name_direct_param_idx = None;
                        if is_callback_slot {
                            if let Some(name) = &var_name {
                                var_name_direct_param_idx =
                                    self.resolve_param_index_from_name_shallow(name);
                            }
                            if let Some(name) = &var_name {
                                callback_name_reused_non_callback_arg =
                                    args.iter().enumerate().any(|(other_i, other_arg)| {
                                        other_i != i
                                            && ParameterUsageHints::callback_signature(
                                                fn_name, other_i,
                                            )
                                            .is_none()
                                            && self.extract_var_name(other_arg).as_deref()
                                                == Some(name.as_str())
                                    });
                            }
                            for (other_i, other_arg) in args.iter().enumerate() {
                                if other_i == i
                                    || ParameterUsageHints::callback_signature(fn_name, other_i)
                                        .is_some()
                                {
                                    continue;
                                }
                                if let Some(other_idx) =
                                    self.resolve_param_index_from_expr_shallow(other_arg)
                                {
                                    callback_excluded_indices.insert(other_idx);
                                }
                            }
                            if let Some(idx) = resolved_param_idx {
                                if callback_excluded_indices.contains(&idx) {
                                    resolved_param_idx = None;
                                }
                            }
                        }
                        if is_callback_slot {
                            let callback_slots = self.callback_slot_indices(fn_name);
                            if Self::prefer_slot_ordinal_callback_fallback(fn_name)
                                && callback_slots.len() > 1
                            {
                                if let Some(name) = &var_name {
                                    if self.alias_candidate_indices(name).len() > 1 {
                                        resolved_param_idx = None;
                                    }
                                }
                            }
                            if callback_name_reused_non_callback_arg
                                && callback_slots.len() == 1
                                && !Self::prefer_slot_ordinal_callback_fallback(fn_name)
                            {
                                resolved_param_idx = None;
                            }
                            if callback_slots.len() == 1
                                && !Self::prefer_slot_ordinal_callback_fallback(fn_name)
                            {
                                if let Some(name) = &var_name {
                                    if let Some(idx) = self.resolve_latest_alias_param_index(name) {
                                        let ambiguous_alias =
                                            self.alias_candidate_indices(name).len() > 1;
                                        let conflicts_non_callback =
                                            callback_excluded_indices.contains(&idx);
                                        if (resolved_param_idx.is_none() || ambiguous_alias)
                                            && !conflicts_non_callback
                                        {
                                            resolved_param_idx = Some(idx);
                                            used_alias_latest_fallback = true;
                                        }
                                    }
                                    if resolved_param_idx.is_none() {
                                        if let Some(idx) =
                                            self.resolve_param_index_via_value_alias_chain(name)
                                        {
                                            if !callback_excluded_indices.contains(&idx) {
                                                resolved_param_idx = Some(idx);
                                                used_alias_latest_fallback = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if is_callback_slot && resolved_param_idx.is_none() {
                            let callback_slots = self.callback_slot_indices(fn_name);
                            if resolved_param_idx.is_none() {
                                if Self::prefer_slot_ordinal_callback_fallback(fn_name)
                                    && (callback_slots.len() > 1
                                        || callback_slots.as_slice() == [0])
                                {
                                    // APIs that preserve callback ordering in wrappers
                                    // (e.g., pthread_atfork, on_exit) often map callback slots
                                    // directly to same-ordinal parameters.
                                    resolved_param_idx = Some(i);
                                    used_slot_fallback = true;
                                } else if callback_slots.len() == 1
                                    && callback_excluded_indices.is_empty()
                                    && callback_name_reused_non_callback_arg
                                {
                                    // If the callback expression aliases a non-callback argument
                                    // expression and we cannot map by data flow, keep the callback
                                    // at the call-site ordinal instead of reusing that conflicting
                                    // non-callback parameter index.
                                    resolved_param_idx = Some(i);
                                    used_slot_fallback = true;
                                } else {
                                    resolved_param_idx = self
                                        .fallback_callback_param_index_excluding(
                                            &callback_excluded_indices,
                                        )
                                        .or_else(|| self.fallback_callback_param_index());
                                    used_shape_fallback = resolved_param_idx.is_some();
                                }
                            }
                            if used_shape_fallback
                                && !self
                                    .should_use_shape_callback_fallback(arg, var_name.as_deref())
                            {
                                used_shape_fallback = false;
                                resolved_param_idx = None;
                            }
                            if used_shape_fallback
                                && callback_slots.len() == 1
                                && !Self::prefer_slot_ordinal_callback_fallback(fn_name)
                            {
                                used_alias_latest_fallback = true;
                                used_shape_fallback = false;
                            }
                        }
                        if is_callback_slot {
                            let callback_slots = self.callback_slot_indices(fn_name);
                            let var_name_conflicts_non_callback = var_name_direct_param_idx
                                .map(|idx| callback_excluded_indices.contains(&idx))
                                .unwrap_or(false);
                            let var_name_conflicts_resolved = matches!(
                                (var_name_direct_param_idx, resolved_param_idx),
                                (Some(var_idx), Some(resolved_idx)) if var_idx != resolved_idx
                            );
                            if let Some(name) = &var_name {
                                if !var_name_conflicts_non_callback && !var_name_conflicts_resolved
                                {
                                    self.record_usage_hint(name, |h| {
                                        h.passed_as_callback_to.push((fn_name.clone(), i));
                                        h.function_pointer_confidence =
                                            h.function_pointer_confidence.saturating_add(4);
                                        h.add_function_pointer_reason(format!(
                                            "passed to '{}' argument {} (callback slot)",
                                            fn_name, i
                                        ));
                                    });
                                }
                            }
                            if let Some(param_idx) = resolved_param_idx {
                                let suppress_shape_reason = used_shape_fallback
                                    && callback_slots.len() == 1
                                    && !Self::prefer_slot_ordinal_callback_fallback(fn_name);
                                let inferred_same_slot =
                                    Self::prefer_slot_ordinal_callback_fallback(fn_name)
                                        && callback_slots.len() > 1
                                        && param_idx == i;
                                let hints = self.param_hints.entry(param_idx).or_default();
                                hints.is_function_pointer = true;
                                hints.function_pointer_confidence =
                                    hints.function_pointer_confidence.saturating_add(4);
                                hints.passed_as_callback_to.push((fn_name.clone(), i));
                                hints.add_function_pointer_reason(format!(
                                    "[source=alias] alias/forwarded value passed to '{}' argument {} (callback slot)",
                                    fn_name, i
                                ));
                                if used_shape_fallback && !suppress_shape_reason {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=shape-fallback] mapped callback slot '{}' argument {} by ABI-shaped fallback",
                                        fn_name, i
                                    ));
                                }
                                if used_alias_latest_fallback || suppress_shape_reason {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=alias-latest] mapped callback slot '{}' argument {} by latest alias assignment",
                                        fn_name, i
                                    ));
                                }
                                if used_slot_fallback {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=slot-fallback] mapped callback slot '{}' argument {} by slot ordinal",
                                        fn_name, i
                                    ));
                                } else if inferred_same_slot {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=slot-fallback] callback slot '{}' argument {} stayed on the matching ordinal parameter",
                                        fn_name, i
                                    ));
                                }
                            }
                        }
                        if let Some(sig) = self.callback_signature_from_summary(fn_name, i) {
                            let var_name_conflicts_non_callback = var_name_direct_param_idx
                                .map(|idx| callback_excluded_indices.contains(&idx))
                                .unwrap_or(false);
                            let var_name_conflicts_resolved = matches!(
                                (var_name_direct_param_idx, resolved_param_idx),
                                (Some(var_idx), Some(resolved_idx)) if var_idx != resolved_idx
                            );
                            if let Some(name) = &var_name {
                                if !var_name_conflicts_non_callback && !var_name_conflicts_resolved
                                {
                                    let sig_for_hint = sig.clone();
                                    self.record_usage_hint(name, |h| {
                                        h.is_function_pointer = true;
                                        h.function_pointer_confidence =
                                            h.function_pointer_confidence.saturating_add(5);
                                        h.add_function_pointer_reason(format!(
                                            "[source=summary] summary marks '{}' argument {} as function-pointer callback",
                                            fn_name, i
                                        ));
                                        if let ParamType::FunctionPointer {
                                            return_type,
                                            params,
                                        } = sig_for_hint.clone()
                                        {
                                            h.function_pointer_arg_types = params;
                                            h.function_pointer_return_type = Some(*return_type);
                                        }
                                    });
                                }
                            }
                            if let Some(param_idx) = resolved_param_idx {
                                let hints = self.param_hints.entry(param_idx).or_default();
                                hints.is_function_pointer = true;
                                hints.function_pointer_confidence =
                                    hints.function_pointer_confidence.saturating_add(5);
                                hints.passed_as_callback_to.push((fn_name.clone(), i));
                                hints.add_function_pointer_reason(format!(
                                    "[source=summary] summary callback type propagated through alias for '{}' argument {}",
                                    fn_name, i
                                ));
                                if let ParamType::FunctionPointer {
                                    return_type,
                                    params,
                                } = sig
                                {
                                    hints.function_pointer_arg_types = params;
                                    hints.function_pointer_return_type = Some(*return_type);
                                }
                            }
                        }
                    }

                    self.analyze_expr_reads_with_context(arg, false, false);
                }
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.analyze_expr_reads_with_context(inner, is_dereferenced, is_comparison);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.analyze_expr_reads(cond);
                self.analyze_expr_reads(then_expr);
                self.analyze_expr_reads(else_expr);
            }
            _ => {}
        }
    }

    /// Returns true when a function argument position is typically a callback.
    fn is_callback_position(function_name: &str, arg_index: usize) -> bool {
        ParameterUsageHints::callback_signature(function_name, arg_index).is_some()
    }

    fn param_type_from_summary(summary: &super::interprocedural::SummaryType) -> ParamType {
        use super::interprocedural::SummaryType;
        match summary {
            SummaryType::Unknown => ParamType::Unknown,
            SummaryType::Void => ParamType::Void,
            SummaryType::Bool => ParamType::Bool,
            SummaryType::SignedInt(bits) => ParamType::SignedInt((*bits).min(64)),
            SummaryType::UnsignedInt(bits) => ParamType::UnsignedInt((*bits).min(64)),
            SummaryType::Float(bits) => ParamType::Float((*bits).min(64)),
            SummaryType::Pointer(_) => ParamType::Pointer,
            SummaryType::Array(_, _) => ParamType::Pointer,
            SummaryType::Struct(_) => ParamType::Pointer,
            SummaryType::FunctionPointer {
                return_type,
                params,
            } => ParamType::FunctionPointer {
                return_type: Box::new(Self::param_type_from_summary(return_type)),
                params: params.iter().map(Self::param_type_from_summary).collect(),
            },
        }
    }

    fn callback_signature_from_summary(
        &self,
        function_name: &str,
        arg_index: usize,
    ) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        let ty = summary.param_types.get(&arg_index)?;
        match ty {
            super::interprocedural::SummaryType::FunctionPointer { .. } => {
                Some(Self::param_type_from_summary(ty))
            }
            _ => None,
        }
    }

    fn return_function_pointer_from_summary(&self, function_name: &str) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        let ty = summary.return_type.as_ref()?;
        match ty {
            super::interprocedural::SummaryType::FunctionPointer { .. } => {
                Some(Self::param_type_from_summary(ty))
            }
            _ => None,
        }
    }

    fn return_type_from_summary(&self, function_name: &str) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        summary
            .return_type
            .as_ref()
            .map(Self::param_type_from_summary)
    }

    fn builtin_signature_type_database() -> &'static TypeDatabase {
        static DB: OnceLock<TypeDatabase> = OnceLock::new();
        DB.get_or_init(|| {
            let mut db = TypeDatabase::new();
            load_posix_types(&mut db);
            load_linux_types(&mut db);
            load_libc_functions(&mut db);
            db
        })
    }

    fn builtin_function_params(function_name: &str) -> Option<Vec<(String, ParamType)>> {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let proto = Self::builtin_signature_type_database().get_function(clean)?;
        proto
            .parameters
            .iter()
            .map(|(name, ty)| Some((name.clone(), Self::param_type_from_ctype(ty)?)))
            .collect()
    }

    fn known_function_params(function_name: &str) -> Option<Vec<(String, ParamType)>> {
        if let Some(params) = get_known_function_params(function_name) {
            return Some(
                params
                    .iter()
                    .map(|(name, ty)| ((*name).to_string(), ty.clone()))
                    .collect(),
            );
        }

        Self::builtin_function_params(function_name)
    }

    fn builtin_call_return_type(function_name: &str) -> Option<ParamType> {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let proto = Self::builtin_signature_type_database().get_function(clean)?;
        Self::param_type_from_ctype(&proto.return_type)
    }

    fn param_type_from_ctype(ty: &CType) -> Option<ParamType> {
        match ty {
            CType::Void => Some(ParamType::Void),
            CType::Int(int_ty) => Some(if int_ty.signed {
                ParamType::SignedInt((int_ty.size as u8).saturating_mul(8))
            } else {
                ParamType::UnsignedInt((int_ty.size as u8).saturating_mul(8))
            }),
            CType::Float(float_ty) => {
                Some(ParamType::Float((float_ty.size as u8).saturating_mul(8)))
            }
            CType::Pointer(inner) => match Self::param_type_from_ctype(inner) {
                Some(ParamType::Void) => Some(ParamType::Pointer),
                Some(inner_ty) => Some(ParamType::TypedPointer(Box::new(inner_ty))),
                None => Some(ParamType::Pointer),
            },
            CType::Array(array_ty) => match Self::param_type_from_ctype(&array_ty.element) {
                Some(ParamType::Void) => Some(ParamType::Pointer),
                Some(inner_ty) => Some(ParamType::TypedPointer(Box::new(inner_ty))),
                None => Some(ParamType::Pointer),
            },
            CType::Struct(struct_ty) => struct_ty
                .name
                .as_ref()
                .map(|name| ParamType::Named(format!("struct {name}"))),
            CType::Union(union_ty) => union_ty
                .name
                .as_ref()
                .map(|name| ParamType::Named(format!("union {name}"))),
            CType::Enum(enum_ty) => Some(ParamType::UnsignedInt(
                (enum_ty.underlying_size as u8).saturating_mul(8),
            )),
            CType::Function(func_ty) => Some(ParamType::FunctionPointer {
                return_type: Box::new(
                    Self::param_type_from_ctype(&func_ty.return_type).unwrap_or(ParamType::Unknown),
                ),
                params: func_ty
                    .parameters
                    .iter()
                    .filter_map(|param| Self::param_type_from_ctype(&param.param_type))
                    .collect(),
            }),
            CType::Typedef(typedef_ty) => Self::param_type_from_ctype(&typedef_ty.target),
            CType::Named(name) => Some(ParamType::Named(name.clone())),
        }
    }

    fn known_call_return_type(function_name: &str) -> Option<ParamType> {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        match clean {
            "builtin_prefetch" | "builtin_trap" | "builtin_unreachable" => Some(ParamType::Void),
            "builtin_return_address" => Some(ParamType::Pointer),
            "qsort" | "qsort_r" | "qsort_s" | "bsd_qsort_r" => Some(ParamType::Void),
            "hexray_qsort_r"
            | "hexray_bsd_qsort_r"
            | "pthread_create"
            | "on_exit"
            | "hexray_on_exit"
            | "pthread_atfork"
            | "hexray_pthread_atfork" => Some(ParamType::SignedInt(32)),
            "bsearch" => Some(ParamType::Pointer),
            "signal" | "bsd_signal" | "sysv_signal" | "sigset" => {
                Some(ParamType::FunctionPointer {
                    return_type: Box::new(ParamType::Void),
                    params: vec![ParamType::SignedInt(32)],
                })
            }
            _ => Self::builtin_call_return_type(clean),
        }
    }

    fn is_discardable_tail_call_return_function(function_name: &str) -> bool {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        matches!(
            clean,
            "pthread_mutex_lock"
                | "pthread_mutex_unlock"
                | "pthread_cond_broadcast"
                | "pthread_cond_signal"
                | "pthread_detach"
                | "pthread_join"
                | "pthread_rwlock_unlock"
                | "pthread_spin_unlock"
                | "free"
                | "kfree"
                | "fclose"
                | "pthread_setspecific"
                | "sigaction"
                | "sigsuspend"
                | "sigprocmask"
                | "pthread_sigmask"
                | "sigemptyset"
                | "sigfillset"
                | "sigaddset"
                | "sigdelset"
                | "sigismember"
                | "kill"
                | "raise"
                | "tgkill"
                | "usleep"
                | "sleep"
        )
    }

    fn infer_tail_call_return_type(&self, expr: &Expr) -> Option<ParamType> {
        if let ExprKind::Cast { expr: inner, .. } = &expr.kind {
            return self.infer_tail_call_return_type(inner);
        }
        if let ExprKind::Call { target, args } = &expr.kind {
            if let Some(name) = self.extract_call_name(target) {
                if crate::is_noreturn_function_name(&name) {
                    return Some(ParamType::Void);
                }
                if let Some(ty) = self.infer_atomic_pseudo_call_return_type(&name, args) {
                    return Some(ty);
                }
                if Self::is_x87_mnemonic(&name) {
                    return Some(ParamType::Float(80));
                }
                if let Some(summary_ty) = self.return_type_from_summary(&name) {
                    return Some(summary_ty);
                }
                if let Some(known_ty) = Self::known_call_return_type(&name) {
                    return Some(known_ty);
                }
            }
            return Some(ParamType::SignedInt(32));
        }
        None
    }

    fn infer_tail_call_forwarded_return_type(&self, expr: &Expr) -> Option<ParamType> {
        if let ExprKind::Cast { expr: inner, .. } = &expr.kind {
            return self.infer_tail_call_forwarded_return_type(inner);
        }
        if let ExprKind::Call { target, .. } = &expr.kind {
            if let Some(name) = self.extract_call_name(target) {
                if Self::is_discardable_tail_call_return_function(&name) {
                    return None;
                }
            }
        }
        self.infer_tail_call_return_type(expr)
    }

    fn infer_atomic_pseudo_call_return_type(&self, name: &str, args: &[Expr]) -> Option<ParamType> {
        match name {
            "__atomic_thread_fence" | "atomic_store" => Some(ParamType::Void),
            "atomic_compare_exchange_strong" => Some(ParamType::Bool),
            "atomic_exchange" | "atomic_fetch_add" | "atomic_fetch_sub" | "atomic_fetch_and"
            | "atomic_fetch_or" | "atomic_fetch_xor" => self
                .infer_atomic_pseudo_call_result_size(args)
                .map(Self::signed_int_param_type_for_size)
                .or(Some(ParamType::SignedInt(32))),
            _ => None,
        }
    }

    fn infer_atomic_pseudo_call_result_size(&self, args: &[Expr]) -> Option<u8> {
        let ptr = args.first()?;
        Self::infer_pointee_size_from_expr(ptr)
    }

    fn infer_pointee_size_from_expr(expr: &Expr) -> Option<u8> {
        match &expr.kind {
            ExprKind::AddressOf(inner) => Self::infer_pointee_size_from_expr(inner)
                .or_else(|| Self::infer_terminal_expr_size(inner)),
            ExprKind::Deref { size, .. } => Some(*size),
            ExprKind::Var(var) => Some(var.size).filter(|size| *size > 0),
            ExprKind::FieldAccess { base, .. } | ExprKind::Cast { expr: base, .. } => {
                Self::infer_pointee_size_from_expr(base)
            }
            ExprKind::ArrayAccess { element_size, .. } => Some(*element_size as u8),
            _ => None,
        }
    }

    fn infer_terminal_expr_size(expr: &Expr) -> Option<u8> {
        match &expr.kind {
            ExprKind::Var(var) => Some(var.size).filter(|size| *size > 0),
            ExprKind::Deref { size, .. } => Some(*size),
            ExprKind::ArrayAccess { element_size, .. } => Some(*element_size as u8),
            ExprKind::FieldAccess { base, .. } | ExprKind::Cast { expr: base, .. } => {
                Self::infer_terminal_expr_size(base)
            }
            _ => None,
        }
    }

    fn signed_int_param_type_for_size(size: u8) -> ParamType {
        match size {
            1 => ParamType::SignedInt(8),
            2 => ParamType::SignedInt(16),
            4 => ParamType::SignedInt(32),
            8 => ParamType::SignedInt(64),
            _ => ParamType::SignedInt(64),
        }
    }

    /// Infers a type for an argument passed into an indirect function call.
    fn infer_indirect_call_arg_type(expr: &Expr) -> ParamType {
        match &expr.kind {
            ExprKind::Deref { .. }
            | ExprKind::AddressOf(_)
            | ExprKind::ArrayAccess { .. }
            | ExprKind::FieldAccess { .. }
            | ExprKind::GotRef { .. } => ParamType::Pointer,
            ExprKind::IntLit(n) => {
                if *n >= i32::MIN as i128 && *n <= i32::MAX as i128 {
                    ParamType::SignedInt(32)
                } else {
                    ParamType::SignedInt(64)
                }
            }
            ExprKind::Var(var) => {
                let name = var.name.to_lowercase();
                if name.starts_with("xmm") || name.starts_with("ymm") || name.starts_with("zmm") {
                    match var.size {
                        0..=4 => ParamType::Float(32),
                        5..=8 => ParamType::Float(64),
                        size => ParamType::SimdFloat(size),
                    }
                } else if name.starts_with("d") {
                    ParamType::Float(64)
                } else if name.starts_with("s") {
                    ParamType::Float(32)
                } else {
                    match var.size {
                        1 => ParamType::SignedInt(8),
                        2 => ParamType::SignedInt(16),
                        4 => ParamType::SignedInt(32),
                        8 => ParamType::SignedInt(64),
                        _ => ParamType::SignedInt(64),
                    }
                }
            }
            ExprKind::Cast {
                to_size,
                signed,
                expr: _,
            } => match (*to_size, *signed) {
                (1, true) => ParamType::SignedInt(8),
                (2, true) => ParamType::SignedInt(16),
                (4, true) => ParamType::SignedInt(32),
                (8, true) => ParamType::SignedInt(64),
                (1, false) => ParamType::UnsignedInt(8),
                (2, false) => ParamType::UnsignedInt(16),
                (4, false) => ParamType::UnsignedInt(32),
                (8, false) => ParamType::UnsignedInt(64),
                _ => ParamType::SignedInt(64),
            },
            _ => ParamType::SignedInt(64),
        }
    }

    fn merge_param_types(a: &ParamType, b: &ParamType) -> ParamType {
        match (a, b) {
            (ParamType::Unknown, t) | (t, ParamType::Unknown) => t.clone(),
            (ParamType::Pointer, ParamType::TypedPointer(inner))
            | (ParamType::TypedPointer(inner), ParamType::Pointer) => {
                ParamType::TypedPointer(inner.clone())
            }
            (ParamType::Pointer, _) | (_, ParamType::Pointer) => ParamType::Pointer,
            (ParamType::TypedPointer(inner_a), ParamType::TypedPointer(inner_b)) => {
                let merged = Self::merge_param_types(inner_a, inner_b);
                if matches!(merged, ParamType::Unknown) {
                    ParamType::Pointer
                } else {
                    ParamType::TypedPointer(Box::new(merged))
                }
            }
            (ParamType::Named(a), ParamType::Named(b)) if a == b => ParamType::Named(a.clone()),
            (ParamType::Float(sa), ParamType::Float(sb)) => ParamType::Float((*sa).max(*sb)),
            (ParamType::SimdInt128, ParamType::SimdInt128) => ParamType::SimdInt128,
            (ParamType::SimdFloat(sa), ParamType::SimdFloat(sb)) => {
                ParamType::SimdFloat((*sa).max(*sb))
            }
            (ParamType::UnsignedLongLong, ParamType::UnsignedLongLong) => {
                ParamType::UnsignedLongLong
            }
            (ParamType::SizeT, ParamType::SizeT) => ParamType::SizeT,
            (ParamType::PtrDiffT, ParamType::PtrDiffT) => ParamType::PtrDiffT,
            (ParamType::UnsignedInt(sa), ParamType::UnsignedInt(sb)) => {
                ParamType::UnsignedInt((*sa).max(*sb))
            }
            (ParamType::SignedInt(sa), ParamType::SignedInt(sb)) => {
                ParamType::SignedInt((*sa).max(*sb))
            }
            (ParamType::UnsignedLongLong, ParamType::UnsignedInt(64))
            | (ParamType::UnsignedInt(64), ParamType::UnsignedLongLong) => {
                ParamType::UnsignedLongLong
            }
            (ParamType::SizeT, ParamType::UnsignedInt(64))
            | (ParamType::UnsignedInt(64), ParamType::SizeT) => ParamType::SizeT,
            (ParamType::PtrDiffT, ParamType::SignedInt(64))
            | (ParamType::SignedInt(64), ParamType::PtrDiffT) => ParamType::PtrDiffT,
            (ParamType::SignedInt(sa), ParamType::UnsignedInt(sb))
            | (ParamType::UnsignedInt(sa), ParamType::SignedInt(sb)) => {
                ParamType::SignedInt((*sa).max(*sb))
            }
            (ParamType::FunctionPointer { .. }, _) | (_, ParamType::FunctionPointer { .. }) => {
                ParamType::Pointer
            }
            _ => ParamType::Unknown,
        }
    }

    fn float_param_type_for_size(size: u8) -> ParamType {
        match size {
            0..=4 => ParamType::Float(32),
            5..=8 => ParamType::Float(64),
            10 => ParamType::Float(80),
            size => ParamType::SimdFloat(size),
        }
    }

    fn observed_float_register_size(&self, idx: usize, reg_name: &str) -> Option<u8> {
        let reg_lower = reg_name.to_lowercase();
        let mut candidates = vec![reg_lower, format!("farg{}", idx)];
        for prefix in ["xmm", "ymm", "zmm"] {
            candidates.push(format!("{prefix}{idx}"));
        }

        candidates
            .into_iter()
            .filter_map(|name| self.value_sizes.get(&name).copied())
            .max()
    }

    fn consistent_observed_float_arg_size(&self) -> Option<u8> {
        let mut observed_sizes = self
            .convention
            .float_arg_registers()
            .iter()
            .enumerate()
            .filter(|(_, reg)| self.observed_float_arg_regs.contains(&reg.to_lowercase()))
            .filter_map(|(idx, reg)| self.observed_float_register_size(idx, reg))
            .filter(|size| *size > 0);

        let first = observed_sizes.next()?;
        observed_sizes.all(|size| size == first).then_some(first)
    }

    fn is_ambiguous_indirect_arg_type(ty: &ParamType) -> bool {
        matches!(ty, ParamType::Unknown | ParamType::SignedInt(64))
    }

    fn record_function_pointer_call_signature(&mut self, reg_name: &str, args: &[Expr]) {
        let Some(idx) = self.arg_register_index(reg_name) else {
            return;
        };
        self.record_function_pointer_call_signature_by_index(idx, args);
    }

    fn record_function_pointer_call_signature_by_index(&mut self, idx: usize, args: &[Expr]) {
        let mut inferred: Vec<ParamType> = args
            .iter()
            .map(Self::infer_indirect_call_arg_type)
            .collect();
        let informative_count = inferred
            .iter()
            .filter(|ty| !Self::is_ambiguous_indirect_arg_type(ty))
            .count();
        if informative_count == 0 {
            inferred = vec![ParamType::Pointer; inferred.len()];
        } else {
            inferred = inferred
                .into_iter()
                .map(|ty| {
                    if Self::is_ambiguous_indirect_arg_type(&ty) {
                        ParamType::Pointer
                    } else {
                        ty
                    }
                })
                .collect();
        }

        let hints = self.param_hints.entry(idx).or_default();
        hints.is_function_pointer = true;
        hints.function_pointer_confidence = hints
            .function_pointer_confidence
            .saturating_add(if informative_count > 0 { 2 } else { 1 });
        hints.add_function_pointer_reason(if informative_count > 0 {
            format!(
                "used as indirect call target with {} observed argument(s)",
                args.len()
            )
        } else {
            "used as indirect call target (argument types ambiguous)".to_string()
        });
        if hints.function_pointer_return_type.is_none() {
            hints.function_pointer_return_type = Some(ParamType::SignedInt(64));
        }
        if hints.function_pointer_arg_types.is_empty() {
            hints.function_pointer_arg_types = inferred;
            return;
        }

        let common_len = hints.function_pointer_arg_types.len().min(inferred.len());
        for (i, inferred_ty) in inferred.iter().enumerate().take(common_len) {
            let merged = Self::merge_param_types(&hints.function_pointer_arg_types[i], inferred_ty);
            hints.function_pointer_arg_types[i] = merged;
        }

        if inferred.len() > hints.function_pointer_arg_types.len() {
            hints
                .function_pointer_arg_types
                .extend_from_slice(&inferred[hints.function_pointer_arg_types.len()..]);
        }
    }

    fn infer_return_function_pointer(&self, expr: &Expr) -> Option<ParamType> {
        match &expr.kind {
            ExprKind::Var(var) => {
                if let Some(idx) = self.arg_register_index(&var.name) {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        let ty = hints.infer_type(var.size.max(8));
                        if matches!(ty, ParamType::FunctionPointer { .. }) {
                            return Some(ty);
                        }
                    }
                }
                self.value_function_pointer_types
                    .get(&var.name.to_lowercase())
                    .cloned()
            }
            ExprKind::Call { target, .. } => {
                let name = self.extract_call_name(target)?;
                let clean = name.strip_prefix('_').unwrap_or(&name);
                match clean {
                    "signal" | "bsd_signal" | "sysv_signal" | "sigset" => {
                        Some(ParamType::FunctionPointer {
                            return_type: Box::new(ParamType::Void),
                            params: vec![ParamType::SignedInt(32)],
                        })
                    }
                    _ => self.return_function_pointer_from_summary(clean),
                }
            }
            ExprKind::Cast { expr: inner, .. } => self.infer_return_function_pointer(inner),
            _ => None,
        }
    }

    fn resolve_alias_param_index(&self, var_name: &str) -> Option<usize> {
        let candidates = self.alias_candidate_indices(var_name);
        if candidates.len() == 1 {
            candidates.iter().next().copied()
        } else {
            None
        }
    }

    fn resolve_latest_alias_param_index(&self, var_name: &str) -> Option<usize> {
        if let Some(idx) = self.function_pointer_alias_latest.get(var_name) {
            return Some(*idx);
        }
        Self::lifted_alias_name_variants(var_name)
            .into_iter()
            .find_map(|name| self.function_pointer_alias_latest.get(&name).copied())
    }

    fn insert_function_pointer_alias_entry(&mut self, name: &str, idx: usize) {
        self.function_pointer_aliases
            .entry(name.to_string())
            .or_default()
            .insert(idx);
        self.function_pointer_alias_latest
            .insert(name.to_string(), idx);
    }

    fn insert_function_pointer_alias(&mut self, lhs_name: &str, idx: usize) {
        self.insert_function_pointer_alias_entry(lhs_name, idx);
        for alias_name in Self::lifted_alias_name_variants(lhs_name) {
            self.insert_function_pointer_alias_entry(&alias_name, idx);
        }
    }

    fn insert_value_alias_entry(&mut self, lhs_name: &str, rhs_name: &str) {
        self.value_alias_latest
            .insert(lhs_name.to_string(), rhs_name.to_string());
    }

    fn insert_value_alias(&mut self, lhs_name: &str, rhs_name: &str) {
        self.insert_value_alias_entry(lhs_name, rhs_name);
        for alias_name in Self::lifted_alias_name_variants(lhs_name) {
            self.insert_value_alias_entry(&alias_name, rhs_name);
        }
    }

    fn resolve_latest_value_alias(&self, var_name: &str) -> Option<String> {
        if let Some(rhs) = self.value_alias_latest.get(var_name) {
            return Some(rhs.clone());
        }
        Self::lifted_alias_name_variants(var_name)
            .into_iter()
            .find_map(|name| self.value_alias_latest.get(&name).cloned())
    }

    fn parse_lifted_hex_suffix(name: &str, prefix: &str) -> Option<u128> {
        let suffix = name.strip_prefix(prefix)?;
        let suffix = suffix.strip_prefix("0x").unwrap_or(suffix);
        u128::from_str_radix(suffix, 16).ok()
    }

    fn lifted_alias_name_variants(var_name: &str) -> Vec<String> {
        let mut variants = Vec::new();
        if let Some(offset_str) = var_name.strip_prefix("stack_") {
            if let Ok(offset) = offset_str.parse::<i128>() {
                if offset < 0 {
                    let abs = (-offset) as u128;
                    // Negative stack slots are frequently locals in lifted IR.
                    // Keep only local-name aliases here to avoid spurious ABI
                    // parameter inference from stack-local traffic.
                    variants.push(format!("local_{:x}", abs));
                } else {
                    variants.push(format!("var_{:x}", offset as u128));
                }
            }
            return variants;
        }

        if var_name.starts_with("arg_") || var_name.starts_with("local_") {
            let abs = Self::parse_lifted_hex_suffix(var_name, "arg_")
                .or_else(|| Self::parse_lifted_hex_suffix(var_name, "local_"));
            if let Some(abs) = abs {
                if var_name.starts_with("arg_") {
                    variants.push(format!("local_{:x}", abs));
                } else {
                    variants.push(format!("arg_{:x}", abs));
                }
                variants.push(format!("stack_-{}", abs));
            }
            return variants;
        }

        if let Some(offset) = Self::parse_lifted_hex_suffix(var_name, "var_") {
            variants.push(format!("stack_{}", offset));
        }
        variants
    }

    fn alias_candidate_indices(&self, var_name: &str) -> BTreeSet<usize> {
        let mut candidates = BTreeSet::new();
        if let Some(indices) = self.function_pointer_aliases.get(var_name) {
            candidates.extend(indices.iter().copied());
        }
        for alias_name in Self::lifted_alias_name_variants(var_name) {
            if let Some(indices) = self.function_pointer_aliases.get(&alias_name) {
                candidates.extend(indices.iter().copied());
            }
        }
        candidates
    }

    fn fallback_callback_param_index(&self) -> Option<usize> {
        let max_from_reads = self
            .read_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
            .max();
        let max_from_writes = self
            .written_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
            .max();
        let max_from_aliases = self
            .function_pointer_aliases
            .values()
            .flat_map(|indices| indices.iter().copied())
            .max();
        [max_from_reads, max_from_writes, max_from_aliases]
            .into_iter()
            .flatten()
            .max()
    }

    fn fallback_callback_param_index_excluding(&self, excluded: &HashSet<usize>) -> Option<usize> {
        let mut candidates = BTreeSet::new();
        for idx in self
            .read_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .written_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .function_pointer_aliases
            .values()
            .flat_map(|indices| indices.iter().copied())
        {
            candidates.insert(idx);
        }
        candidates
            .into_iter()
            .rev()
            .find(|idx| !excluded.contains(idx))
    }

    fn callback_slot_indices(&self, function_name: &str) -> Vec<usize> {
        (0..8)
            .filter(|idx| ParameterUsageHints::callback_signature(function_name, *idx).is_some())
            .collect()
    }

    fn should_use_shape_callback_fallback(&self, expr: &Expr, var_name: Option<&str>) -> bool {
        let Some(name) = var_name else {
            return !matches!(expr.kind, ExprKind::IntLit(_));
        };
        let lowered = name.to_lowercase();
        self.may_alias_parameter(&lowered)
            || self.assigned_value_names.contains(&lowered)
            || self.resolve_alias_param_index(&lowered).is_some()
            || self.resolve_latest_alias_param_index(&lowered).is_some()
            || !self.alias_candidate_indices(&lowered).is_empty()
    }

    fn prefer_slot_ordinal_callback_fallback(function_name: &str) -> bool {
        matches!(
            ParameterUsageHints::normalize_callback_name(function_name),
            "pthread_atfork" | "hexray_pthread_atfork" | "on_exit" | "hexray_on_exit"
        )
    }

    fn resolve_param_index_from_name_internal(
        &self,
        var_name: &str,
        allow_fallback: bool,
    ) -> Option<usize> {
        if let Some(idx) = self.resolve_param_index_from_name_shallow(var_name) {
            return Some(idx);
        }
        if let Some(idx) = self.resolve_param_index_via_value_alias_chain(var_name) {
            return Some(idx);
        }
        if allow_fallback && self.may_alias_parameter(var_name) {
            return self.fallback_callback_param_index();
        }
        None
    }

    fn resolve_param_index_from_name_shallow(&self, var_name: &str) -> Option<usize> {
        if let Some(idx) = self.resolve_alias_param_index(var_name) {
            return Some(idx);
        }
        if self.alias_candidate_indices(var_name).len() > 1 {
            return None;
        }
        if let Some(idx) = self.direct_arg_register_index(var_name) {
            let root = self.copied_arg_root(idx);
            if root != idx {
                return Some(root);
            }

            let lowered = var_name.to_lowercase();
            let seen_as_input = self.read_regs.contains(&lowered)
                || self.read_regs.contains(&format!("arg{}", idx));
            if self.written_regs.contains(&lowered) && !seen_as_input {
                return None;
            }
            return Some(idx);
        }
        if let Some(idx) = Self::lifted_arg_slot_index(&var_name.to_lowercase()) {
            return Some(idx);
        }
        None
    }

    fn resolve_param_index_via_value_alias_chain(&self, var_name: &str) -> Option<usize> {
        let mut queue = VecDeque::new();
        queue.push_back(var_name.to_string());
        for alias in Self::lifted_alias_name_variants(var_name) {
            queue.push_back(alias);
        }
        let mut visited = HashSet::new();
        while let Some(name) = queue.pop_front() {
            let lowered = name.to_lowercase();
            if !visited.insert(lowered.clone()) {
                continue;
            }

            if let Some(idx) = self.resolve_param_index_from_name_shallow(&lowered) {
                return Some(idx);
            }

            if let Some(next) = self.resolve_latest_value_alias(&lowered) {
                queue.push_back(next);
            }
        }
        None
    }

    fn resolve_param_index_from_expr_precise(&self, expr: &Expr) -> Option<usize> {
        self.resolve_param_index_from_expr_internal(expr, false)
    }

    fn resolve_param_index_from_expr_shallow(&self, expr: &Expr) -> Option<usize> {
        if let Some(var_name) = self.extract_var_name(expr) {
            if let Some(idx) = self.resolve_param_index_from_name_shallow(&var_name) {
                return Some(idx);
            }
        }

        if let Some(offset) = self.extract_stack_offset(expr) {
            let stack_name = format!("stack_{}", offset);
            if let Some(idx) = self.resolve_param_index_from_name_shallow(&stack_name) {
                return Some(idx);
            }
        }

        match &expr.kind {
            ExprKind::Cast { expr: inner, .. } => self.resolve_param_index_from_expr_shallow(inner),
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                if lowered.starts_with("arg_")
                    || lowered.starts_with("var_")
                    || lowered.starts_with("local_")
                    || lowered.starts_with("stack_")
                {
                    self.resolve_param_index_from_name_shallow(&lowered)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn resolve_param_index_from_expr_internal(
        &self,
        expr: &Expr,
        allow_fallback: bool,
    ) -> Option<usize> {
        if let Some(var_name) = self.extract_var_name(expr) {
            if let Some(idx) =
                self.resolve_param_index_from_name_internal(&var_name, allow_fallback)
            {
                return Some(idx);
            }
        }

        if let Some(offset) = self.extract_stack_offset(expr) {
            let stack_name = format!("stack_{}", offset);
            if let Some(idx) =
                self.resolve_param_index_from_name_internal(&stack_name, allow_fallback)
            {
                return Some(idx);
            }
        }

        match &expr.kind {
            ExprKind::Cast { expr: inner, .. } => {
                self.resolve_param_index_from_expr_internal(inner, allow_fallback)
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                if lowered.starts_with("arg_")
                    || lowered.starts_with("var_")
                    || lowered.starts_with("local_")
                    || lowered.starts_with("stack_")
                {
                    self.resolve_param_index_from_name_internal(&lowered, allow_fallback)
                        .or_else(|| {
                            if allow_fallback {
                                self.fallback_callback_param_index()
                            } else {
                                None
                            }
                        })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn may_alias_parameter(&self, var_name: &str) -> bool {
        var_name.starts_with("arg")
            || var_name.starts_with("stack_")
            || var_name.starts_with("arg_")
            || var_name.starts_with("var_")
            || var_name.starts_with("local_")
            || self.arg_register_index(var_name).is_some()
    }

    fn extract_var_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(v) => Some(v.name.to_lowercase()),
            ExprKind::Unknown(name) => Some(name.to_lowercase()),
            ExprKind::Deref { .. } => self
                .extract_stack_offset(expr)
                .map(|offset| format!("stack_{}", offset)),
            ExprKind::ArrayAccess { .. } => self
                .extract_stack_offset(expr)
                .map(|offset| format!("stack_{}", offset)),
            ExprKind::Cast { expr: inner, .. } => self.extract_var_name(inner),
            _ => None,
        }
    }

    /// Extracts a register name from an expression if it's a simple register reference.
    fn extract_register_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(var) => Some(var.name.clone()),
            ExprKind::Unknown(name) if self.reg_size_from_name(name) > 0 => Some(name.clone()),
            _ => None,
        }
    }

    /// If `name` is a `stack_{offset}` slot synthesized by
    /// [`Self::extract_var_name`] for a deref expression, and the
    /// prologue scan recorded an argument register spilled to that
    /// exact offset, return that register's canonical name.
    ///
    /// This is the bridge that lets pointer-usage hints flow to a
    /// parameter even after the structurer's simplification folds
    /// the intermediate `Var(rax) = *(rbp+offset)` reload into a
    /// containing expression (so the load surfaces as
    /// `Deref(stack_slot)` and the original register name is gone
    /// from the IR). The `[[project_structurer_ordering_refactor]]`
    /// memo's Option C — recognize collapsed patterns post-simplify
    /// — depends on this lookup.
    fn spilled_arg_register_from_var_name(&self, name: &str) -> Option<String> {
        let offset_str = name.strip_prefix("stack_")?;
        let offset: i128 = offset_str.parse().ok()?;
        if self.invalidated_spill_offsets.contains(&offset) {
            // The slot was overwritten by a non-spill store after
            // the prologue, so loads from it no longer represent
            // the original argument. Codex review on PR #32 pass 9.
            return None;
        }
        self.param_spill_order
            .iter()
            .find(|obs| obs.offset as i128 == offset)
            .map(|obs| obs.register.clone())
    }

    /// Extracts a stack offset from a deref expression.
    fn extract_stack_offset(&self, expr: &Expr) -> Option<i128> {
        match &expr.kind {
            ExprKind::Deref { addr, .. } => {
                if let ExprKind::Var(base) = &addr.kind {
                    if is_stack_base_register(&base.name) {
                        return Some(0);
                    }
                }
                if let ExprKind::BinOp { op, left, right } = &addr.kind {
                    if let ExprKind::Var(base) = &left.kind {
                        if is_stack_base_register(&base.name) {
                            if let ExprKind::IntLit(offset) = &right.kind {
                                let actual = match op {
                                    BinOpKind::Add => *offset,
                                    BinOpKind::Sub => -*offset,
                                    _ => return None,
                                };
                                return Some(actual);
                            }
                        }
                    }
                }
                if let ExprKind::ArrayAccess {
                    base,
                    index,
                    element_size,
                } = &addr.kind
                {
                    return self.extract_stack_offset_from_array_index(base, index, *element_size);
                }
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => return self.extract_stack_offset_from_array_index(base, index, *element_size),
            _ => {}
        }
        None
    }

    fn extract_stack_offset_from_array_index(
        &self,
        base: &Expr,
        index: &Expr,
        element_size: usize,
    ) -> Option<i128> {
        let ExprKind::Var(base_var) = &base.kind else {
            return None;
        };
        let base_name = base_var.name.to_lowercase();
        if !is_frame_pointer(&base_name)
            && !matches!(base_name.as_str(), "sp" | "rsp" | "esp" | "x31")
        {
            return None;
        }
        let ExprKind::IntLit(slot_index) = &index.kind else {
            return None;
        };
        Some(*slot_index * element_size as i128)
    }

    /// Checks if a register name is an argument register.
    fn is_arg_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Check for renamed argument variables (arg0, arg1, etc.)
        if name_lower.starts_with("arg") {
            if let Some(suffix) = name_lower.strip_prefix("arg") {
                if suffix.parse::<usize>().is_ok() {
                    return true;
                }
            }
        }
        if Self::lifted_arg_slot_index(&name_lower).is_some() {
            return true;
        }

        // Check both 64-bit and 32-bit register variants
        self.convention
            .integer_arg_registers()
            .iter()
            .any(|r| r.to_lowercase() == name_lower)
            || self
                .convention
                .integer_arg_registers_32()
                .iter()
                .any(|r| r.to_lowercase() == name_lower)
            || self
                .convention
                .float_arg_registers()
                .iter()
                .any(|r| r.to_lowercase() == name_lower)
    }

    /// Returns the argument index for a register, or None.
    fn direct_arg_register_index(&self, name: &str) -> Option<usize> {
        let name_lower = name.to_lowercase();

        // Check for renamed argument variables (arg0, arg1, etc.)
        if let Some(suffix) = name_lower.strip_prefix("arg") {
            if let Ok(idx) = suffix.parse::<usize>() {
                return Some(idx);
            }
        }

        // Check 64-bit integer registers
        if let Some(idx) = self
            .convention
            .integer_arg_registers()
            .iter()
            .position(|r| r.to_lowercase() == name_lower)
        {
            return Some(idx);
        }

        // Check 32-bit integer registers
        if let Some(idx) = self
            .convention
            .integer_arg_registers_32()
            .iter()
            .position(|r| r.to_lowercase() == name_lower)
        {
            return Some(idx);
        }

        None
    }

    fn arg_register_index(&self, name: &str) -> Option<usize> {
        self.direct_arg_register_index(name)
            .or_else(|| Self::lifted_arg_slot_index(&name.to_lowercase()))
    }

    fn lifted_arg_slot_index(name: &str) -> Option<usize> {
        let suffix = name.strip_prefix("arg_")?;
        let suffix = suffix.strip_prefix("0x").unwrap_or(suffix);
        let offset = u64::from_str_radix(suffix, 16).ok()?;
        if offset < 8 || offset % 8 != 0 {
            return None;
        }
        Some(((offset - 8) / 8) as usize)
    }

    /// Checks if a register is a return register.
    fn is_return_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        name_lower == self.convention.integer_return_register()
            || name_lower == self.convention.integer_return_register_32()
            || name_lower == self.convention.float_return_register()
            || Self::x86_simd_register_index(&name_lower) == Some(0)
    }

    /// If `lhs` is a float-bank register destination AND the load
    /// is SCALAR-WIDTH (4 = single, 8 = double), return the width.
    /// Otherwise 0. Used by the Assign handler to flag the RHS walk
    /// as "float context" so Deref/ArrayAccess hint propagation
    /// picks `Float(n)` element types.
    ///
    /// Codex review on PR #38 pass 1 narrowed this — the register
    /// bank alone is not enough to distinguish scalar FP loads
    /// (`movsd`/`movss`) from integer SIMD loads (`movq`/`movdqa`/
    /// `vmovdqu`/NEON `LDR Q*`). Scalar SSE lifts to a Variable
    /// with size 4 or 8; full-width SIMD (xmm 16B, ymm 32B, zmm
    /// 64B) lifts to a Variable with size > 8 and must NOT be
    /// treated as float context. The `Unknown("farg*")` rename
    /// only happens in scalar contexts via PR #36's lift logic,
    /// so it's safe to default to 8 there.
    fn float_dest_load_size(&self, lhs: &Expr) -> u8 {
        let (name, var_size) = match &lhs.kind {
            ExprKind::Var(var) => (var.name.clone(), Some(var.size)),
            ExprKind::Unknown(name) => (name.clone(), None),
            _ => return 0,
        };
        let lower = name.to_ascii_lowercase();
        let is_x86_float_bank = matches!(
            self.convention,
            CallingConvention::SystemV | CallingConvention::Win64
        ) && (lower.starts_with("xmm")
            || lower.starts_with("ymm")
            || lower.starts_with("zmm"));
        // ARM64 SIMD-FP register aliases — `s*` collides with RISC-V
        // saved INTEGER registers `s0`-`s11`, so gate by convention.
        // Codex review on PR #38 pass 6.
        let is_arm_float_bank = matches!(self.convention, CallingConvention::Aarch64)
            && (lower.starts_with('d')
                || lower.starts_with('s')
                || lower.starts_with('q')
                || lower.starts_with('v'))
            && lower.len() > 1
            && lower[1..].chars().all(|c| c.is_ascii_digit());
        let is_farg_alias = lower
            .strip_prefix("farg")
            .is_some_and(|s| s.parse::<usize>().is_ok());
        let is_float_bank = is_x86_float_bank || is_arm_float_bank || is_farg_alias;
        if !is_float_bank {
            return 0;
        }
        match var_size {
            // Scalar SSE: movsd (8) / movss (4). Accept.
            Some(8) => 8,
            Some(4) => 4,
            // Wider (full xmm 16 / ymm 32 / zmm 64) or narrower
            // half-precision — not a scalar float context, the
            // lifted instruction was likely an integer SIMD load
            // or an FP16 load we don't handle yet. Reject.
            Some(_) => 0,
            // Unknown spelling (e.g. `farg2` after structurer
            // stabilization) — the rename only fires in scalar
            // contexts so default to double.
            None => 8,
        }
    }

    fn is_float_arg_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.convention
            .float_arg_registers()
            .iter()
            .any(|reg| reg.eq_ignore_ascii_case(&name_lower))
            || Self::x86_simd_register_index(&name_lower)
                .is_some_and(|idx| idx < self.convention.float_arg_registers().len())
            || name_lower
                .strip_prefix("farg")
                .is_some_and(|suffix| suffix.parse::<usize>().is_ok())
    }

    /// Checks if a register is a float return register.
    fn is_float_return_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        name_lower == self.convention.float_return_register()
            || Self::x86_simd_register_index(&name_lower) == Some(0)
            || name_lower
                .strip_prefix("farg")
                .is_some_and(|suffix| suffix.parse::<usize>().ok() == Some(0))
    }

    fn x86_simd_register_index(name: &str) -> Option<usize> {
        for prefix in ["xmm", "ymm", "zmm"] {
            if let Some(suffix) = name.strip_prefix(prefix) {
                return suffix.parse::<usize>().ok();
            }
        }
        None
    }

    fn canonical_float_arg_register_name(&self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        if let Some(idx) = Self::x86_simd_register_index(&name_lower) {
            return self
                .convention
                .float_arg_registers()
                .get(idx)
                .map(|reg| reg.to_lowercase());
        }
        // `farg{n}` aliases (the structurer's stabilization rename)
        // also map to the convention's nth float arg register so the
        // write-before-read filter recognizes `farg2` write paired
        // with an `xmm2` read (and vice versa). Codex review on
        // PR #37 pass 1.
        if let Some(suffix) = name_lower.strip_prefix("farg") {
            if let Ok(idx) = suffix.parse::<usize>() {
                if let Some(reg) = self.convention.float_arg_registers().get(idx) {
                    return Some(reg.to_lowercase());
                }
            }
        }
        self.convention
            .float_arg_registers()
            .iter()
            .find(|reg| reg.eq_ignore_ascii_case(&name_lower))
            .map(|reg| reg.to_lowercase())
    }

    fn observed_float_expr_size(&self, var: &Variable) -> u8 {
        let name_lower = var.name.to_lowercase();
        if name_lower.starts_with("xmm") {
            return match var.size {
                1..=8 => var.size,
                _ => 8,
            };
        }
        if name_lower.starts_with("ymm") {
            return if var.size > 0 { var.size } else { 32 };
        }
        if name_lower.starts_with("zmm") {
            return if var.size > 0 { var.size } else { 64 };
        }
        self.effective_var_size(var)
    }

    fn is_x87_stack_register(name: &str) -> bool {
        name.to_lowercase()
            .strip_prefix("st(")
            .and_then(|suffix| suffix.strip_suffix(')'))
            .is_some_and(|suffix| suffix.parse::<usize>().ok().is_some_and(|idx| idx < 8))
    }

    fn x87_stack_arg_offset(name: &str) -> Option<i64> {
        let lowered = name.to_lowercase();
        if let Some(idx) = Self::lifted_arg_slot_index(&lowered) {
            return Some((8 * (idx + 1)) as i64);
        }
        if let Some(offset) = Self::parse_lifted_hex_suffix(&lowered, "var_") {
            return Some(offset as i64);
        }
        if let Some(offset) = lowered.strip_prefix("stack_") {
            return offset.parse::<i64>().ok().filter(|offset| *offset >= 8);
        }
        None
    }

    fn is_x87_mnemonic(name: &str) -> bool {
        let lowered = name.to_ascii_lowercase();
        [
            "fld", "fst", "fstp", "fild", "fist", "fistp", "fisttp", "fadd", "faddp", "fiadd",
            "fsub", "fsubr", "fsubp", "fsubrp", "fisub", "fisubr", "fmul", "fmulp", "fimul",
            "fdiv", "fdivr", "fdivp", "fdivrp", "fidiv", "fidivr", "fcom", "fcomp", "fucom",
            "fucomp", "fucompp", "fcomi", "fucomi", "ftst", "fxam", "fxch", "fld1", "fldz",
            "fldpi", "fabs", "fchs", "fsqrt", "frndint", "fscale", "f2xm1", "fyl2x", "fyl2xp1",
            "fptan", "fpatan", "fsin", "fcos", "fsincos", "fincstp", "fdecstp",
        ]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    }

    fn observe_x87_call(&mut self, target: &super::expression::CallTarget, args: &[Expr]) {
        let super::expression::CallTarget::Named(name) = target else {
            return;
        };
        if !Self::is_x87_mnemonic(name) {
            return;
        }

        self.x87_ops_observed = true;
        for arg in args {
            if let Some(var_name) = self.extract_var_name(arg) {
                if Self::is_x87_stack_register(&var_name) {
                    self.x87_st0_input_observed |= var_name.eq_ignore_ascii_case("st(0)");
                }
                if let Some(offset) = Self::x87_stack_arg_offset(&var_name) {
                    self.x87_stack_arg_offsets.insert(offset);
                }
            }
        }
    }

    fn expr_is_x87_return_value(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => Self::is_x87_stack_register(&var.name),
            ExprKind::Unknown(name) => Self::is_x87_stack_register(name),
            ExprKind::Call { target, .. } => {
                matches!(target, super::expression::CallTarget::Named(name) if Self::is_x87_mnemonic(name))
            }
            ExprKind::Cast { expr, .. } => self.expr_is_x87_return_value(expr),
            _ => false,
        }
    }

    fn is_opaque_x86_integer_simd_comment(name: &str) -> bool {
        let trimmed = name.trim();
        let Some(mnemonic) = trimmed
            .strip_prefix("/* SSE: ")
            .and_then(|rest| rest.strip_suffix(" */"))
        else {
            return false;
        };

        // TODO(31.1): model opaque YMM/XMM vector values directly instead of relying on
        // comment mnemonics and shadowed scalar carriers during signature recovery.
        Self::looks_like_x86_integer_simd_mnemonic(mnemonic)
    }

    fn looks_like_x86_integer_simd_mnemonic(mnemonic: &str) -> bool {
        [
            "punpck", "vpunpck", "pshuf", "vpshuf", "padd", "vpadd", "psub", "vpsub", "pmul",
            "vpmul", "pack", "vpack", "pcmp", "vpcmp", "pand", "vpand", "por", "vpor", "pxor",
            "vpxor", "psll", "vpsll", "psrl", "vpsrl", "psra", "vpsra", "palignr", "vpalignr",
            "pblend", "vpblend", "pinsr", "vpinsr", "pextr", "vpextr", "phadd", "vphadd", "phsub",
            "vphsub", "pabs", "vpabs", "pavg", "vpavg", "pmax", "vpmax", "pmin", "vpmin", "pmadd",
            "vpmadd", "pmov", "vpmov", "ptest", "vptest", "psadbw", "vpsadbw", "mpsadbw",
            "vmpsadbw",
        ]
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix))
    }

    fn expr_is_float_abi_value(&self, expr: &Expr) -> bool {
        let Some(name) = self.extract_var_name(expr) else {
            return false;
        };
        let name_lower = name.to_lowercase();
        self.is_float_return_register(&name_lower) || self.is_float_arg_register(&name_lower)
    }

    fn expr_uses_float_abi_value(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => self.expr_is_float_abi_value(&Expr::var(var.clone())),
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                self.is_float_return_register(&lowered) || self.is_float_arg_register(&lowered)
            }
            ExprKind::BinOp { left, right, .. } => {
                self.expr_uses_float_abi_value(left) || self.expr_uses_float_abi_value(right)
            }
            ExprKind::UnaryOp { operand, .. } => self.expr_uses_float_abi_value(operand),
            ExprKind::Deref { addr, .. } => self.expr_uses_float_abi_value(addr),
            ExprKind::AddressOf(expr) => self.expr_uses_float_abi_value(expr),
            ExprKind::ArrayAccess { base, index, .. } => {
                self.expr_uses_float_abi_value(base) || self.expr_uses_float_abi_value(index)
            }
            ExprKind::FieldAccess { base, .. } => self.expr_uses_float_abi_value(base),
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                self.expr_uses_float_abi_value(lhs) || self.expr_uses_float_abi_value(rhs)
            }
            ExprKind::Call { target, args } => {
                let target_uses_float = match target {
                    super::expression::CallTarget::Indirect(inner) => {
                        self.expr_uses_float_abi_value(inner)
                    }
                    super::expression::CallTarget::IndirectGot { expr, .. } => {
                        self.expr_uses_float_abi_value(expr)
                    }
                    _ => false,
                };
                target_uses_float || args.iter().any(|arg| self.expr_uses_float_abi_value(arg))
            }
            ExprKind::Cast { expr, .. } => self.expr_uses_float_abi_value(expr),
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.expr_uses_float_abi_value(cond)
                    || self.expr_uses_float_abi_value(then_expr)
                    || self.expr_uses_float_abi_value(else_expr)
            }
            ExprKind::BitField { expr, .. } => self.expr_uses_float_abi_value(expr),
            ExprKind::Phi(exprs) => exprs
                .iter()
                .any(|expr| self.expr_uses_float_abi_value(expr)),
            ExprKind::IntLit(_) | ExprKind::GotRef { .. } => false,
        }
    }

    fn expr_uses_integer_return_register(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => {
                let lowered = var.name.to_lowercase();
                lowered == self.convention.integer_return_register()
                    || lowered == self.convention.integer_return_register_32()
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                lowered == self.convention.integer_return_register()
                    || lowered == self.convention.integer_return_register_32()
            }
            ExprKind::BinOp { left, right, .. } => {
                self.expr_uses_integer_return_register(left)
                    || self.expr_uses_integer_return_register(right)
            }
            ExprKind::UnaryOp { operand, .. } => self.expr_uses_integer_return_register(operand),
            ExprKind::Deref { addr, .. } => self.expr_uses_integer_return_register(addr),
            ExprKind::AddressOf(expr) => self.expr_uses_integer_return_register(expr),
            ExprKind::ArrayAccess { base, index, .. } => {
                self.expr_uses_integer_return_register(base)
                    || self.expr_uses_integer_return_register(index)
            }
            ExprKind::FieldAccess { base, .. } => self.expr_uses_integer_return_register(base),
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                self.expr_uses_integer_return_register(lhs)
                    || self.expr_uses_integer_return_register(rhs)
            }
            ExprKind::Call { target, args } => {
                let target_uses_return = match target {
                    super::expression::CallTarget::Indirect(inner) => {
                        self.expr_uses_integer_return_register(inner)
                    }
                    super::expression::CallTarget::IndirectGot { expr, .. } => {
                        self.expr_uses_integer_return_register(expr)
                    }
                    _ => false,
                };
                target_uses_return
                    || args
                        .iter()
                        .any(|arg| self.expr_uses_integer_return_register(arg))
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.expr_uses_integer_return_register(cond)
                    || self.expr_uses_integer_return_register(then_expr)
                    || self.expr_uses_integer_return_register(else_expr)
            }
            ExprKind::Cast { expr, .. } => self.expr_uses_integer_return_register(expr),
            ExprKind::BitField { expr, .. } => self.expr_uses_integer_return_register(expr),
            ExprKind::Phi(exprs) => exprs
                .iter()
                .any(|expr| self.expr_uses_integer_return_register(expr)),
            ExprKind::IntLit(_) | ExprKind::GotRef { .. } => false,
        }
    }

    /// Returns the size in bytes based on register name variant.
    fn reg_size_from_name(&self, name: &str) -> u8 {
        let name_lower = name.to_lowercase();

        // x86-64 register naming
        if name_lower.starts_with("zmm") {
            return 64;
        }
        if name_lower.starts_with("ymm") {
            return 32;
        }
        if name_lower.starts_with("xmm") {
            return 16;
        }
        if name_lower.starts_with('r') && !name_lower.ends_with('d') {
            return 8; // 64-bit (rax, rdi, etc.)
        }
        if name_lower.starts_with('e') || name_lower.ends_with('d') {
            return 4; // 32-bit (eax, r8d, etc.)
        }
        if name_lower.ends_with('w') {
            return 2; // 16-bit
        }
        if name_lower.ends_with('b') || name_lower.ends_with('l') {
            return 1; // 8-bit
        }

        // RISC-V register aliases (a0..a7, t0..t6, s0..s11, etc.).
        if matches!(self.convention, CallingConvention::RiscV) {
            let is_xn = name_lower
                .strip_prefix('x')
                .is_some_and(|suffix| suffix.parse::<u8>().is_ok());
            if is_xn
                || matches!(
                    name_lower.as_str(),
                    "zero"
                        | "ra"
                        | "sp"
                        | "gp"
                        | "tp"
                        | "t0"
                        | "t1"
                        | "t2"
                        | "t3"
                        | "t4"
                        | "t5"
                        | "t6"
                        | "s0"
                        | "s1"
                        | "s2"
                        | "s3"
                        | "s4"
                        | "s5"
                        | "s6"
                        | "s7"
                        | "s8"
                        | "s9"
                        | "s10"
                        | "s11"
                        | "a0"
                        | "a1"
                        | "a2"
                        | "a3"
                        | "a4"
                        | "a5"
                        | "a6"
                        | "a7"
                        | "fp"
                )
            {
                return 8;
            }
        }

        // ARM64 register naming
        if name_lower.starts_with('x') {
            return 8; // 64-bit
        }
        if name_lower.starts_with('w') {
            return 4; // 32-bit
        }
        if name_lower.starts_with('d') || name_lower.starts_with('q') {
            return 8; // 64-bit float/SIMD
        }
        if name_lower.starts_with('s') && name_lower.len() <= 3 {
            return 4; // 32-bit float
        }

        // Not a recognized register name.
        0
    }

    fn value_size_alias_names(name_lower: &str) -> Vec<String> {
        if let Some(suffix) = name_lower.strip_prefix("xmm") {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return vec![format!("ymm{}", suffix), format!("zmm{}", suffix)];
            }
        }
        if let Some(suffix) = name_lower.strip_prefix("ymm") {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return vec![format!("xmm{}", suffix), format!("zmm{}", suffix)];
            }
        }
        if let Some(suffix) = name_lower.strip_prefix("zmm") {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return vec![format!("xmm{}", suffix), format!("ymm{}", suffix)];
            }
        }
        if let Some(suffix) = name_lower.strip_prefix('w') {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return vec![format!("x{}", suffix)];
            }
        }
        if let Some(suffix) = name_lower.strip_prefix('x') {
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return vec![format!("w{}", suffix)];
            }
        }
        Vec::new()
    }

    fn record_value_size_hint(&mut self, name_lower: &str, size: u8) {
        let current = self.value_sizes.get(name_lower).copied().unwrap_or(0);
        let merged = if current == 0 {
            size
        } else if (self.is_float_arg_register(name_lower)
            || self.is_float_return_register(name_lower)
            || Self::x86_simd_register_index(name_lower).is_some())
            && current <= 8
            && size <= 8
        {
            current.min(size)
        } else {
            current.max(size)
        };
        self.value_sizes.insert(name_lower.to_string(), merged);
        for alias in Self::value_size_alias_names(name_lower) {
            let alias_current = self.value_sizes.get(&alias).copied().unwrap_or(0);
            let alias_merged = if alias_current == 0 {
                size
            } else if (self.is_float_arg_register(&alias)
                || self.is_float_return_register(&alias)
                || Self::x86_simd_register_index(&alias).is_some())
                && alias_current <= 8
                && size <= 8
            {
                alias_current.min(size)
            } else {
                alias_current.max(size)
            };
            self.value_sizes.insert(alias, alias_merged);
        }
    }

    /// Infers the size of an expression result.
    fn infer_expr_size(&self, expr: &Expr) -> Option<u8> {
        match &expr.kind {
            ExprKind::Var(var) => {
                let var_name_lower = var.name.to_lowercase();
                if Self::is_x87_stack_register(&var_name_lower) {
                    return Some(10);
                }
                if self.is_float_return_register(&var_name_lower)
                    || self.is_float_arg_register(&var_name_lower)
                {
                    if let Some(size) = self.value_sizes.get(&var_name_lower) {
                        return Some(*size);
                    }
                    let size = self.observed_float_expr_size(var);
                    if size > 0 {
                        return Some(size);
                    }
                    return Some(8);
                }
                if let Some(size) = self.value_sizes.get(&var_name_lower) {
                    // Prefer tracked value width for non-ABI temporaries/registers.
                    if !self.is_arg_register(&var_name_lower)
                        && !self.is_return_register(&var_name_lower)
                    {
                        return Some(*size);
                    }
                }
                // First try to infer from register name (w0 = 4, x0 = 8, etc.)
                let size = self.effective_var_size(var);
                if size > 0 {
                    Some(size)
                } else if let Some(size) = self.value_sizes.get(&var_name_lower) {
                    Some(*size)
                } else if var.size > 0 {
                    // Fall back to variable's stored size (for stack variables, etc.)
                    Some(var.size)
                } else {
                    None
                }
            }
            ExprKind::Unknown(name) => {
                let name_lower = name.to_lowercase();
                if Self::is_x87_stack_register(&name_lower) {
                    return Some(10);
                }
                if self.is_float_return_register(&name_lower)
                    || self.is_float_arg_register(&name_lower)
                {
                    if let Some(size) = self.value_sizes.get(&name_lower) {
                        return Some(*size);
                    }
                    if let Some(idx) = name_lower
                        .strip_prefix("farg")
                        .and_then(|suffix| suffix.parse::<usize>().ok())
                    {
                        if let Some(reg_name) = self.convention.float_arg_registers().get(idx) {
                            if let Some(size) = self.observed_float_register_size(idx, reg_name) {
                                return Some(size);
                            }
                        }
                    }
                    let reg_size = self.reg_size_from_name(&name_lower);
                    if reg_size > 0 {
                        return Some(reg_size);
                    }
                    return Some(8);
                }
                if let Some(size) = self.value_sizes.get(&name_lower) {
                    return Some(*size);
                }
                let reg_size = self.reg_size_from_name(&name_lower);
                if reg_size > 0 {
                    Some(reg_size)
                } else {
                    None
                }
            }
            ExprKind::IntLit(n) => {
                // Plain integer literals default to at least `int` width in C/C++.
                if *n >= i32::MIN as i128 && *n <= i32::MAX as i128 {
                    Some(4)
                } else {
                    Some(8)
                }
            }
            ExprKind::Deref { size, .. } => Some(*size),
            ExprKind::ArrayAccess { element_size, .. } => Some(*element_size as u8),
            ExprKind::Cast { to_size, .. } => Some(*to_size),
            ExprKind::Call { target, args } => {
                if let Some(name) = self.extract_call_name(target) {
                    if matches!(name.as_str(), "fminf" | "fmaxf") {
                        return Some(4);
                    }
                    if matches!(name.as_str(), "fmin" | "fmax") {
                        return Some(8);
                    }
                    if let Some(size) = name
                        .strip_prefix("__m")
                        .and_then(|suffix| suffix.split('_').next())
                        .and_then(|digits| digits.parse::<u8>().ok())
                    {
                        return Some(size / 8);
                    }
                    if let Some(size) =
                        self.infer_atomic_pseudo_call_result_size(args).filter(|_| {
                            matches!(
                                name.as_str(),
                                "atomic_exchange"
                                    | "atomic_fetch_add"
                                    | "atomic_fetch_sub"
                                    | "atomic_fetch_and"
                                    | "atomic_fetch_or"
                                    | "atomic_fetch_xor"
                            )
                        })
                    {
                        return Some(size);
                    }
                    if name == "atomic_compare_exchange_strong" {
                        return Some(1);
                    }
                }
                matches!(target, super::expression::CallTarget::Named(name) if Self::is_x87_mnemonic(name))
                    .then_some(10)
            }
            ExprKind::BinOp { left, right, .. } => {
                let left_size = self.infer_expr_size(left);
                let right_size = self.infer_expr_size(right);
                match (left_size, right_size) {
                    (Some(l), Some(r)) => Some(l.max(r)),
                    (Some(s), None) | (None, Some(s)) => Some(s),
                    (None, None) => None,
                }
            }
            _ => None,
        }
    }

    fn effective_var_size(&self, var: &Variable) -> u8 {
        let named_size = self.reg_size_from_name(&var.name);
        if var.size > 0 && (named_size == 0 || var.size < named_size) {
            var.size
        } else {
            named_size.max(var.size)
        }
    }

    /// Checks if an expression is likely a pointer based on its structure and context.
    fn is_expr_likely_pointer(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // Address-of operations definitely produce pointers
            ExprKind::AddressOf(_) => true,

            // Array accesses produce the element, but the base is a pointer
            ExprKind::ArrayAccess { .. } => false, // The result is the element, not a pointer

            // Field access suggests struct pointer usage
            ExprKind::FieldAccess { .. } => false, // Result is the field value, not necessarily a pointer

            // Dereferences produce values, but if being returned, the source might be a pointer
            ExprKind::Deref { .. } => false,

            // Variables - check if they're parameters that were used as pointers
            ExprKind::Var(var) => {
                // Check if this is a parameter that's been used as a pointer
                let var_name_lower = var.name.to_lowercase();
                if self.value_pointer_hints.contains(&var_name_lower) {
                    return true;
                }
                if let Some(idx) = self.arg_register_index(&var_name_lower) {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        // If parameter was dereferenced, used in pointer arithmetic, or null-checked, it's a pointer
                        return hints.is_dereferenced
                            || hints.is_pointer_arithmetic
                            || hints.is_null_checked
                            || hints.is_string_arg;
                    }
                }
                false
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                if self.value_pointer_hints.contains(&lowered) {
                    return true;
                }
                if let Some(idx) = self.arg_register_index(&lowered) {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        return hints.is_dereferenced
                            || hints.is_pointer_arithmetic
                            || hints.is_null_checked
                            || hints.is_string_arg;
                    }
                }
                false
            }

            // Calls to known pointer-returning functions
            ExprKind::Call { target, .. } => {
                if let Some(name) = self.extract_call_name(target) {
                    let clean = name.strip_prefix('_').unwrap_or(&name);
                    // Check for common pointer-returning functions
                    matches!(
                        clean,
                        "malloc"
                            | "calloc"
                            | "realloc"
                            | "strdup"
                            | "strndup"
                            | "strchr"
                            | "strrchr"
                            | "strstr"
                            | "getenv"
                            | "getcwd"
                            | "fopen"
                            | "mmap"
                            | "bsearch"
                    )
                } else {
                    false
                }
            }

            // Casts - check the inner expression
            ExprKind::Cast {
                expr: inner,
                to_size,
                ..
            } => {
                // If casting to 8 bytes and inner is pointer-like, likely a pointer
                *to_size == 8 && self.is_expr_likely_pointer(inner)
            }

            // Binary operations - pointer arithmetic suggests pointer result
            ExprKind::BinOp { op, left, right } => {
                matches!(op, BinOpKind::Add | BinOpKind::Sub)
                    && (self.is_expr_likely_pointer(left) || self.is_expr_likely_pointer(right))
            }

            // Null/zero is ambiguous - could be NULL pointer or 0
            ExprKind::IntLit(0) => false,

            // Non-zero integer literals are not pointers
            ExprKind::IntLit(_) => false,

            // Unknown expressions might be pointers
            _ => false,
        }
    }

    /// Builds the final signature from collected information.
    fn build_signature(&self) -> FunctionSignature {
        let mut sig = FunctionSignature::new(self.convention);

        // Check for known function signature first
        let known_params = self
            .current_func_name
            .as_ref()
            .and_then(|name| Self::known_function_params(name));

        // Determine which argument registers were used
        let int_regs = self.convention.integer_arg_registers();
        let int_regs_32 = self.convention.integer_arg_registers_32();

        // Track which argument registers were actually read (use-before-def)
        let mut used_args: Vec<usize> = Vec::new();

        for (idx, (reg64, reg32)) in int_regs.iter().zip(int_regs_32.iter()).enumerate() {
            let reg64_lower = reg64.to_lowercase();
            let reg32_lower = reg32.to_lowercase();
            let pseudo_arg = format!("arg{}", idx);
            let lifted_slot = 8 * (idx + 1);
            let lifted_arg = format!("arg_{:x}", lifted_slot);
            let lifted_arg_prefixed = format!("arg_0x{:x}", lifted_slot);

            if self.read_regs.contains(&reg64_lower)
                || self.read_regs.contains(&reg32_lower)
                || self.read_regs.contains(&pseudo_arg)
                || self.read_regs.contains(&lifted_arg)
                || self.read_regs.contains(&lifted_arg_prefixed)
                || self
                    .param_hints
                    .get(&idx)
                    .is_some_and(ParameterUsageHints::has_strong_signal)
            {
                used_args.push(idx);
            }
        }

        for idx in 0..self.dwarf_param_names.len().min(int_regs.len()) {
            if !used_args.contains(&idx) {
                used_args.push(idx);
            }
        }
        if self.tail_call_min_arity.is_some() && known_params.is_none() {
            if let Some(min_arity) = self.tail_call_min_arity {
                for idx in 0..min_arity.min(int_regs.len()) {
                    if !used_args.contains(&idx) {
                        used_args.push(idx);
                    }
                }
            }
        }
        used_args.sort_unstable();

        let variadic_fixed_param_count = self.infer_variadic_fixed_param_count(&used_args);
        if let Some(fixed_count) = variadic_fixed_param_count {
            sig.is_variadic = true;
            used_args.retain(|idx| *idx < fixed_count);
            for idx in 0..fixed_count.min(int_regs.len()) {
                if !used_args.contains(&idx) {
                    used_args.push(idx);
                }
            }
            used_args.sort_unstable();
        }

        // Create parameters only for registers that were actually used
        for &idx in &used_args {
            let reg64 = int_regs[idx].to_lowercase();
            let reg32 = int_regs_32[idx].to_lowercase();

            // Check if we have a known parameter name/type for this index
            let (known_name, known_type) = known_params
                .as_ref()
                .and_then(|params| params.get(idx))
                .map(|(name, ty)| (Some(name.clone()), Some(ty.clone())))
                .unwrap_or((None, None));

            // Get usage hints for this parameter
            let hints = self.param_hints.get(&idx);

            // Determine the size from register usage
            let size = if let (Some(s64), Some(s32)) =
                (self.reg_sizes.get(&reg64), self.reg_sizes.get(&reg32))
            {
                let prefer_narrow_integer = hints.is_some_and(|h| {
                    !h.is_dereferenced
                        && !h.is_pointer_arithmetic
                        && !h.is_null_checked
                        && !h.is_string_arg
                        && (h.is_signed_comparison
                            || h.is_unsigned_ops
                            || h.is_array_index
                            || h.is_loop_bound)
                });
                if prefer_narrow_integer {
                    (*s64).min(*s32)
                } else {
                    *s64
                }
            } else if let Some(s) = self.reg_sizes.get(&reg64) {
                *s
            } else if let Some(s) = self.reg_sizes.get(&reg32) {
                *s
            } else {
                // If no size information, prefer int32 for simple integer parameters
                // unless hints suggest this should be a pointer (8 bytes) or larger type
                if let Some(h) = hints {
                    if h.is_dereferenced
                        || h.is_pointer_arithmetic
                        || h.is_null_checked
                        || h.is_string_arg
                    {
                        8 // Pointer-like usage, use 8 bytes
                    } else {
                        4 // Default to int32 for simple integer usage
                    }
                } else {
                    4 // Default to int32 when no hints available
                }
            };

            // Use known type, or infer type from usage hints if available
            let param_type = if let Some(known_ty) = known_type {
                known_ty
            } else if let Some(override_ty) = self.param_type_overrides.get(&idx) {
                override_ty.clone()
            } else if let Some(hints) = hints {
                hints.infer_type(size)
            } else {
                match size {
                    1 => ParamType::SignedInt(8),
                    2 => ParamType::SignedInt(16),
                    4 => ParamType::SignedInt(32),
                    _ => ParamType::SignedInt(64),
                }
            };

            // Use known name, custom name, infer from hints, or default
            let name = if let Some(dwarf_name) = self
                .dwarf_param_names
                .get(idx)
                .filter(|name| !name.is_empty())
            {
                dwarf_name.clone()
            } else if let Some(known_nm) = known_name {
                known_nm
            } else if let Some(custom_name) = self.param_names.get(&idx) {
                custom_name.clone()
            } else if let Some(hints) = hints {
                hints.suggest_name(idx)
            } else {
                format!("arg{}", idx)
            };

            let confidence = hints
                .map(|h| {
                    if matches!(param_type, ParamType::FunctionPointer { .. }) {
                        h.function_pointer_confidence
                    } else {
                        u8::MAX
                    }
                })
                .unwrap_or(u8::MAX);

            if matches!(param_type, ParamType::FunctionPointer { .. }) {
                if let Some(h) = hints {
                    if !h.function_pointer_reasons.is_empty() {
                        sig.parameter_provenance
                            .insert(idx, h.function_pointer_reasons.clone());
                    }
                }
            }

            sig.parameters.push(
                Parameter::new(
                    name,
                    param_type,
                    ParameterLocation::IntegerRegister {
                        name: int_regs[idx].to_string(),
                        index: idx,
                    },
                )
                .with_confidence(confidence),
            );
        }

        // Detect pointer+size parameter pairs
        self.detect_param_pairs(&mut sig);

        if self.x87_ops_observed
            && (self.x87_st0_input_observed || !self.x87_stack_arg_offsets.is_empty())
            && sig.parameters.is_empty()
        {
            let stack_offsets: Vec<_> = if self.x87_stack_arg_offsets.is_empty() {
                vec![8_i64]
            } else {
                self.x87_stack_arg_offsets.iter().copied().collect()
            };
            for (idx, offset) in stack_offsets.into_iter().enumerate() {
                sig.parameters.push(Parameter::new(
                    format!("arg{}", idx),
                    ParamType::Float(80),
                    ParameterLocation::Stack { offset },
                ));
            }
        }

        // Check for float arguments
        let float_regs = self.convention.float_arg_registers();
        let integer_simd_signature =
            self.integer_simd_ops_observed && self.return_from_integer_simd_lane;
        // For a variadic function, only the first `named_float_count` float
        // arg registers are real parameters; the rest are the variadic FP
        // register-save area spilled in the prologue. The count comes from the
        // `va_start` `fp_offset` initialiser when observed (so an integer-named
        // variadic like `printf`/`sum_ints` correctly drops `farg0`), falling
        // back to the integer fixed-count only when `fp_offset` wasn't seen
        // (e.g. the structurer already collapsed the diamond) to avoid
        // regressing the pre-existing behaviour there.
        let float_param_cutoff = variadic_fixed_param_count.map(|int_fixed| {
            // aarch64 AAPCS: the `__vr_offs` field gives the named float count
            // directly.
            if let Some((_, named_fp)) = self.aapcs_va_list_counts {
                return named_fp;
            }
            // SysV: prefer the structured-body __va_list_tag resolver; fall back
            // to the raw-prologue seed when the va_arg diamonds were already
            // collapsed (which deletes the fp_offset store the resolver reads);
            // only then fall back to the integer prefix.
            self.resolve_sysv_named_float_count()
                .or(self.va_list_float_count_seed)
                .unwrap_or(int_fixed)
        });
        for (idx, reg) in float_regs.iter().enumerate() {
            if float_param_cutoff.is_some_and(|cutoff| idx >= cutoff) {
                continue;
            }
            let reg_lower = reg.to_lowercase();
            let seen_as_param = self.read_regs.contains(&reg_lower)
                || self.observed_float_arg_regs.contains(&reg_lower)
                || (integer_simd_signature && idx == 0);
            if seen_as_param {
                if integer_simd_signature {
                    sig.parameters.push(Parameter::new(
                        format!("arg{}", idx),
                        ParamType::SimdInt128,
                        ParameterLocation::FloatRegister {
                            name: reg.to_string(),
                            index: idx,
                        },
                    ));
                } else {
                    let size = self.observed_float_register_size(idx, reg).unwrap_or(8);
                    sig.parameters.push(Parameter::new(
                        format!("farg{}", idx),
                        Self::float_param_type_for_size(size),
                        ParameterLocation::FloatRegister {
                            name: reg.to_string(),
                            index: idx,
                        },
                    ));
                }
            }
        }

        // Determine return type
        sig.has_return = self.return_value_set;
        sig.return_provenance = self.return_provenance.clone();
        sig.return_confidence = self.return_confidence;
        if self.return_value_set {
            if let Some(ref fp_ty) = self.return_function_pointer {
                sig.return_type = fp_ty.clone();
            } else if self.return_from_integer_simd_lane {
                sig.return_type = match self.return_size {
                    1 => ParamType::SignedInt(8),
                    2 => ParamType::SignedInt(16),
                    4 => ParamType::SignedInt(32),
                    8 => ParamType::SignedInt(64),
                    _ => ParamType::SignedInt(32),
                };
            } else if self.float_return {
                sig.return_type = Self::float_param_type_for_size(self.return_size);
            } else if let Some(tail_ty) = self.tail_call_return_type.as_ref() {
                if !matches!(tail_ty, ParamType::Void | ParamType::Unknown) {
                    sig.return_type = tail_ty.clone();
                } else if self.return_is_pointer && self.return_size == 8 {
                    sig.return_type = ParamType::Pointer;
                } else if matches!(self.current_func_kind, Some(SymbolKind::IndirectFunction)) {
                    sig.return_type = ParamType::Pointer;
                    if !sig
                        .return_provenance
                        .iter()
                        .any(|reason| reason == "IFUNC resolver default return type")
                    {
                        sig.return_provenance
                            .push("IFUNC resolver default return type".to_string());
                    }
                    sig.return_confidence = sig.return_confidence.max(200);
                } else {
                    sig.return_type = match self.return_size {
                        1 => ParamType::SignedInt(8),
                        2 => ParamType::SignedInt(16),
                        4 => ParamType::SignedInt(32),
                        8 => ParamType::SignedInt(64),
                        _ => ParamType::SignedInt(64),
                    };
                }
            } else if self.return_is_pointer && self.return_size == 8 {
                // Return value is a pointer
                sig.return_type = ParamType::Pointer;
            } else if matches!(self.current_func_kind, Some(SymbolKind::IndirectFunction)) {
                sig.return_type = ParamType::Pointer;
                if !sig
                    .return_provenance
                    .iter()
                    .any(|reason| reason == "IFUNC resolver default return type")
                {
                    sig.return_provenance
                        .push("IFUNC resolver default return type".to_string());
                }
                sig.return_confidence = sig.return_confidence.max(200);
            } else {
                // Infer return type based on size
                sig.return_type = match self.return_size {
                    1 => ParamType::SignedInt(8),
                    2 => ParamType::SignedInt(16),
                    4 => ParamType::SignedInt(32),
                    8 => ParamType::SignedInt(64),
                    _ => ParamType::SignedInt(64),
                };
            }
        } else {
            sig.return_type = ParamType::Void;
        }

        // Reorder mixed int/float parameters by observed source
        // declaration order, derived from prologue spill offsets.
        // Codex review on PR #25 / SSE-1.
        self.reorder_params_by_spill_offset(&mut sig);

        if matches!(self.current_func_name.as_deref(), Some("main" | "_main")) {
            sig.has_return = true;
            sig.return_type = ParamType::SignedInt(32);
            if !sig
                .return_provenance
                .iter()
                .any(|r| r == "main ABI default return type")
            {
                sig.return_provenance
                    .push("main ABI default return type".to_string());
            }
            sig.return_confidence = sig.return_confidence.max(220);
        }

        sig
    }

    /// Reorders the recovered parameter list by source-declaration
    /// order recovered from prologue spill offsets.
    ///
    /// At `-O0` the compiler spills every parameter register to the
    /// stack in source order — the first source parameter goes to
    /// `[rbp-8]`, the second to `[rbp-16]`, etc., regardless of
    /// whether each is integer-bank or float-bank. By tracking each
    /// param register's smallest observed spill offset and sorting
    /// DESCENDING (largest = closest to rbp = earliest spilled),
    /// we recover the source order even when int and float params
    /// are interleaved (the `double scale_sum(double x, int n)`
    /// case that previously emitted as `(int32_t arg0, double farg0)`).
    ///
    /// Parameters without observed spill offsets (e.g. seeded from
    /// raw float scanning without a structured spill site) sort to
    /// the end in their existing relative order — a stable
    /// fallback that preserves the leaf-case heuristic. SSE-1.
    fn reorder_params_by_spill_offset(&self, sig: &mut FunctionSignature) {
        if sig.parameters.len() < 2 || self.param_spill_order.is_empty() {
            return;
        }
        // Build a register-name → spill-offset lookup from the raw
        // prologue scan (already in instruction order, but we sort
        // by offset for robustness). The bank-class mapping in each
        // parameter's ParameterLocation tells us which spill to use.
        let int_arg_regs: Vec<String> = self
            .convention
            .integer_arg_registers()
            .iter()
            .map(|r| r.to_lowercase())
            .collect();
        let int_arg_regs_32: Vec<String> = self
            .convention
            .integer_arg_registers_32()
            .iter()
            .map(|r| r.to_lowercase())
            .collect();
        let float_arg_regs: Vec<String> = self
            .convention
            .float_arg_registers()
            .iter()
            .map(|r| r.to_lowercase())
            .collect();

        // Use SPILL-INSTRUCTION ORDER rather than stack offset.
        // aarch64 packs 4-byte integer slots and 8-byte FP slots
        // with different alignment, so the offsets are not
        // monotonic in source order (`int, double, int, double`
        // can spill to `[sp,44], [sp,32], [sp,40], [sp,24]`).
        // The scanner already records observations in instruction
        // order — index into that order IS source order. Codex
        // review on PR #27 pass 2.
        let spill_index_for = |p: &Parameter| -> Option<usize> {
            match &p.location {
                ParameterLocation::IntegerRegister { index, .. } => {
                    let r64 = int_arg_regs.get(*index)?;
                    let r32 = int_arg_regs_32.get(*index);
                    self.param_spill_order
                        .iter()
                        .position(|obs| &obs.register == r64 || r32 == Some(&obs.register))
                }
                ParameterLocation::FloatRegister { index, .. } => {
                    let r = float_arg_regs.get(*index)?;
                    self.param_spill_order
                        .iter()
                        .position(|obs| &obs.register == r)
                }
                _ => None,
            }
        };

        // Require observed spills for EVERY recovered parameter
        // before reordering, AND require at least one int and one
        // float to be present (so all-int/all-float signatures
        // keep the existing leaf-case heuristic). Without the
        // all-observed gate, partial spill data would move some
        // params ahead of others, inventing a wrong source order
        // for cases like `(int a, int b, double x)` where only
        // `a` and `xmm0` are homed at -O0 but `b` was kept in
        // `esi` and never spilled. Codex review on PR #27 pass 8.
        let mut has_int = false;
        let mut has_float = false;
        for p in &sig.parameters {
            match &p.location {
                ParameterLocation::IntegerRegister { .. } => has_int = true,
                ParameterLocation::FloatRegister { .. } => has_float = true,
                _ => {}
            }
            if matches!(
                p.location,
                ParameterLocation::IntegerRegister { .. } | ParameterLocation::FloatRegister { .. }
            ) && spill_index_for(p).is_none()
            {
                // Some register parameter isn't observed — bail out
                // entirely rather than introducing a spurious order.
                return;
            }
        }
        if !(has_int && has_float) {
            return;
        }

        let mut indexed: Vec<(usize, Parameter)> = sig.parameters.drain(..).enumerate().collect();
        indexed.sort_by(|(orig_a, a), (orig_b, b)| {
            let idx_a = spill_index_for(a);
            let idx_b = spill_index_for(b);
            match (idx_a, idx_b) {
                // Both observed — sort ASCENDING by observation
                // index (= instruction order in the prologue =
                // source-declaration order).
                (Some(ia), Some(ib)) => ia.cmp(&ib),
                // Observed beats not-observed (place observed
                // params first; unobserved fall to the end).
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                // Neither observed — preserve original order.
                (None, None) => orig_a.cmp(orig_b),
            }
        });
        // We intentionally do NOT renumber `argN`/`fargN` names by
        // position. The structured body references each parameter
        // by its ABI register index — on Win64, mixed signatures
        // have POSITIONAL float indices: `void f(int n, double x)`
        // puts `n` in `rcx` (slot 0) and `x` in `xmm1` (slot 1),
        // so the float param's name is `farg1` everywhere the body
        // references it. Renumbering would rewrite the declaration
        // to `farg0` while the body still references `farg1`,
        // producing an inconsistent signature. Codex review on
        // PR #27 pass 13.
        //
        // For SystemV/aarch64 the int and float bank indices are
        // dense from 0 within each bank, so the existing names
        // happen to read as a natural sequence — no renumbering
        // needed.
        // Remap per-parameter provenance keys to the new positions.
        // Without this a function pointer's `function_pointer_reasons`
        // would attach to the wrong (post-reorder) parameter index.
        // Codex review on PR #27 pass 9.
        if !sig.parameter_provenance.is_empty() {
            let old_provenance = std::mem::take(&mut sig.parameter_provenance);
            for (new_idx, (old_idx, _)) in indexed.iter().enumerate() {
                if let Some(reasons) = old_provenance.get(old_idx) {
                    sig.parameter_provenance.insert(new_idx, reasons.clone());
                }
            }
        }
        // Reapply DWARF parameter names by the POST-reorder index.
        // DWARF names are stored in source-declaration order; after
        // reorder the new index N IS the source-position N, so
        // dwarf_param_names[N] is the right name to attach.
        //
        // We OVERWRITE existing names (not just generic
        // `arg*`/`farg*`) because pre-reorder DWARF application
        // attached names by register-bank index. For example a
        // `double f(double x, int n)` whose DWARF names are
        // ["x", "n"] gets pre-reorder names `n` (on rdi, int idx
        // 0) and `x` (on xmm0, float idx 0). After moving float
        // to position 0, we'd skip name reassignment because "n"
        // is non-generic — but it's the WRONG name for the new
        // float-first param. Codex review on PR #27 pass 11.
        if !self.dwarf_param_names.is_empty() {
            for (new_idx, (_, p)) in indexed.iter_mut().enumerate() {
                if let Some(dwarf_name) = self.dwarf_param_names.get(new_idx) {
                    if !dwarf_name.is_empty() {
                        p.name = dwarf_name.clone();
                    }
                }
            }
        }
        sig.parameters = indexed.into_iter().map(|(_, p)| p).collect();
    }

    fn observe_sysv_va_list_assignment(&mut self, lhs: &Expr, rhs: &Expr) {
        if !matches!(self.convention, CallingConvention::SystemV) {
            return;
        }

        let Some(lhs_name) = self.extract_var_name(lhs) else {
            return;
        };
        let lhs_is_stack_slot = matches!(&lhs.kind, ExprKind::Var(var) if matches!(var.kind, VarKind::Stack(_)))
            || self.extract_stack_offset(lhs).is_some();

        if lhs_is_stack_slot {
            // Record every frame-slot constant / pointer store by offset; the
            // va_list `fp_offset` field is resolved later from the full
            // `__va_list_tag` shape (see `resolve_sysv_named_float_count`),
            // never from an isolated value match (codex P2 on PR #46).
            if let Some(off) = self.sysv_stack_slot_offset(lhs) {
                if let ExprKind::IntLit(value) = &rhs.kind {
                    // First write wins: the `va_start` initializer is the first
                    // store to the `gp_offset`/`fp_offset` slot. Later `va_arg`
                    // accesses mutate the same slot (e.g. `fp_offset += 16`),
                    // and keeping the last store would misread that runtime
                    // state as a named-float count (codex P2 on PR #46).
                    self.sysv_stack_const_stores.entry(off).or_insert(*value);
                }
                if Self::expr_is_stack_base_with_const_offset(rhs) {
                    self.sysv_stack_pointer_stores.insert(off);
                }
            }
            match &rhs.kind {
                ExprKind::IntLit(value) => {
                    if let Some(fixed_count) =
                        Self::sysv_va_list_named_param_count_from_gp_offset(*value)
                    {
                        self.sysv_va_list_gp_offset_slots.insert(lhs_name.clone());
                        self.variadic_fixed_param_count = Some(
                            self.variadic_fixed_param_count
                                .unwrap_or(0)
                                .max(fixed_count),
                        );
                    }
                    if Self::is_sysv_va_list_fp_offset(*value) {
                        self.sysv_va_list_fp_offset_slots.insert(lhs_name.clone());
                    }
                }
                ExprKind::Var(var) => self.observe_sysv_va_list_alias(&lhs_name, &var.name),
                ExprKind::Unknown(name) => self.observe_sysv_va_list_alias(&lhs_name, name),
                ExprKind::Cast { expr: inner, .. } => {
                    if let Some(inner_name) = self.extract_var_name(inner) {
                        self.observe_sysv_va_list_alias(&lhs_name, &inner_name);
                    }
                }
                _ => {}
            }

            if Self::expr_is_stack_base_with_const_offset(rhs) {
                self.sysv_va_list_pointer_slots.insert(lhs_name);
            }
            return;
        }

        match &rhs.kind {
            ExprKind::Var(var) => self.observe_sysv_va_list_alias(&lhs_name, &var.name),
            ExprKind::Unknown(name) => self.observe_sysv_va_list_alias(&lhs_name, name),
            ExprKind::Cast { expr: inner, .. } => {
                if let Some(inner_name) = self.extract_var_name(inner) {
                    self.observe_sysv_va_list_alias(&lhs_name, &inner_name);
                }
            }
            _ => {}
        }
    }

    fn observe_sysv_va_list_alias(&mut self, lhs_name: &str, rhs_name: &str) {
        let rhs_name = rhs_name.to_lowercase();
        if self.var_name_traces_to_sysv_slot_set(&rhs_name, &self.sysv_va_list_gp_offset_slots) {
            self.sysv_va_list_gp_offset_slots
                .insert(lhs_name.to_string());
        }
        if self.var_name_traces_to_sysv_slot_set(&rhs_name, &self.sysv_va_list_fp_offset_slots) {
            self.sysv_va_list_fp_offset_slots
                .insert(lhs_name.to_string());
        }
        if self.var_name_traces_to_sysv_slot_set(&rhs_name, &self.sysv_va_list_pointer_slots) {
            self.sysv_va_list_pointer_slots.insert(lhs_name.to_string());
        }
    }

    /// Observe a recovered `va_start(ap, last)` call. This is the marker the
    /// structurer leaves after collapsing the `va_arg` state machine and
    /// scrubbing the raw va_list slot setup; it stands in for the slot stores as
    /// the variadic materialization signal and carries the fixed-parameter count
    /// (the position of the named `last` argument).
    fn observe_va_start_call(&mut self, function_name: &str, args: &[Expr]) {
        if !matches!(self.convention, CallingConvention::SystemV) {
            return;
        }
        if ParameterUsageHints::normalize_callback_name(function_name) != "va_start" {
            return;
        }
        self.sysv_va_start_seen = true;
        if let Some(last) = args.get(1) {
            if let Some(count) = Self::va_start_last_param_count(last) {
                self.variadic_fixed_param_count =
                    Some(self.variadic_fixed_param_count.unwrap_or(0).max(count));
            }
        }
    }

    /// Derive the fixed-parameter count from the named `last` argument of a
    /// recovered `va_start(ap, argN)` call: `argN` means `N + 1` fixed params.
    fn va_start_last_param_count(last: &Expr) -> Option<usize> {
        let name = match &last.kind {
            ExprKind::Unknown(name) => name.as_str(),
            ExprKind::Var(var) => var.name.as_str(),
            _ => return None,
        };
        let idx: usize = name.strip_prefix("arg")?.parse().ok()?;
        Some(idx + 1)
    }

    fn observe_variadic_forwarding_call(&mut self, function_name: &str, args: &[Expr]) {
        if !self.has_sysv_va_list_materialization() {
            return;
        }

        let Some(fixed_arg_count) = Self::known_va_list_forwarder_fixed_arg_count(function_name)
        else {
            return;
        };
        if args.len() <= fixed_arg_count {
            return;
        }
        if !self.expr_looks_like_sysv_va_list_arg(&args[fixed_arg_count]) {
            return;
        }

        let known_params = Self::known_function_params(function_name);
        self.variadic_fixed_param_count = Some(
            self.variadic_fixed_param_count.unwrap_or(0).max(
                (0..fixed_arg_count)
                    .filter_map(|arg_index| {
                        self.resolve_param_index_from_expr_precise(&args[arg_index])
                            .map(|param_idx| {
                                if let Some((param_name, param_type)) = known_params
                                    .as_ref()
                                    .and_then(|params| params.get(arg_index))
                                {
                                    self.param_names
                                        .entry(param_idx)
                                        .or_insert_with(|| param_name.clone());
                                    self.param_type_overrides
                                        .entry(param_idx)
                                        .or_insert_with(|| param_type.clone());
                                }
                                param_idx + 1
                            })
                    })
                    .max()
                    .unwrap_or(1),
            ),
        );

        // TODO(45.2): materialize a synthetic `va_list ap` local so forwarded wrappers
        // decompile as `vprintf(fmt, ap)` instead of exposing the raw stack root.
    }

    fn observe_printf_format_forwarding_call(&mut self, function_name: &str, args: &[Expr]) {
        let Some(format_index) = Self::known_printf_format_arg_index(function_name) else {
            return;
        };
        let Some(format) = args
            .get(format_index)
            .and_then(|expr| self.extract_string_literal(expr))
        else {
            return;
        };

        for (offset, param_type) in Self::parse_printf_format_param_types(&format)
            .into_iter()
            .enumerate()
        {
            let Some(arg) = args.get(format_index + 1 + offset) else {
                break;
            };
            let Some(param_idx) = self.resolve_param_index_from_expr_precise(arg) else {
                continue;
            };

            self.param_type_overrides
                .entry(param_idx)
                .or_insert_with(|| param_type.clone());
            if matches!(param_type, ParamType::SizeT) {
                self.record_usage_hint(&format!("arg{}", param_idx), |h| h.is_size_param = true);
            }
        }
    }

    fn known_printf_format_arg_index(function_name: &str) -> Option<usize> {
        match ParameterUsageHints::normalize_callback_name(function_name) {
            "printf" => Some(0),
            "fprintf" | "dprintf" | "syslog" => Some(1),
            "sprintf" | "asprintf" => Some(1),
            "snprintf" => Some(2),
            "printf_chk" => Some(1),
            "fprintf_chk" | "dprintf_chk" => Some(2),
            "sprintf_chk" | "asprintf_chk" => Some(3),
            "snprintf_chk" => Some(4),
            _ => None,
        }
    }

    fn extract_string_literal(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Unknown(text)
                if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 =>
            {
                Some(text[1..text.len() - 1].to_string())
            }
            ExprKind::IntLit(value) if *value >= 0 && *value <= i128::from(u64::MAX) => {
                self.read_string_from_binary_data(*value as u64)
            }
            ExprKind::GotRef { address, .. } => self.read_string_from_binary_data(*address),
            ExprKind::Cast { expr: inner, .. } => self.extract_string_literal(inner),
            _ => None,
        }
    }

    fn read_string_from_binary_data(&self, address: u64) -> Option<String> {
        let binary_data = self.binary_data.as_deref()?;
        let (section, base) = binary_data.section_containing(address)?;
        let start = usize::try_from(address.checked_sub(base)?).ok()?;
        let suffix = section.get(start..)?;
        let end = suffix.iter().position(|byte| *byte == 0)?;
        std::str::from_utf8(&suffix[..end]).ok().map(str::to_string)
    }

    fn parse_printf_format_param_types(format: &str) -> Vec<ParamType> {
        let bytes = format.as_bytes();
        let mut i = 0usize;
        let mut types = Vec::new();

        while i < bytes.len() {
            if bytes[i] != b'%' {
                i += 1;
                continue;
            }
            i += 1;
            if i >= bytes.len() {
                break;
            }
            if bytes[i] == b'%' {
                i += 1;
                continue;
            }

            while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b' ' | b'+' | b'\'') {
                i += 1;
            }

            if i < bytes.len() && bytes[i] == b'*' {
                types.push(ParamType::SignedInt(32));
                i += 1;
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }

            if i < bytes.len() && bytes[i] == b'.' {
                i += 1;
                if i < bytes.len() && bytes[i] == b'*' {
                    types.push(ParamType::SignedInt(32));
                    i += 1;
                } else {
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                }
            }

            let mut long_double = false;
            let mut length = PrintfLengthModifier::None;
            if i + 1 < bytes.len() {
                match &bytes[i..i + 2] {
                    b"hh" => {
                        length = PrintfLengthModifier::CharChar;
                        i += 2;
                    }
                    b"ll" => {
                        length = PrintfLengthModifier::LongLong;
                        i += 2;
                    }
                    _ => {}
                }
            }
            if matches!(length, PrintfLengthModifier::None) && i < bytes.len() {
                match bytes[i] {
                    b'h' => {
                        length = PrintfLengthModifier::Short;
                        i += 1;
                    }
                    b'l' => {
                        length = PrintfLengthModifier::Long;
                        i += 1;
                    }
                    b'j' => {
                        length = PrintfLengthModifier::IntMax;
                        i += 1;
                    }
                    b'z' => {
                        length = PrintfLengthModifier::Size;
                        i += 1;
                    }
                    b't' => {
                        length = PrintfLengthModifier::PtrDiff;
                        i += 1;
                    }
                    b'L' => {
                        long_double = true;
                        i += 1;
                    }
                    _ => {}
                }
            }

            if i >= bytes.len() {
                break;
            }

            if let Some(param_type) =
                Self::printf_conversion_param_type(bytes[i] as char, length, long_double)
            {
                types.push(param_type);
            }
            i += 1;
        }

        types
    }

    fn printf_conversion_param_type(
        specifier: char,
        length: PrintfLengthModifier,
        long_double: bool,
    ) -> Option<ParamType> {
        match specifier {
            'd' | 'i' => Some(match length {
                PrintfLengthModifier::PtrDiff => ParamType::PtrDiffT,
                PrintfLengthModifier::LongLong | PrintfLengthModifier::IntMax => {
                    ParamType::SignedInt(64)
                }
                _ => ParamType::SignedInt(32),
            }),
            'u' | 'o' | 'x' | 'X' => Some(match length {
                PrintfLengthModifier::LongLong => ParamType::UnsignedLongLong,
                PrintfLengthModifier::Size => ParamType::SizeT,
                PrintfLengthModifier::PtrDiff | PrintfLengthModifier::IntMax => {
                    ParamType::UnsignedInt(64)
                }
                _ => ParamType::UnsignedInt(32),
            }),
            'c' => Some(ParamType::SignedInt(32)),
            's' => Some(ParamType::Pointer),
            'p' => Some(ParamType::Pointer),
            'n' => Some(ParamType::TypedPointer(Box::new(ParamType::SignedInt(32)))),
            'a' | 'A' | 'e' | 'E' | 'f' | 'F' | 'g' | 'G' => Some(if long_double {
                ParamType::Float(80)
            } else {
                ParamType::Float(64)
            }),
            _ => None,
        }
    }

    fn infer_variadic_fixed_param_count(&self, used_args: &[usize]) -> Option<usize> {
        // aarch64 AAPCS: the `__va_list` tag's `__gr_offs` directly encodes the
        // named integer-parameter prefix; the SysV materialization heuristics
        // below don't apply (different ABI / tag layout).
        if let Some((named_gp, _)) = self.aapcs_va_list_counts {
            return Some(named_gp);
        }
        if !self.has_sysv_va_list_materialization() {
            return None;
        }

        // TODO(45.1): collapse the full SysV `va_arg` state machine into a dedicated
        // `va_arg(ap, T)` IR node instead of only repairing the wrapper signature.
        if let Some(fixed_count) = self.variadic_fixed_param_count {
            return Some(fixed_count);
        }

        let mut fixed_prefix = 0usize;
        for idx in 0..self.convention.max_int_args() {
            if !used_args.contains(&idx) {
                if fixed_prefix > 0 {
                    break;
                }
                continue;
            }
            if self.variadic_fixed_param_has_signal(idx) {
                fixed_prefix = idx + 1;
            } else if fixed_prefix > 0 {
                break;
            }
        }

        if fixed_prefix > 0 {
            Some(fixed_prefix)
        } else {
            (!used_args.is_empty()).then_some(1)
        }
    }

    fn variadic_fixed_param_has_signal(&self, idx: usize) -> bool {
        self.param_type_overrides.contains_key(&idx)
            || self
                .param_hints
                .get(&idx)
                .is_some_and(ParameterUsageHints::has_strong_signal)
            || self
                .dwarf_param_names
                .get(idx)
                .is_some_and(|name| !name.is_empty())
            || self.param_names.get(&idx).is_some_and(|name| {
                !name.is_empty()
                    && name != &format!("arg{idx}")
                    && !name.starts_with("var_")
                    && !name.starts_with("local_")
            })
    }

    fn has_sysv_va_list_materialization(&self) -> bool {
        if !matches!(self.convention, CallingConvention::SystemV) {
            return false;
        }
        // A recovered `va_start` call is on its own definitive: the structurer
        // only emits it after matching the full va_arg state machine, having
        // scrubbed the raw slot stores the checks below would otherwise see.
        if self.sysv_va_start_seen {
            return true;
        }
        !self.sysv_va_list_gp_offset_slots.is_empty()
            && self.sysv_va_list_pointer_slots.len() >= 2
            && (!self.sysv_va_list_fp_offset_slots.is_empty()
                || self.has_observed_register_varargs_spills())
    }

    fn has_observed_register_varargs_spills(&self) -> bool {
        self.convention
            .integer_arg_registers()
            .iter()
            .zip(self.convention.integer_arg_registers_32().iter())
            .enumerate()
            .skip(1)
            .any(|(idx, (reg64, reg32))| {
                self.read_regs.contains(&format!("arg{}", idx))
                    || self.read_regs.contains(&reg64.to_lowercase())
                    || self.read_regs.contains(&reg32.to_lowercase())
            })
    }

    fn known_va_list_forwarder_fixed_arg_count(function_name: &str) -> Option<usize> {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        match clean {
            "vprintf" => Some(1),
            "vfprintf" | "vdprintf" | "vsyslog" => Some(2),
            "vsprintf" | "vasprintf" => Some(2),
            "vsnprintf" => Some(3),
            "vprintf_chk" => Some(2),
            "vfprintf_chk" | "vdprintf_chk" => Some(3),
            "vsprintf_chk" | "vasprintf_chk" => Some(4),
            "vsnprintf_chk" => Some(5),
            _ => None,
        }
    }

    fn sysv_va_list_named_param_count_from_gp_offset(value: i128) -> Option<usize> {
        if (0..48).contains(&value) && value % 8 == 0 {
            return usize::try_from(value / 8).ok();
        }
        None
    }

    fn is_sysv_va_list_fp_offset(value: i128) -> bool {
        (48..=176).contains(&value) && value % 16 == 0
    }

    /// Number of named float/SSE parameters encoded by a SysV `va_start`
    /// `fp_offset` initialiser. The FP register-save area sits after the 6
    /// general-purpose slots (6 * 8 = 48 bytes), and each named float param
    /// consumes one 16-byte SSE slot, so `fp_offset = 48 + 16 * named_floats`.
    /// `fp_offset == 48` therefore means zero named floats (the common
    /// integer-named variadic case).
    fn sysv_va_list_named_float_count_from_fp_offset(value: i128) -> Option<usize> {
        if (48..=176).contains(&value) && value % 16 == 0 {
            return usize::try_from((value - 48) / 16).ok();
        }
        None
    }

    /// Frame offset of a stack slot expression, accepting both the bare
    /// `Var(Stack(off))` form and the deref-of-frame-base form
    /// [`Self::extract_stack_offset`] handles. Used to locate the va_list
    /// `gp_offset`/`fp_offset` fields by their layout positions.
    fn sysv_stack_slot_offset(&self, expr: &Expr) -> Option<i64> {
        if let ExprKind::Var(v) = &expr.kind {
            if let VarKind::Stack(off) = v.kind {
                return Some(off);
            }
        }
        self.extract_stack_offset(expr)
            .and_then(|off| i64::try_from(off).ok())
    }

    /// Number of named float params, read from the SysV `__va_list_tag`'s
    /// `fp_offset` field — but only once a genuine tag is located by its full
    /// shape: `gp_offset` (8*k) at base `b`, `fp_offset` (48+16*f) at `b+4`,
    /// and `stack_base`-relative pointer fields (`overflow_arg_area` /
    /// `reg_save_area`) at `b+8` and `b+16`. Requiring all four fields rejects
    /// an unrelated adjacent pair of gp/fp-looking constants (codex P2 on PR
    /// #46). `None` when no such tag is present (e.g. the structurer already
    /// collapsed the diamond), so callers fall back to the integer prefix.
    ///
    /// Candidate bases are scanned in a deterministic (sorted) order so the
    /// recovered signature is stable. (A local aggregate initialised to the
    /// *exact* 24-byte va_list-tag shape — two small int constants followed by
    /// two stack-relative pointers at +8/+16 — would also match; that is not a
    /// shape compilers emit for ordinary locals, so it is an accepted
    /// theoretical residual rather than a practical hazard.)
    fn resolve_sysv_named_float_count(&self) -> Option<usize> {
        let mut bases: Vec<i64> = self.sysv_stack_const_stores.keys().copied().collect();
        bases.sort_unstable();
        for base in bases {
            let Some(&gp_value) = self.sysv_stack_const_stores.get(&base) else {
                continue;
            };
            if Self::sysv_va_list_named_param_count_from_gp_offset(gp_value).is_none() {
                continue;
            }
            let Some(&fp_value) = self.sysv_stack_const_stores.get(&(base + 4)) else {
                continue;
            };
            let Some(float_count) = Self::sysv_va_list_named_float_count_from_fp_offset(fp_value)
            else {
                continue;
            };
            if self.sysv_stack_pointer_stores.contains(&(base + 8))
                && self.sysv_stack_pointer_stores.contains(&(base + 16))
            {
                return Some(float_count);
            }
        }
        None
    }

    fn expr_looks_like_sysv_va_list_arg(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => {
                let lowered = var.name.to_lowercase();
                matches!(lowered.as_str(), "rsp" | "esp" | "sp")
                    || self.var_name_traces_to_sysv_slot_set(
                        &lowered,
                        &self.sysv_va_list_pointer_slots,
                    )
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                matches!(lowered.as_str(), "rsp" | "esp" | "sp")
                    || self.var_name_traces_to_sysv_slot_set(
                        &lowered,
                        &self.sysv_va_list_pointer_slots,
                    )
            }
            ExprKind::AddressOf(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.expr_looks_like_sysv_va_list_arg(inner)
            }
            ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. } => {
                self.extract_var_name(expr).is_some_and(|name| {
                    self.var_name_traces_to_sysv_slot_set(&name, &self.sysv_va_list_pointer_slots)
                })
            }
            _ => false,
        }
    }

    fn var_name_traces_to_sysv_slot_set(&self, var_name: &str, slots: &HashSet<String>) -> bool {
        let mut queue = VecDeque::new();
        queue.push_back(var_name.to_lowercase());
        for alias in Self::lifted_alias_name_variants(var_name) {
            queue.push_back(alias);
        }
        let mut visited = HashSet::new();
        while let Some(name) = queue.pop_front() {
            let lowered = name.to_lowercase();
            if !visited.insert(lowered.clone()) {
                continue;
            }
            if slots.contains(&lowered) {
                return true;
            }
            if let Some(next) = self.resolve_latest_value_alias(&lowered) {
                queue.push_back(next);
            }
        }
        false
    }

    fn expr_is_stack_base_with_const_offset(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add | BinOpKind::Sub,
                left,
                right,
            } => {
                matches!(&left.kind, ExprKind::Var(var) if is_stack_base_register(&var.name))
                    && matches!(right.kind, ExprKind::IntLit(_))
            }
            ExprKind::Cast { expr: inner, .. } => Self::expr_is_stack_base_with_const_offset(inner),
            _ => false,
        }
    }

    /// Detects common parameter pairs like (buffer, size) and improves naming.
    fn detect_param_pairs(&self, sig: &mut FunctionSignature) {
        if sig.parameters.len() < 2 {
            return;
        }

        // Look for pointer + size pairs
        let mut i = 0;
        while i < sig.parameters.len() - 1 {
            let is_ptr = matches!(sig.parameters[i].param_type, ParamType::Pointer);
            let is_size = matches!(
                sig.parameters[i + 1].param_type,
                ParamType::UnsignedInt(_)
                    | ParamType::SignedInt(32 | 64)
                    | ParamType::UnsignedLongLong
                    | ParamType::SizeT
                    | ParamType::PtrDiffT
            );

            if is_ptr && is_size {
                // Check if the size param has hints suggesting it's a size
                let next_idx = match &sig.parameters[i + 1].location {
                    ParameterLocation::IntegerRegister { index, .. } => Some(*index),
                    _ => None,
                };

                if let Some(idx) = next_idx {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        if hints.is_loop_bound || hints.is_array_index {
                            // This is likely a size parameter
                            sig.parameters[i + 1].param_type = match sig.parameters[i + 1]
                                .param_type
                            {
                                ParamType::SignedInt(bits) if hints.is_signed_comparison => {
                                    ParamType::SignedInt(bits.max(32))
                                }
                                ParamType::UnsignedInt(bits) => {
                                    ParamType::UnsignedInt(bits.max(32))
                                }
                                ParamType::SignedInt(bits) => ParamType::UnsignedInt(bits.max(32)),
                                _ if hints.is_signed_comparison => ParamType::SignedInt(32),
                                _ => ParamType::UnsignedInt(32),
                            };
                            if sig.parameters[i + 1].name.starts_with("arg") {
                                sig.parameters[i + 1].name = match i {
                                    0 => "size".to_string(),
                                    1 => "count".to_string(),
                                    _ => format!("n{}", i + 1),
                                };
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }
}

/// Checks if a register name is a frame pointer.
fn is_frame_pointer(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "rbp" | "ebp" | "x29" | "fp" | "s0"
    )
}

fn is_stack_base_register(name: &str) -> bool {
    is_frame_pointer(name) || matches!(name.to_lowercase().as_str(), "rsp" | "esp" | "sp" | "x31")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{CallTarget, VarKind, Variable};
    use hexray_core::BasicBlockId;
    use std::sync::Arc;

    fn xmm(idx: u16) -> hexray_core::Register {
        use hexray_core::{Architecture, RegisterClass};
        // x86 XMM0 == 64; the 128-bit form renders as "xmm{idx}".
        hexray_core::Register::new(Architecture::X86_64, RegisterClass::Vector, 64 + idx, 128)
    }

    /// aarch64 vector register at idx 0..31. `bits` selects the
    /// access width — 32 for `s*`, 64 for `d*`, 128 for `q*`/`v*`.
    /// Arm64 vector register ID base in hexray-core is 64, so the
    /// renderer uses `64 + idx`.
    fn aarch64_v(idx: u16, bits: u16) -> hexray_core::Register {
        use hexray_core::{Architecture, RegisterClass};
        hexray_core::Register::new(Architecture::Arm64, RegisterClass::Vector, 64 + idx, bits)
    }

    fn aarch64_x(idx: u16, bits: u16) -> hexray_core::Register {
        use hexray_core::{Architecture, RegisterClass};
        hexray_core::Register::new(Architecture::Arm64, RegisterClass::General, idx, bits)
    }

    fn aarch64_mem(base: hexray_core::Register, disp: i64) -> Operand {
        Operand::Memory(hexray_core::MemoryRef::base_disp(base, disp, 8))
    }

    /// Build a one-block aarch64 CFG (instead of the x86 helper) for
    /// regression tests that need the Arm64 architecture stamp.
    fn aarch64_single_block_cfg(insts: Vec<(&str, Operation, Vec<Operand>)>) -> ControlFlowGraph {
        use hexray_core::{BasicBlock, BlockTerminator, Instruction};
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut addr = 0x1000u64;
        for (mnemonic, op, operands) in insts {
            block.instructions.push(
                Instruction::new(addr, 4, vec![], mnemonic)
                    .with_operation(op)
                    .with_operands(operands),
            );
            addr += 4;
        }
        block.terminator = BlockTerminator::Return;
        cfg.add_block(block);
        cfg
    }

    fn gpr(id: u16, bits: u16) -> hexray_core::Register {
        use hexray_core::{Architecture, RegisterClass};
        hexray_core::Register::new(Architecture::X86_64, RegisterClass::General, id, bits)
    }

    /// Build a one-block CFG from a list of (mnemonic, operation, operands).
    fn single_block_cfg(insts: Vec<(&str, Operation, Vec<Operand>)>) -> ControlFlowGraph {
        use hexray_core::{BasicBlock, BlockTerminator, Instruction};
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut addr = 0x1000u64;
        for (mnemonic, op, operands) in insts {
            block.instructions.push(
                Instruction::new(addr, 4, vec![], mnemonic)
                    .with_operation(op)
                    .with_operands(operands),
            );
            addr += 4;
        }
        block.terminator = BlockTerminator::Return;
        cfg.add_block(block);
        cfg
    }

    fn mem(base: hexray_core::Register, disp: i64) -> Operand {
        Operand::Memory(hexray_core::MemoryRef::base_disp(base, disp, 8))
    }

    #[test]
    fn scan_detects_spilled_double_args() {
        // movsd %xmm0,[rbp-8] ; movsd %xmm1,[rbp-16]  (the -O0 arg spill)
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![
            (
                "movsd",
                Operation::Store,
                vec![mem(rbp, -8), Operand::Register(xmm(0))],
            ),
            (
                "movsd",
                Operation::Store,
                vec![mem(rbp, -16), Operand::Register(xmm(1))],
            ),
        ]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert_eq!(
            found,
            vec![(0, "xmm0".to_string(), 8), (1, "xmm1".to_string(), 8)]
        );
    }

    /// SSE-1: the prologue spill scanner must record the order in
    /// which parameter registers are spilled to the stack. For
    /// `double scale_sum(double x, int n)` clang emits
    /// `movsd [rbp-8], xmm0; mov [rbp-12], edi` — xmm0 at -8 (the
    /// first source param), edi at -12 (the second). Verify both
    /// are captured in instruction order with the right offsets.
    #[test]
    fn scan_param_spill_order_captures_mixed_int_float_spills() {
        let rbp = gpr(5, 64);
        let edi = gpr(7, 32);
        let cfg = single_block_cfg(vec![
            (
                "movsd",
                Operation::Store,
                vec![mem(rbp, -8), Operand::Register(xmm(0))],
            ),
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -12), Operand::Register(edi)],
            ),
        ]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert_eq!(
            order,
            vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "edi".to_string(),
                    offset: -12,
                },
            ]
        );
    }

    // Removed `scan_param_spill_order_ignores_reg_to_reg_moves`:
    // pass-3 strengthening means reg-reg moves correctly TERMINATE
    // the scan rather than being silently skipped (otherwise body
    // stores after them would pollute observations). The new
    // `scan_param_spill_order_terminates_on_reg_reg_move` test
    // covers the corrected behavior.

    /// Codex review on PR #27 pass 7: a narrow integer arg like
    /// `char c` is spilled as `dil` at `-O0`. The scanner must
    /// canonicalize `dil` (and `di`, `r8b`, etc.) to the 64-bit
    /// ABI name `rdi` so it's recognized as an arg-register spill.
    #[test]
    fn scan_param_spill_order_normalizes_narrow_int_aliases() {
        let rbp = gpr(5, 64);
        let dil = gpr(7, 8); // 8-bit form of rdi
        let cfg = single_block_cfg(vec![(
            "mov",
            Operation::Move,
            vec![mem(rbp, -4), Operand::Register(dil)],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -4,
            }],
            "narrow int alias (dil) must normalize to ABI rdi"
        );
    }

    /// Codex review on PR #27 pass 6: under -fomit-frame-pointer
    /// rbp can be used as a general-purpose register: `mov rbp,
    /// rdi` is body work, NOT frame setup. The scaffold detector
    /// must require the SOURCE be the stack pointer (for `mov`) or
    /// an immediate (for `add/sub`), not just look at the
    /// destination. Verify body `mov rbp, rdi` breaks the scan so
    /// a later body store isn't mistaken for a prologue spill.
    #[test]
    fn scan_param_spill_order_does_not_accept_body_mov_to_rbp() {
        let rbp = gpr(5, 64);
        let rdi = gpr(7, 64);
        let esi = gpr(6, 32);
        let cfg = single_block_cfg(vec![
            // Body work: rbp = rdi (rbp used as GPR).
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(rbp), Operand::Register(rdi)],
            ),
            // Later body store — must NOT be recorded.
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -20), Operand::Register(esi)],
            ),
        ]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert!(
            order.is_empty(),
            "`mov rbp, rdi` (body work) must break the scan, got {order:?}"
        );
    }

    /// Codex review on PR #27 pass 5: aarch64 `-O0` typically
    /// spills parameters relative to `x29` (frame pointer) after
    /// `mov x29, sp` — `str d0, [x29, #-8]`. The frame-base check
    /// must accept x29/fp/x31 in addition to the x86 rbp/rsp set.
    #[test]
    fn scan_param_spill_order_accepts_x29_relative_spills() {
        let x29 = aarch64_x(29, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 64)), aarch64_mem(x29, -8)],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "d0".to_string(),
                offset: -8,
            }],
            "x29-relative spill must be recognized"
        );
    }

    /// Codex review on PR #27 pass 4: aarch64 single-precision
    /// spills use the `s0`/`s1` register name. The scanner must
    /// normalize them to the ABI name `d0`/`d1` so the float bank
    /// recognizes them. Without this, a `float`-typed parameter
    /// is silently dropped and mixed signatures don't reorder.
    #[test]
    fn scan_param_spill_order_normalizes_aarch64_s_register() {
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            // 32-bit width = `s0` (single-precision).
            vec![Operand::Register(aarch64_v(0, 32)), aarch64_mem(sp, 4)],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "d0".to_string(),
                offset: 4,
            }],
            "aarch64 s0 must normalize to ABI name d0"
        );
    }

    /// Codex review on PR #27 pass 4: aarch64 standard `-O0`
    /// prologue is `stp x29, x30, [sp, #-16]!; mov x29, sp` —
    /// the `mov x29, sp` is frame setup, not body work. The
    /// scaffold detector must whitelist x29/fp as a destination
    /// for `mov`-style instructions.
    #[test]
    fn scan_param_spill_order_treats_aarch64_x29_setup_as_scaffold() {
        let sp = aarch64_x(31, 64);
        let x29 = aarch64_x(29, 64);
        let cfg = aarch64_single_block_cfg(vec![
            // mov x29, sp  — frame-pointer setup (skip).
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(x29), Operand::Register(sp)],
            ),
            // str d0, [sp, #8]  — first param spill.
            (
                "str",
                Operation::Store,
                vec![Operand::Register(aarch64_v(0, 64)), aarch64_mem(sp, 8)],
            ),
        ]);
        let order = scan_param_spill_order(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "d0".to_string(),
                offset: 8,
            }],
            "x29 frame setup must not break the scan"
        );
    }

    /// Codex review on PR #27 pass 3: aarch64 `str d0, [sp, #8]`
    /// has operand[0] = register (source), operand[1] = memory
    /// (destination) — opposite of x86. The scanner must recognize
    /// both layouts.
    #[test]
    fn scan_param_spill_order_handles_aarch64_str_layout() {
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 64)), aarch64_mem(sp, 8)],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "d0".to_string(),
                offset: 8,
            }],
            "aarch64 STR must be detected (reg, mem layout)"
        );
    }

    /// Codex review on PR #27 pass 3: aarch64 `stp d0, d1, [sp, #-16]!`
    /// stores TWO registers as a pair. Both should be captured in
    /// order with sequential offsets.
    #[test]
    fn scan_param_spill_order_handles_aarch64_stp_pair() {
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "stp",
            Operation::Store,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
                aarch64_mem(sp, -16),
            ],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            order,
            vec![
                ParamSpillObservation {
                    register: "d0".to_string(),
                    offset: -16,
                },
                ParamSpillObservation {
                    register: "d1".to_string(),
                    offset: -8,
                },
            ],
            "aarch64 STP must record both registers as a pair"
        );
    }

    /// Codex review on PR #27 pass 3: a reg-reg move like
    /// `mov rax, rdi` is body work, not a prologue spill. It must
    /// terminate the scan so later body stores don't pollute the
    /// observation list.
    #[test]
    fn scan_param_spill_order_terminates_on_reg_reg_move() {
        let rbp = gpr(5, 64);
        let rax = gpr(0, 64);
        let rdi = gpr(7, 64);
        let esi = gpr(6, 32);
        let cfg = single_block_cfg(vec![
            // Real prologue spill.
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -8), Operand::Register(rdi)],
            ),
            // Body reg-reg move — should STOP the scan.
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(rax), Operand::Register(rdi)],
            ),
            // Later body store — must NOT be picked up.
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -20), Operand::Register(esi)],
            ),
        ]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -8,
            }],
            "scan must stop at reg-reg move"
        );
    }

    /// Codex review on PR #27 passes 10 & 11: when DWARF names
    /// are available they're applied by register-bank index BEFORE
    /// the reorder runs — so an int param gets `dwarf_names[0]`
    /// and a float param gets `dwarf_names[0]` too, leading to
    /// duplicate or stale names after reorder. Verify the reorder
    /// reapplies the source-order DWARF names to ALL parameters
    /// regardless of their pre-reorder names. Pass 11 strengthened
    /// the assertion to also catch the previously-passing case
    /// where the pre-reorder name happened to be non-generic.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_overwrites_stale_dwarf_names_after_remap() {
        let mut sig = FunctionSignature::default();
        // Pre-reorder names attached by register bank — the
        // dwarf-name-application step attached `x` (dwarf[0]) to
        // the int param (rdi was index 0 in the int bank) and `n`
        // (dwarf[1]? — but float bank index 0 → in our codebase
        // the float assignment may attach a different name). In
        // any case, after reorder the names should match
        // source-order DWARF.
        sig.parameters = vec![
            Parameter::new(
                "x".to_string(), // STALE — was attached to int by old bank order
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rdi".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "n".to_string(), // STALE
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm0".to_string(),
                    index: 0,
                },
            ),
        ];
        // DWARF source order: ["x" (the double), "n" (the int)].
        let recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_dwarf_param_names(vec!["x".to_string(), "n".to_string()])
            .with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -16,
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);
        // Float (now at index 0) takes dwarf[0]="x"; int (index 1)
        // takes dwarf[1]="n".
        assert_eq!(sig.parameters[0].name, "x");
        assert_eq!(sig.parameters[1].name, "n");
        // And the types match their parameters: float param is
        // double, int param is int.
        assert!(matches!(sig.parameters[0].param_type, ParamType::Float(64)));
        assert!(matches!(
            sig.parameters[1].param_type,
            ParamType::SignedInt(32)
        ));
    }

    /// Codex review on PR #27 pass 13: on Win64 `void f(int n,
    /// double x)` puts the float in xmm1 (positional slot 1), so
    /// its name is `farg1` everywhere the body references it.
    /// The reorder must NOT renumber it to `farg0` even after
    /// moving it to position 0 — that would break the body→
    /// declaration alignment.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_preserves_abi_indexed_farg_names_on_win64() {
        let mut sig = FunctionSignature::default();
        sig.parameters = vec![
            Parameter::new(
                "arg0".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rcx".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "farg1".to_string(), // Win64 positional float index
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm1".to_string(),
                    index: 1,
                },
            ),
        ];
        let recovery =
            SignatureRecovery::new(CallingConvention::Win64).with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm1".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rcx".to_string(),
                    offset: -16,
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);
        // The float moves to position 0 BUT keeps its ABI name
        // `farg1` (matching the body), not renumbered to `farg0`.
        // Note: Win64 might not actually trigger the reorder (it's
        // gated to int+float observed), but the principle holds:
        // we don't renumber.
        // Find the float parameter regardless of position and
        // assert its name stayed `farg1`.
        let float_param = sig
            .parameters
            .iter()
            .find(|p| matches!(p.location, ParameterLocation::FloatRegister { .. }))
            .expect("float param present");
        assert_eq!(
            float_param.name, "farg1",
            "ABI-indexed farg name must NOT be renumbered to farg0 — body references farg1"
        );
    }

    /// Codex review on PR #27 pass 10 alternate: when the pre-
    /// reorder names ARE generic (arg/farg), the DWARF names
    /// should be reapplied by the new index so float goes to "x"
    /// and int goes to "n".
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_applies_dwarf_names_to_generic_arg_farg_after_reorder() {
        let mut sig = FunctionSignature::default();
        sig.parameters = vec![
            Parameter::new(
                "arg0".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rdi".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "farg0".to_string(),
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm0".to_string(),
                    index: 0,
                },
            ),
        ];
        let recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_dwarf_param_names(vec!["x".to_string(), "n".to_string()])
            .with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -16,
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);
        // After reorder, float at position 0 gets DWARF[0]="x";
        // int at position 1 gets DWARF[1]="n".
        assert_eq!(sig.parameters[0].name, "x");
        assert_eq!(sig.parameters[1].name, "n");
    }

    /// Codex review on PR #27 pass 9: parameter_provenance is a
    /// `HashMap<usize, Vec<String>>` keyed by parameter index.
    /// Reordering parameters without remapping these keys causes
    /// e.g. function-pointer-callback reasons to attach to the
    /// wrong (post-reorder) parameter. Verify provenance follows
    /// the parameter as it moves.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_remaps_parameter_provenance() {
        let mut sig = FunctionSignature::default();
        // Pre-reorder: arg0 (int) at index 0 with provenance,
        // farg0 (float) at index 1 without.
        sig.parameters = vec![
            Parameter::new(
                "arg0".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rdi".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "farg0".to_string(),
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm0".to_string(),
                    index: 0,
                },
            ),
        ];
        sig.parameter_provenance
            .insert(0, vec!["callback hint".to_string()]);

        let recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_param_spill_order(vec![
                // Float observed first → moves to index 0.
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -16,
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);

        // Float now at index 0, int at index 1. Provenance should
        // follow the int parameter to its new position (1).
        assert!(
            !sig.parameter_provenance.contains_key(&0),
            "provenance must not stay at old index 0"
        );
        assert_eq!(
            sig.parameter_provenance.get(&1),
            Some(&vec!["callback hint".to_string()]),
            "provenance must follow the int param to its new index 1"
        );
    }

    /// Codex review on PR #27 pass 8: when only SOME params have
    /// spill observations, the reorder must bail out entirely
    /// rather than rearrange the partial set. For `(int a, int b,
    /// double x)` where only `a` and `xmm0` were spilled (b lives
    /// in `esi` and was never homed), reordering would invent the
    /// wrong source order `(a, x, b)`.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_bails_when_some_params_have_no_spill_observation() {
        let mut sig = FunctionSignature::default();
        sig.parameters = vec![
            Parameter::new(
                "arg0".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rdi".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "arg1".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rsi".to_string(),
                    index: 1,
                },
            ),
            Parameter::new(
                "farg0".to_string(),
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm0".to_string(),
                    index: 0,
                },
            ),
        ];
        // Only rdi (arg0) and xmm0 (farg0) have spill observations
        // — rsi (arg1) was not spilled. Reorder must NOT fire.
        let recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -4,
                },
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -16,
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);
        // Order must remain unchanged.
        let names: Vec<&str> = sig.parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["arg0", "arg1", "farg0"],
            "must NOT reorder when arg1 has no spill observation"
        );
    }

    /// Codex review on PR #27 pass 2: aarch64 packs int (4 bytes)
    /// and float (8 bytes) spills with different alignment, so
    /// spill offsets are NOT monotonic in source-declaration
    /// order. Verify the reorder helper uses observation INDEX
    /// (instruction order), not offset — a fake order list with
    /// non-monotonic offsets but correct sequence should still
    /// yield correct source ordering.
    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn reorder_uses_observation_index_not_offset() {
        let mut sig = FunctionSignature::default();
        sig.parameters = vec![
            Parameter::new(
                "arg0".to_string(),
                ParamType::SignedInt(32),
                ParameterLocation::IntegerRegister {
                    name: "rdi".to_string(),
                    index: 0,
                },
            ),
            Parameter::new(
                "farg0".to_string(),
                ParamType::Float(64),
                ParameterLocation::FloatRegister {
                    name: "xmm0".to_string(),
                    index: 0,
                },
            ),
        ];
        // Pretend rdi was spilled SECOND (at a HIGHER offset than
        // xmm0) — offset alone would put rdi first by descending
        // sort, but observation index says float was first.
        let recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -32, // would lose by offset sort
                },
                ParamSpillObservation {
                    register: "edi".to_string(),
                    offset: -8, // would win by offset sort
                },
            ]);
        recovery.reorder_params_by_spill_offset(&mut sig);
        // Float must be first because it was observed first.
        assert!(matches!(
            sig.parameters[0].location,
            ParameterLocation::FloatRegister { .. }
        ));
        assert!(matches!(
            sig.parameters[1].location,
            ParameterLocation::IntegerRegister { .. }
        ));
    }

    /// Codex review on PR #27 pass 1: a reload like
    /// `mov edi, [rbp-12]` MUST NOT be recorded as a spill of edi.
    /// Operand direction matters — only `mov [mem], reg` (memory
    /// dest, register source) is a spill.
    #[test]
    fn scan_param_spill_order_rejects_reload_pattern() {
        let rbp = gpr(5, 64);
        let edi = gpr(7, 32);
        let cfg = single_block_cfg(vec![(
            "mov",
            Operation::Move,
            // Reload: operand[0] = reg (dst), operand[1] = mem (src).
            vec![Operand::Register(edi), mem(rbp, -12)],
        )]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert!(
            order.is_empty(),
            "reload `mov reg, [mem]` must not be recorded as a spill, got {order:?}"
        );
    }

    /// Codex review on PR #27 pass 1: the scanner stops at the
    /// first non-prologue body instruction so later body stores
    /// don't pollute the spill observations. Verify a body
    /// `mov [rbp-20], esi` AFTER a non-prologue instruction
    /// (`xor eax, eax` followed by `mov [rbp-20], esi`) isn't
    /// captured. The non-prologue instruction breaks the scan.
    #[test]
    fn scan_param_spill_order_stops_at_first_body_instruction() {
        let rbp = gpr(5, 64);
        let edi = gpr(7, 32);
        let esi = gpr(6, 32);
        let eax = gpr(0, 32);
        let cfg = single_block_cfg(vec![
            // Real prologue spill.
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -8), Operand::Register(edi)],
            ),
            // Body instruction — breaks the scan.
            (
                "xor",
                Operation::Xor,
                vec![Operand::Register(eax), Operand::Register(eax)],
            ),
            // Body store — must NOT be picked up.
            (
                "mov",
                Operation::Move,
                vec![mem(rbp, -20), Operand::Register(esi)],
            ),
        ]);
        let order = scan_param_spill_order(&cfg, CallingConvention::SystemV);
        assert_eq!(
            order,
            vec![ParamSpillObservation {
                register: "edi".to_string(),
                offset: -8,
            }],
            "scan must stop at first non-prologue instruction"
        );
    }

    #[test]
    fn scan_detects_single_precision_size() {
        // movss %xmm0,[rbp-4]  -> float (4 bytes)
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![(
            "movss",
            Operation::Store,
            vec![mem(rbp, -4), Operand::Register(xmm(0))],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert_eq!(found, vec![(0, "xmm0".to_string(), 4)]);
    }

    #[test]
    fn scan_requires_contiguous_prefix() {
        // Only xmm1 used as a source (xmm0 untouched): no contiguous prefix.
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![(
            "movsd",
            Operation::Store,
            vec![mem(rbp, -8), Operand::Register(xmm(1))],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert!(found.is_empty(), "non-prefix xmm1 must not be an argument");
    }

    #[test]
    fn scan_ignores_written_before_read() {
        // movsd [rbp-8],%xmm0 first writes xmm0, then a later read is not an arg.
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![
            (
                "movsd",
                Operation::Move,
                vec![Operand::Register(xmm(0)), mem(rbp, -8)],
            ),
            (
                "movsd",
                Operation::Store,
                vec![mem(rbp, -16), Operand::Register(xmm(0))],
            ),
        ]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert!(
            found.is_empty(),
            "xmm0 written before read is not an argument"
        );
    }

    #[test]
    fn scan_integer_only_function_has_no_float_args() {
        // mov [rbp-8],%rdi : integer arg spill, no xmm at all.
        let rbp = gpr(5, 64);
        let rdi = gpr(7, 64);
        let cfg = single_block_cfg(vec![(
            "mov",
            Operation::Store,
            vec![mem(rbp, -8), Operand::Register(rdi)],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert!(found.is_empty());
    }

    /// aarch64: `STR Dn, [sp, #imm]` is the -O0 float-arg spill. The
    /// source register is operand[0] (opposite of x86 movsd which has
    /// memory first). Without the position-agnostic Store handling,
    /// the scanner would mark the float-bank register as written-
    /// before-read and miss the arg.
    #[test]
    fn aarch64_scan_detects_d0_d1_args_from_str_spill() {
        // str d0, [sp, #8]   ; str d1, [sp, #16]
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![
            (
                "str",
                Operation::Store,
                vec![Operand::Register(aarch64_v(0, 64)), aarch64_mem(sp, 8)],
            ),
            (
                "str",
                Operation::Store,
                vec![Operand::Register(aarch64_v(1, 64)), aarch64_mem(sp, 16)],
            ),
        ]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            found,
            vec![(0, "d0".to_string(), 8), (1, "d1".to_string(), 8)]
        );
    }

    /// `STR Sn, [sp, #imm]` is the single-precision spill: width is
    /// taken from the `s*` register prefix, NOT from a mnemonic
    /// suffix (aarch64 has no `*ss`/`*sd` form).
    #[test]
    fn aarch64_scan_picks_single_precision_size_from_register() {
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 32)), aarch64_mem(sp, 4)],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(found, vec![(0, "d0".to_string(), 4)]);
    }

    /// Codex review on PR #25: aarch64 `stp d0, d1, [sp, #-16]!` is a
    /// store-pair carrying two source register operands plus the
    /// memory destination. The scanner has to count BOTH registers,
    /// not just operand[0], otherwise float-arity recovery undercounts
    /// for functions whose prologue spills the args as a pair.
    #[test]
    fn aarch64_scan_detects_both_args_in_stp_spill() {
        // stp d0, d1, [sp, #-16]!
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "stp",
            Operation::Store,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
                aarch64_mem(sp, -16),
            ],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            found,
            vec![(0, "d0".to_string(), 8), (1, "d1".to_string(), 8)]
        );
    }

    /// Codex review on PR #25: aarch64 FP instructions use a 3-operand
    /// `dst, src1, src2` form (`fadd d0, d0, d1`). The scanner has to
    /// look at every source operand past operand[0], not just
    /// operand[1], otherwise a function whose body uses both args
    /// directly (no spill at all — an optimised build) is reported
    /// as taking only `d0`. The Xor self-zero idiom shortcut still
    /// fires before this loop so `pxor xmm,xmm` doesn't accidentally
    /// flag arg reads.
    #[test]
    fn aarch64_scan_detects_d1_in_fadd_third_operand() {
        // fadd d0, d0, d1
        let cfg = aarch64_single_block_cfg(vec![(
            "fadd",
            Operation::Add,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
            ],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            found,
            vec![(0, "d0".to_string(), 8), (1, "d1".to_string(), 8)],
            "fadd d0, d0, d1 must register both arg reads"
        );
    }

    /// Codex review on PR #25 pass 4: aarch64 `fcmp d0, d1` carries
    /// `d0` as operand[0] but `Operation::Compare` doesn't write a
    /// destination — it sets flags. Without skipping Compare/Test in
    /// the return classifier, a void function that just compares its
    /// FP args would seed a `double` return type.
    #[test]
    fn aarch64_return_scan_ignores_fcmp_compare() {
        // fcmp d0, d1   ; ret
        let cfg = aarch64_single_block_cfg(vec![(
            "fcmp",
            Operation::Compare,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
            ],
        )]);
        let result = scan_float_return(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            result, None,
            "fcmp d0, d1 must not seed a float return (Compare doesn't write)"
        );
    }

    /// Codex review on PR #25: a leaf function that takes a float
    /// arg and returns void (or an integer through `x0`/`w0`) has
    /// `str d0, [sp, #...]` as its arg spill at the top of the entry
    /// block. If that entry block is also the return block (the
    /// common single-block leaf case), the return-classifier
    /// scanning backwards would otherwise see `d0` at operand[0] of
    /// the STR and mistakenly classify the function as returning
    /// `double`. `Operation::Store` must be skipped by the return
    /// classifier.
    #[test]
    fn aarch64_return_scan_ignores_str_d0_arg_spill() {
        // Body:
        //   str d0, [sp, #8]    ; spill incoming float arg
        //   ret
        // No write to d0 as a destination; this is a void function
        // (or one whose integer return is elsewhere). `scan_float_return`
        // must return None.
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 64)), aarch64_mem(sp, 8)],
        )]);
        let result = scan_float_return(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            result, None,
            "aarch64 STR d0 (arg spill) must not seed a float return"
        );
    }

    /// Codex review on PR #25 pass 7: `ldp d0, d1, [sp, #N]` on
    /// aarch64 LOADS d0 and d1 from memory — both register operands
    /// are destinations, not sources. The arg scan must mark both
    /// as written rather than treating operand[1] as a source read,
    /// otherwise a function that loads two doubles from a local
    /// would be reported as accepting `d1` as a 2nd float argument.
    #[test]
    fn aarch64_scan_does_not_treat_ldp_dest_as_arg_read() {
        // ldp d0, d1, [sp, #16]   ; load two locals into d0/d1
        // No prior write to d0 or d1, but they're both destinations
        // here. Expected: NO detected float arguments.
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "ldp",
            Operation::Load,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
                aarch64_mem(sp, 16),
            ],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert!(
            found.is_empty(),
            "ldp destinations must not be flagged as float arg reads, got {found:?}"
        );
    }

    /// Codex review on PR #25 pass 7: x86 `movd r32, xmm0` /
    /// `vmovd r32, xmm0` is classified as `Operation::Store` even
    /// though operand[0] is the integer destination register. The
    /// pass-2 store-skip in the return classifier was too broad and
    /// would let the classifier walk back past the integer return
    /// write to an earlier xmm0 write, falsely classifying an
    /// integer-returning function as returning a float. Restrict the
    /// skip to memory-destination stores so register-only `movd`
    /// returns the integer classification.
    #[test]
    fn return_classifier_movd_eax_xmm0_classifies_as_integer() {
        // movd eax, xmm0     ; integer extraction from SSE bank
        // ret
        let cfg = single_block_cfg(vec![(
            "movd",
            Operation::Store,
            vec![Operand::Register(gpr(0, 32)), Operand::Register(xmm(0))],
        )]);
        let block = cfg.entry_block().unwrap();
        let result = block_return_register_class(block, CallingConvention::SystemV);
        assert_eq!(
            result,
            Some(ReturnRegClass::Integer),
            "movd eax, xmm0 (reg→reg Store) must classify as integer return"
        );
    }

    /// Codex review on PR #25 pass 10: x86 VEX-encoded loads such as
    /// `vmaskmovps xmm2, xmm0, [rdi]` are `Operation::Load` with the
    /// middle operand being a SOURCE (mask), not a destination. The
    /// pass-7 ldp fix that marked every leading register operand of
    /// a Load as written would also mark xmm0 (the incoming arg) as
    /// written before any read, suppressing the arg detection.
    /// Single-destination Loads must only mark operand[0] as written;
    /// operand[1..] before the memory operand are source reads.
    #[test]
    fn scan_detects_vex_load_mask_register_as_arg_read() {
        // vmaskmovps xmm2, xmm0, [rdi]
        // operand[0] = xmm2 (dest)
        // operand[1] = xmm0 (mask source — the incoming float arg)
        // operand[2] = [rdi] (memory source)
        let rdi = gpr(7, 64);
        let cfg = single_block_cfg(vec![(
            "vmaskmovps",
            Operation::Load,
            vec![
                Operand::Register(xmm(2)),
                Operand::Register(xmm(0)),
                mem(rdi, 0),
            ],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert_eq!(
            found,
            vec![(0, "xmm0".to_string(), 8)],
            "vmaskmovps mask (operand[1]) must register as a float arg read"
        );
    }

    /// Codex review on PR #25 pass 9: aarch64 `fcmp d0, d1` carries
    /// d0 in operand[0] as a SOURCE read (Compare doesn't write its
    /// operand[0]). The previous `skip(1)` source-iteration would
    /// miss d0 here, so a function whose only FP use was a compare
    /// against d0 would recover NO float parameters. Verify d0 and
    /// d1 are both detected as 8-byte float args.
    #[test]
    fn aarch64_scan_detects_d0_and_d1_in_fcmp() {
        // fcmp d0, d1
        let cfg = aarch64_single_block_cfg(vec![(
            "fcmp",
            Operation::Compare,
            vec![
                Operand::Register(aarch64_v(0, 64)),
                Operand::Register(aarch64_v(1, 64)),
            ],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(
            found,
            vec![(0, "d0".to_string(), 8), (1, "d1".to_string(), 8)],
            "fcmp d0, d1 must mark BOTH d0 and d1 as arg reads"
        );
    }

    /// Codex review on PR #25 pass 9: x86 `movdqa xmm1, xmm0` (a
    /// reg-to-reg SSE store-form encoding) is classified as
    /// `Operation::Store` even though operand[0] is the destination
    /// register, not a source. Without distinguishing memory-store
    /// from reg-to-reg-store, a function that just copies its
    /// single float arg from xmm0 to xmm1 would be reported as
    /// taking both xmm0 AND xmm1.
    #[test]
    fn scan_does_not_treat_reg_to_reg_store_dest_as_arg_read() {
        // movdqa xmm1, xmm0   ; copy xmm0 → xmm1 (no memory operand)
        let cfg = single_block_cfg(vec![(
            "movdqa",
            Operation::Store,
            vec![Operand::Register(xmm(1)), Operand::Register(xmm(0))],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert_eq!(
            found,
            vec![(0, "xmm0".to_string(), 8)],
            "movdqa xmm1, xmm0 reg-to-reg store: only xmm0 is an arg read"
        );
    }

    /// Codex review on PR #25 pass 5: the aarch64 register renderer
    /// uses `v*` (not `q*`) for the 128-bit SIMD/FP form. The width
    /// helper must size a `v0` operand at 16 bytes; otherwise a
    /// vector arg falls through to mnemonic-based sizing and ends up
    /// recovered as 8-byte `double` instead of 16-byte SIMD.
    #[test]
    fn aarch64_scan_picks_quad_size_from_v_register() {
        // str v0, [sp, #16]   ; 128-bit vector arg spill
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 128)), aarch64_mem(sp, 16)],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert_eq!(found, vec![(0, "d0".to_string(), 16)]);
    }

    /// Codex review on PR #25 pass 12: half-precision `h*` is
    /// deliberately NOT detected as a float arg. The downstream
    /// `float_param_type_for_size(2)` would map it to `Float(32)`
    /// (32-bit `float`), wrongly recovering an `_Float16` signature
    /// as `float`. Until a 16-bit float type lands, the scanner
    /// silently ignores h0 spills so the recovered signature
    /// stays empty rather than mistyped.
    #[test]
    fn aarch64_scan_silently_ignores_half_precision_h_register() {
        // str h0, [sp, #2]   ; spill of _Float16 arg
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "str",
            Operation::Store,
            vec![Operand::Register(aarch64_v(0, 16)), aarch64_mem(sp, 2)],
        )]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::Aarch64);
        assert!(
            found.is_empty(),
            "h0 (half-precision) must not be detected until Float(16) is supported, got {found:?}"
        );
    }

    /// Codex review on PR #25 pass 5: `ldp` isn't always an epilogue
    /// frame restore — `ldp x0, x1, [sp, #N]` immediately before
    /// `ret` is a legitimate return-register load. Globally skipping
    /// `ldp` would miss the integer return write. Only the frame
    /// restore shape (operand[0] == x29) should be skipped.
    #[test]
    fn aarch64_return_classifier_ldp_x0_is_integer_return() {
        // ldp x0, x1, [sp, #16]   ; load return registers
        // ret
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "ldp",
            Operation::Load,
            vec![
                Operand::Register(aarch64_x(0, 64)),
                Operand::Register(aarch64_x(1, 64)),
                aarch64_mem(sp, 16),
            ],
        )]);
        let block = cfg.entry_block().unwrap();
        let result = block_return_register_class(block, CallingConvention::Aarch64);
        assert_eq!(
            result,
            Some(ReturnRegClass::Integer),
            "ldp x0, x1, ... must be classified as an integer return write"
        );
    }

    /// Codex review on PR #25 pass 5 (companion): the frame-restore
    /// shape `ldp x29, x30, [sp, #N]` still has to be skipped — it
    /// isn't a return-register write, just an epilogue restore of
    /// fp/lr. Without the targeted skip, x29 would never match the
    /// return-register set and the classifier would silently keep
    /// walking, but we encode the intent explicitly so a future
    /// refactor of the match arms doesn't surface false positives.
    #[test]
    fn aarch64_return_classifier_ldp_x29_x30_is_skipped() {
        // ldp x29, x30, [sp, #16]   ; epilogue frame restore
        // ret
        let sp = aarch64_x(31, 64);
        let cfg = aarch64_single_block_cfg(vec![(
            "ldp",
            Operation::Load,
            vec![
                Operand::Register(aarch64_x(29, 64)),
                Operand::Register(aarch64_x(30, 64)),
                aarch64_mem(sp, 16),
            ],
        )]);
        let block = cfg.entry_block().unwrap();
        let result = block_return_register_class(block, CallingConvention::Aarch64);
        assert_eq!(
            result, None,
            "ldp x29, x30, ... is a frame restore, not a return write"
        );
    }

    #[test]
    fn scan_excludes_pxor_self_zero() {
        // pxor %xmm0,%xmm0 (zero a float accumulator) must not look like an
        // xmm0 argument read.
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![
            (
                "pxor",
                Operation::Xor,
                vec![Operand::Register(xmm(0)), Operand::Register(xmm(0))],
            ),
            (
                "movsd",
                Operation::Store,
                vec![mem(rbp, -8), Operand::Register(xmm(0))],
            ),
        ]);
        let found = scan_float_arg_registers(&cfg, CallingConvention::SystemV);
        assert!(found.is_empty(), "pxor self-zero is not an argument read");
    }

    /// `%fs:0x28` stack-guard memory operand.
    fn guard_mem() -> Operand {
        use hexray_core::{Architecture, IndexMode, MemoryRef, MemorySpace, RegisterClass};
        let fs = hexray_core::Register::new(
            Architecture::X86_64,
            RegisterClass::Segment,
            hexray_core::register::x86::FS,
            16,
        );
        Operand::Memory(MemoryRef {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x28,
            size: 8,
            segment: Some(fs),
            broadcast: false,
            index_mode: IndexMode::None,
            space: MemorySpace::Generic,
        })
    }

    #[test]
    fn scan_float_return_detects_double_and_single() {
        let rbp = gpr(5, 64);
        let dbl = single_block_cfg(vec![(
            "movsd",
            Operation::Move,
            vec![Operand::Register(xmm(0)), mem(rbp, -8)],
        )]);
        assert_eq!(scan_float_return(&dbl, CallingConvention::SystemV), Some(8));

        let single = single_block_cfg(vec![(
            "movss",
            Operation::Move,
            vec![Operand::Register(xmm(0)), mem(rbp, -4)],
        )]);
        assert_eq!(
            scan_float_return(&single, CallingConvention::SystemV),
            Some(4)
        );
    }

    #[test]
    fn scan_float_return_vetoes_on_integer_return() {
        // The float value lands in xmm0, but the function then converts it to
        // an integer in eax — an integer return.
        let rbp = gpr(5, 64);
        let dbl = single_block_cfg(vec![
            (
                "movsd",
                Operation::Move,
                vec![Operand::Register(xmm(0)), mem(rbp, -8)],
            ),
            (
                "cvttsd2si",
                Operation::Move,
                vec![Operand::Register(gpr(0, 32)), Operand::Register(xmm(0))],
            ),
        ]);
        assert_eq!(scan_float_return(&dbl, CallingConvention::SystemV), None);
    }

    #[test]
    fn scan_float_return_skips_canary_reload() {
        // movsd ...,%xmm0 ; mov ...,%rax ; sub %fs:0x28,%rax ; ret
        // The rax canary reload must not mask the xmm0 float return.
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![
            (
                "movsd",
                Operation::Move,
                vec![Operand::Register(xmm(0)), mem(rbp, -88)],
            ),
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(gpr(0, 64)), mem(rbp, -8)],
            ),
            (
                "sub",
                Operation::Sub,
                vec![Operand::Register(gpr(0, 64)), guard_mem()],
            ),
        ]);
        assert_eq!(scan_float_return(&cfg, CallingConvention::SystemV), Some(8));
    }

    /// Codex review on PR #25 pass 8: the pass-4 fix to skip
    /// Compare/Test ops in the return classifier was too aggressive
    /// — when a stack-protector epilogue uses `cmp` (instead of
    /// `sub`) against the canary, the early skip swallowed the
    /// guard reference before `instruction_references_stack_guard`
    /// got a chance to set saw_guard. The preceding `mov rax,
    /// [canary_slot]` then got mistakenly seeded as the integer
    /// return value, vetoing the real float return in xmm0.
    /// Verify a `cmp %fs:0x28, ...` guard check still sets saw_guard
    /// so the xmm0 float return is preserved.
    #[test]
    fn scan_float_return_skips_canary_reload_when_guard_is_cmp() {
        // movsd ...,%xmm0   ; real float return write
        // mov ...,%rax      ; canary reload from stack slot
        // cmp %fs:0x28,%rax ; guard compare (Operation::Compare)
        // ret
        let rbp = gpr(5, 64);
        let cfg = single_block_cfg(vec![
            (
                "movsd",
                Operation::Move,
                vec![Operand::Register(xmm(0)), mem(rbp, -88)],
            ),
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(gpr(0, 64)), mem(rbp, -8)],
            ),
            (
                "cmp",
                Operation::Compare,
                vec![Operand::Register(gpr(0, 64)), guard_mem()],
            ),
        ]);
        assert_eq!(
            scan_float_return(&cfg, CallingConvention::SystemV),
            Some(8),
            "cmp-form canary guard must not be skipped before guard detection"
        );
    }

    #[test]
    fn test_calling_convention_registers() {
        let sysv = CallingConvention::SystemV;
        assert_eq!(sysv.integer_arg_registers().len(), 6);
        assert_eq!(sysv.float_arg_registers().len(), 8);
        assert_eq!(sysv.integer_return_register(), "rax");

        let win64 = CallingConvention::Win64;
        assert_eq!(win64.integer_arg_registers().len(), 4);
        assert_eq!(win64.float_arg_registers().len(), 4);

        let aarch64 = CallingConvention::Aarch64;
        assert_eq!(aarch64.integer_arg_registers().len(), 8);
        assert_eq!(aarch64.integer_return_register(), "x0");
    }

    #[test]
    fn test_inferred_type_to_c_string() {
        assert_eq!(ParamType::Void.to_c_string(), "void");
        assert_eq!(ParamType::SignedInt(32).to_c_string(), "int32_t");
        assert_eq!(ParamType::SignedInt(64).to_c_string(), "int64_t");
        assert_eq!(ParamType::UnsignedInt(8).to_c_string(), "uint8_t");
        assert_eq!(ParamType::Float(32).to_c_string(), "float");
        assert_eq!(ParamType::Float(64).to_c_string(), "double");
        assert_eq!(ParamType::Float(80).to_c_string(), "long double");
        assert_eq!(ParamType::SimdFloat(32).to_c_string(), "__m256");
        assert_eq!(ParamType::Pointer.to_c_string(), "void*");
        let fp = ParamType::FunctionPointer {
            return_type: Box::new(ParamType::SignedInt(32)),
            params: vec![ParamType::Pointer, ParamType::Pointer],
        };
        assert_eq!(fp.to_c_string(), "int32_t (*)(void*, void*)");
        assert_eq!(fp.format_with_name("cmp"), "int32_t (*cmp)(void*, void*)");
    }

    #[test]
    fn test_signature_to_c_declaration() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.has_return = true;
        sig.return_type = ParamType::SignedInt(32);
        sig.parameters.push(Parameter::new(
            "arg0",
            ParamType::SignedInt(64),
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(Parameter::new(
            "arg1",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let decl = sig.to_c_declaration("my_function");
        assert!(decl.contains("int32_t"));
        assert!(decl.contains("my_function"));
        assert!(decl.contains("int64_t arg0"));
        assert!(decl.contains("void* arg1"));
    }

    #[test]
    fn test_signature_void_function() {
        let sig = FunctionSignature::new(CallingConvention::SystemV);
        let decl = sig.to_c_declaration("void_func");
        assert!(decl.starts_with("void"));
        assert!(decl.contains("void_func(void)"));
    }

    #[test]
    fn test_signature_variadic() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.has_return = true;
        sig.return_type = ParamType::SignedInt(32);
        sig.is_variadic = true;
        sig.parameters.push(Parameter::new(
            "fmt",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));

        let decl = sig.to_c_declaration("printf_like");
        assert!(decl.contains("..."));
    }

    #[test]
    fn test_reg_size_from_name() {
        let recovery = SignatureRecovery::new(CallingConvention::SystemV);

        // x86-64
        assert_eq!(recovery.reg_size_from_name("rax"), 8);
        assert_eq!(recovery.reg_size_from_name("eax"), 4);
        assert_eq!(recovery.reg_size_from_name("rdi"), 8);
        assert_eq!(recovery.reg_size_from_name("edi"), 4);
        assert_eq!(recovery.reg_size_from_name("r8"), 8);
        assert_eq!(recovery.reg_size_from_name("r8d"), 4);
    }

    #[test]
    fn test_aarch64_reg_size_from_name() {
        let recovery = SignatureRecovery::new(CallingConvention::Aarch64);

        // ARM64
        assert_eq!(recovery.reg_size_from_name("x0"), 8);
        assert_eq!(recovery.reg_size_from_name("w0"), 4);
        assert_eq!(recovery.reg_size_from_name("x19"), 8);
        assert_eq!(recovery.reg_size_from_name("w19"), 4);
        assert_eq!(recovery.reg_size_from_name("tmp0"), 0);
    }

    #[test]
    fn test_riscv_reg_size_from_name() {
        let recovery = SignatureRecovery::new(CallingConvention::RiscV);
        assert_eq!(recovery.reg_size_from_name("a0"), 8);
        assert_eq!(recovery.reg_size_from_name("x10"), 8);
        assert_eq!(recovery.reg_size_from_name("s1"), 8);
        assert_eq!(recovery.reg_size_from_name("tmp0"), 0);
    }

    #[test]
    fn test_lifted_slot_index_helpers() {
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_8"), Some(0));
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_10"), Some(1));
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_18"), Some(2));
    }

    #[test]
    fn test_extract_stack_offset_from_array_access() {
        let recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let fp_slot = Expr::array_access(Expr::var(Variable::reg("x29", 8)), Expr::int(-1), 8);
        let sp_slot = Expr::array_access(Expr::var(Variable::reg("sp", 8)), Expr::int(2), 8);
        assert_eq!(recovery.extract_stack_offset(&fp_slot), Some(-8));
        assert_eq!(recovery.extract_stack_offset(&sp_slot), Some(16));
    }

    #[test]
    fn test_convention_from_architecture() {
        assert_eq!(
            CallingConvention::from_architecture("aarch64"),
            CallingConvention::Aarch64
        );
        assert_eq!(
            CallingConvention::from_architecture("arm64"),
            CallingConvention::Aarch64
        );
        assert_eq!(
            CallingConvention::from_architecture("x86_64"),
            CallingConvention::SystemV
        );
        assert_eq!(
            CallingConvention::from_architecture("x86_64-pc-windows-msvc"),
            CallingConvention::Win64
        );
        assert_eq!(
            CallingConvention::from_architecture("riscv64"),
            CallingConvention::RiscV
        );
    }

    #[test]
    fn test_simple_signature_recovery() {
        use hexray_core::BasicBlockId;

        // Create a simple function that uses rdi and rsi
        // Pattern: var_8 = rdi; var_10 = rsi;
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));

        let local_8_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-8));
        let local_10_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-16));

        let local_8 = Expr::deref(local_8_addr, 8);
        let local_10 = Expr::deref(local_10_addr, 8);

        let stmt1 = Expr::assign(local_8, rdi);
        let stmt2 = Expr::assign(local_10, rsi);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt1, stmt2],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // Should detect 2 parameters
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    /// Loading the arg register from a stack slot that is *not* its prologue
    /// spill slot (e.g. the arg register being reused as a scratch temp for a
    /// loop counter) must not rename the parameter after that slot. Doing so
    /// would collide with the slot's own `var_{offset}` local name and turn
    /// every downstream reference to the parameter into the loop counter — the
    /// failure mode behind a whole class of garbled int/float loop output.
    #[test]
    fn test_signature_recovery_does_not_rename_param_after_unrelated_slot_reload() {
        use hexray_core::BasicBlockId;

        // void fn(int*, int): prologue spills rdi → rbp-8, rsi → rbp-12.
        // Body then reloads rdi from a *different* slot (rbp-24, the loop
        // counter's home) — exactly the shape gcc emits when arg0 is reused
        // as the scratch register for `i` inside the loop.
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));

        let slot = |off: i64| -> Expr {
            Expr::deref(
                Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(off as i128)),
                8,
            )
        };

        let spill_rdi = Expr::assign(slot(-8), rdi.clone());
        let spill_rsi = Expr::assign(slot(-12), rsi);
        let body_reload_rdi_from_counter_slot = Expr::assign(rdi.clone(), slot(-24));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![spill_rdi, spill_rsi, body_reload_rdi_from_counter_slot],
                address_range: (0x1000, 0x1018),
            }],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2, "params: {:?}", sig.parameters);
        // arg0's home is rbp-8, so renaming it to "var_8" (its real spill
        // slot) is acceptable; what is NOT acceptable is naming it "var_18"
        // after the unrelated loop-counter slot that just happened to be
        // loaded into rdi later.
        assert_ne!(
            sig.parameters[0].name, "var_18",
            "param 0 was renamed after the loop counter's stack slot — {:?}",
            sig.parameters
        );
        // Sanity: param 1 keeps its default since its register was never
        // reloaded.
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    #[test]
    fn test_signature_recovery_marks_vfprintf_chk_forwarder_variadic() {
        let rsp = Expr::var(Variable::reg("rsp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));
        let rcx = Expr::var(Variable::reg("rcx", 8));
        let r8 = Expr::var(Variable::reg("r8", 8));
        let r9 = Expr::var(Variable::reg("r9", 8));

        let fmt_local = Expr::var(Variable::stack(-0x18, 8));
        let spill_28 = Expr::var(Variable::stack(-0x28, 8));
        let spill_30 = Expr::var(Variable::stack(-0x30, 8));
        let spill_38 = Expr::var(Variable::stack(-0x38, 8));
        let spill_40 = Expr::var(Variable::stack(-0x40, 8));
        let spill_48 = Expr::var(Variable::stack(-0x48, 8));
        let fp_offset = Expr::var(Variable::stack(-0x4, 4));
        let reg_save = Expr::var(Variable::stack(-0x10, 8));
        let overflow = Expr::var(Variable::stack(-0x8, 8));
        let gp_offset = Expr::deref(rsp.clone(), 4);

        let call = Expr::call(
            CallTarget::Named("__vfprintf_chk@GLIBC_2.3.4".to_string()),
            vec![
                Expr::unknown("stdout@@GLIBC_2.2.5"),
                Expr::int(2),
                fmt_local.clone(),
                rsp.clone(),
            ],
        );

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(spill_28, rsi),
                    Expr::assign(spill_30, rdx),
                    Expr::assign(spill_38, rcx),
                    Expr::assign(spill_40, r8),
                    Expr::assign(spill_48, r9),
                    Expr::assign(fmt_local, rdi),
                    Expr::assign(
                        overflow,
                        Expr::binop(BinOpKind::Add, rsp.clone(), Expr::int(224)),
                    ),
                    Expr::assign(gp_offset, Expr::int(8)),
                    Expr::assign(fp_offset, Expr::int(48)),
                    Expr::assign(
                        reg_save,
                        Expr::binop(BinOpKind::Add, rsp.clone(), Expr::int(32)),
                    ),
                    call,
                ],
                address_range: (0x1000, 0x1040),
            }],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.is_variadic);
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].name, "format");
        assert!(matches!(sig.parameters[0].param_type, ParamType::Pointer));
        assert!(sig.to_c_declaration("my_log").contains("..."));
    }

    #[test]
    fn test_signature_recovery_marks_sysv_va_start_user_variadic() {
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));
        let rcx = Expr::var(Variable::reg("rcx", 8));
        let r8 = Expr::var(Variable::reg("r8", 8));
        let r9 = Expr::var(Variable::reg("r9", 8));

        let gp_offset = Expr::var(Variable::stack(-0x10, 4));
        let fp_offset = Expr::var(Variable::stack(-0xc, 4));
        let overflow = Expr::var(Variable::stack(-0x8, 8));
        let reg_save = Expr::var(Variable::stack(-0x18, 8));
        let counter = Expr::var(Variable::stack(-0x20, 4));
        let spill_28 = Expr::var(Variable::stack(-0x28, 8));
        let spill_30 = Expr::var(Variable::stack(-0x30, 8));
        let spill_38 = Expr::var(Variable::stack(-0x38, 8));
        let spill_40 = Expr::var(Variable::stack(-0x40, 8));
        let spill_48 = Expr::var(Variable::stack(-0x48, 8));
        let sum = Expr::var(Variable::stack(-0x58, 4));

        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Block {
                    id: BasicBlockId::new(0),
                    statements: vec![
                        Expr::assign(spill_28, rsi),
                        Expr::assign(spill_30, rdx),
                        Expr::assign(spill_38, rcx),
                        Expr::assign(spill_40, r8),
                        Expr::assign(spill_48, r9),
                        Expr::assign(counter.clone(), Expr::int(0)),
                        Expr::assign(sum.clone(), Expr::int(0)),
                        Expr::assign(gp_offset.clone(), Expr::int(8)),
                        Expr::assign(fp_offset, Expr::int(48)),
                        Expr::assign(
                            overflow,
                            Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                        ),
                        Expr::assign(
                            reg_save.clone(),
                            Expr::binop(BinOpKind::Sub, rbp.clone(), Expr::int(176)),
                        ),
                    ],
                    address_range: (0x1000, 0x1030),
                },
                StructuredNode::While {
                    condition: Expr::binop(BinOpKind::Lt, counter.clone(), rdi),
                    body: vec![StructuredNode::Block {
                        id: BasicBlockId::new(1),
                        statements: vec![
                            Expr::assign(
                                sum.clone(),
                                Expr::binop(
                                    BinOpKind::Add,
                                    sum.clone(),
                                    Expr::deref(
                                        Expr::binop(BinOpKind::Add, reg_save, gp_offset.clone()),
                                        4,
                                    ),
                                ),
                            ),
                            Expr {
                                kind: ExprKind::CompoundAssign {
                                    op: BinOpKind::Add,
                                    lhs: Box::new(gp_offset),
                                    rhs: Box::new(Expr::int(8)),
                                },
                            },
                            Expr {
                                kind: ExprKind::CompoundAssign {
                                    op: BinOpKind::Add,
                                    lhs: Box::new(counter),
                                    rhs: Box::new(Expr::int(1)),
                                },
                            },
                        ],
                        address_range: (0x1030, 0x1060),
                    }],
                    header: Some(BasicBlockId::new(1)),
                    exit_block: Some(BasicBlockId::new(2)),
                },
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.is_variadic);
        assert_eq!(sig.parameters.len(), 1);
        assert!(sig.to_c_declaration("my_sum").contains("..."));
    }

    #[test]
    fn test_sysv_va_list_named_float_count_from_fp_offset() {
        // fp_offset = 48 + 16 * named_floats.
        assert_eq!(
            SignatureRecovery::sysv_va_list_named_float_count_from_fp_offset(48),
            Some(0)
        );
        assert_eq!(
            SignatureRecovery::sysv_va_list_named_float_count_from_fp_offset(64),
            Some(1)
        );
        assert_eq!(
            SignatureRecovery::sysv_va_list_named_float_count_from_fp_offset(176),
            Some(8)
        );
        // Out of range / unaligned -> not an fp_offset initialiser.
        assert_eq!(
            SignatureRecovery::sysv_va_list_named_float_count_from_fp_offset(40),
            None
        );
        assert_eq!(
            SignatureRecovery::sysv_va_list_named_float_count_from_fp_offset(56),
            None
        );
    }

    /// A `va_start` `fp_offset` of 48 means zero named float params, so a float
    /// arg register observed in the body is the variadic FP register-save area,
    /// NOT a parameter (`int sum_ints(int n, ...)` must not surface
    /// `double farg0`). An `fp_offset` of 64 means one named float, kept
    /// (`double scaled(double factor, int n, ...)`).
    #[test]
    fn test_variadic_suppresses_unnamed_float_register_save_area() {
        let build = |fp_offset_value: i128| -> FunctionSignature {
            let rbp = Expr::var(Variable::reg("rbp", 8));
            let rdi = Expr::var(Variable::reg("rdi", 8));
            let xmm0 = Expr::var(Variable::reg("xmm0", 8));
            // __va_list_tag layout: gp_offset@b, fp_offset@b+4,
            // overflow_arg_area@b+8, reg_save_area@b+16 (b = -0x18).
            let gp_offset = Expr::var(Variable::stack(-0x18, 4));
            let fp_offset = Expr::var(Variable::stack(-0x14, 4));
            let overflow = Expr::var(Variable::stack(-0x10, 8));
            let reg_save = Expr::var(Variable::stack(-0x8, 8));
            let sum = Expr::var(Variable::stack(-0x58, 8));

            let cfg = StructuredCfg {
                body: vec![StructuredNode::Block {
                    id: BasicBlockId::new(0),
                    statements: vec![
                        // va_list materialization: gp_offset=8 (1 named int),
                        // fp_offset = 48 + 16*named_floats, two pointer slots.
                        Expr::assign(gp_offset, Expr::int(8)),
                        Expr::assign(fp_offset, Expr::int(fp_offset_value)),
                        Expr::assign(
                            overflow,
                            Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                        ),
                        Expr::assign(
                            reg_save,
                            Expr::binop(BinOpKind::Sub, rbp.clone(), Expr::int(176)),
                        ),
                        // Body references the named int (rdi) and a float reg
                        // (xmm0) — so xmm0 would surface as `farg0` unless it is
                        // recognized as the FP register-save area.
                        Expr::assign(sum, Expr::binop(BinOpKind::Add, xmm0, rdi)),
                    ],
                    address_range: (0x1000, 0x1030),
                }],
                cfg_entry: BasicBlockId::new(0),
            };
            let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
            recovery.analyze(&cfg)
        };

        // fp_offset = 48 -> zero named floats -> no float parameters.
        let sig0 = build(48);
        assert!(sig0.is_variadic, "fp=48 case should be variadic");
        assert!(
            !sig0
                .parameters
                .iter()
                .any(|p| matches!(p.param_type, ParamType::Float(_))),
            "fp_offset=48 must suppress the FP register-save area, got: {}",
            sig0.to_c_declaration("sum_ints")
        );

        // fp_offset = 64 -> one named float -> `double farg0` retained.
        let sig1 = build(64);
        assert!(sig1.is_variadic, "fp=64 case should be variadic");
        assert!(
            sig1.parameters
                .iter()
                .any(|p| matches!(p.param_type, ParamType::Float(_))),
            "fp_offset=64 must keep the one named float param, got: {}",
            sig1.to_c_declaration("scaled")
        );
    }

    /// Codex P2 on PR #46: an unrelated stack local initialized to a value in
    /// 48..=176 must NOT be mistaken for the `fp_offset` field. Only the slot
    /// 4 bytes after the `gp_offset` field is the real `fp_offset`; here the
    /// real one is 48 (zero named floats) and a decoy local is 64, so the
    /// FP register-save area must still be suppressed.
    #[test]
    fn test_variadic_float_count_ignores_unrelated_stack_constant() {
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let xmm0 = Expr::var(Variable::reg("xmm0", 8));
        // Real __va_list_tag at base -0x18: gp@-0x18, fp@-0x14, overflow@-0x10,
        // reg_save@-0x8. A decoy adjacent gp/fp-looking pair (8 then 64) sits
        // at -0x60/-0x5c with NO pointer fields — it must be rejected.
        let gp_offset = Expr::var(Variable::stack(-0x18, 4));
        let fp_offset = Expr::var(Variable::stack(-0x14, 4));
        let decoy_gp = Expr::var(Variable::stack(-0x60, 4)); // looks like gp_offset = 8
        let decoy_fp = Expr::var(Variable::stack(-0x5c, 4)); // looks like fp_offset = 64
        let overflow = Expr::var(Variable::stack(-0x10, 8));
        let reg_save = Expr::var(Variable::stack(-0x8, 8));
        let sum = Expr::var(Variable::stack(-0x58, 8));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(decoy_gp, Expr::int(8)), // poison attempt: gp/fp pair
                    Expr::assign(decoy_fp, Expr::int(64)), // ...but no pointer fields
                    Expr::assign(gp_offset, Expr::int(8)),
                    Expr::assign(fp_offset, Expr::int(48)), // real fp_offset: 0 named floats
                    Expr::assign(
                        overflow,
                        Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                    ),
                    Expr::assign(
                        reg_save,
                        Expr::binop(BinOpKind::Sub, rbp.clone(), Expr::int(176)),
                    ),
                    Expr::assign(sum, Expr::binop(BinOpKind::Add, xmm0, rdi)),
                ],
                address_range: (0x1000, 0x1030),
            }],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        assert!(sig.is_variadic);
        assert!(
            !sig.parameters
                .iter()
                .any(|p| matches!(p.param_type, ParamType::Float(_))),
            "decoy constant 64 must not reintroduce a float param, got: {}",
            sig.to_c_declaration("sum_ints")
        );
    }

    /// Codex P2 on PR #46: the `fp_offset` field is mutated at runtime — a
    /// `va_arg(ap, double)` increments it (48 -> 64 -> ...). The recovered
    /// named-float count must come from the `va_start` initializer (the FIRST
    /// store), not a later `va_arg` state update, so `int sum(int n, ...)` that
    /// merely *consumes* a double vararg still suppresses `farg0`.
    #[test]
    fn test_variadic_float_count_uses_va_start_init_not_later_va_arg_update() {
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let xmm0 = Expr::var(Variable::reg("xmm0", 8));
        let gp_offset = Expr::var(Variable::stack(-0x18, 4));
        let fp_offset = Expr::var(Variable::stack(-0x14, 4));
        let fp_offset_again = Expr::var(Variable::stack(-0x14, 4)); // same slot
        let overflow = Expr::var(Variable::stack(-0x10, 8));
        let reg_save = Expr::var(Variable::stack(-0x8, 8));
        let sum = Expr::var(Variable::stack(-0x58, 8));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(gp_offset, Expr::int(8)),
                    Expr::assign(fp_offset, Expr::int(48)), // va_start init: 0 named floats
                    Expr::assign(
                        overflow,
                        Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                    ),
                    Expr::assign(
                        reg_save,
                        Expr::binop(BinOpKind::Sub, rbp.clone(), Expr::int(176)),
                    ),
                    Expr::assign(sum, Expr::binop(BinOpKind::Add, xmm0, rdi)),
                    // Later va_arg(double) bumps the SAME fp_offset slot to 64.
                    Expr::assign(fp_offset_again, Expr::int(64)),
                ],
                address_range: (0x1000, 0x1030),
            }],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        assert!(sig.is_variadic);
        assert!(
            !sig.parameters
                .iter()
                .any(|p| matches!(p.param_type, ParamType::Float(_))),
            "later fp_offset=64 update must not be read as a named float, got: {}",
            sig.to_c_declaration("sum")
        );
    }

    #[test]
    fn scan_sysv_va_list_named_float_count_reads_fp_offset_from_prologue() {
        use hexray_core::MemoryRef;
        let store_imm = |disp: i64, val: i128| {
            (
                "mov",
                Operation::Move,
                vec![
                    Operand::Memory(MemoryRef::base_disp(gpr(5, 64), disp, 4)), // [rbp+disp]
                    Operand::imm(val, 32),
                ],
            )
        };
        // Pointer-field stores (`overflow_arg_area` / `reg_save_area`): a
        // register written into the slot.
        let store_ptr = |disp: i64| {
            (
                "mov",
                Operation::Move,
                vec![
                    Operand::Memory(MemoryRef::base_disp(gpr(5, 64), disp, 8)),
                    Operand::Register(gpr(0, 64)), // rax
                ],
            )
        };
        // Full __va_list_tag at base -208: gp@-208, fp@-204, ptr@-200, ptr@-192.
        let tag = |fp: i128| {
            single_block_cfg(vec![
                store_imm(-208, 8),
                store_imm(-204, fp),
                store_ptr(-200),
                store_ptr(-192),
            ])
        };
        // fp_offset = 48 -> 0 named floats.
        assert_eq!(
            scan_sysv_va_list_named_float_count(&tag(48), CallingConvention::SystemV),
            Some(0)
        );
        // fp_offset = 80 -> (80-48)/16 = 2 named floats.
        assert_eq!(
            scan_sysv_va_list_named_float_count(&tag(80), CallingConvention::SystemV),
            Some(2)
        );
        // Decoy: gp/fp constants present but NO pointer fields at +8/+16.
        let decoy = single_block_cfg(vec![store_imm(-208, 8), store_imm(-204, 48)]);
        assert_eq!(
            scan_sysv_va_list_named_float_count(&decoy, CallingConvention::SystemV),
            None
        );
        // A gp_offset value with no fp_offset 4 bytes later isn't a tag.
        let no_fp = single_block_cfg(vec![
            store_imm(-208, 8),
            store_imm(-100, 48),
            store_ptr(-200),
            store_ptr(-192),
        ]);
        assert_eq!(
            scan_sysv_va_list_named_float_count(&no_fp, CallingConvention::SystemV),
            None
        );
        // Non-SysV target: declined.
        assert_eq!(
            scan_sysv_va_list_named_float_count(&tag(48), CallingConvention::Win64),
            None
        );
    }

    #[test]
    fn scan_aapcs_va_list_recovers_named_gp_and_fp_counts() {
        let sp = || aarch64_x(31, 64);
        let x0 = || aarch64_x(0, 64);
        let w0 = || aarch64_x(0, 32);
        let add_frame = |imm: i128| {
            (
                "add",
                Operation::Add,
                vec![
                    Operand::Register(x0()),
                    Operand::Register(sp()),
                    Operand::imm(imm, 64),
                ],
            )
        };
        let str_x0 = |slot: i64| {
            (
                "str",
                Operation::Store,
                vec![Operand::Register(x0()), aarch64_mem(sp(), slot)],
            )
        };
        let str_w0 = |slot: i64| {
            (
                "str",
                Operation::Store,
                vec![Operand::Register(w0()), aarch64_mem(sp(), slot)],
            )
        };
        // `movn w0, #k` loads `!k`; e.g. `__gr_offs = -56` is `movn w0, #55`.
        let movn_w0 = |k: i128| {
            (
                "movn",
                Operation::Move,
                vec![Operand::Register(w0()), Operand::imm(k, 32)],
            )
        };
        // __va_list tag at base 24: __stack@24, __gr_top@32, __vr_top@40,
        // __gr_offs@48, __vr_offs@52.
        let tag = |gr_k: i128, vr_k: i128| {
            aarch64_single_block_cfg(vec![
                add_frame(0x110),
                str_x0(24),
                add_frame(0x110),
                str_x0(32),
                add_frame(0xd0),
                str_x0(40),
                movn_w0(gr_k),
                str_w0(48),
                movn_w0(vr_k),
                str_w0(52),
            ])
        };
        // movn #55 -> gr_offs=-56 -> named_gp=1; movn #127 -> vr_offs=-128 -> 0.
        assert_eq!(scan_aapcs_va_list(&tag(55, 127)), Some((1, 0)));
        // 2 named GP, 1 named FP: gr_offs=-48 (movn #47), vr_offs=-112 (movn #111).
        assert_eq!(scan_aapcs_va_list(&tag(47, 111)), Some((2, 1)));
        // Missing the pointer fields -> not a tag.
        let no_ptrs =
            aarch64_single_block_cfg(vec![movn_w0(55), str_w0(48), movn_w0(127), str_w0(52)]);
        assert_eq!(scan_aapcs_va_list(&no_ptrs), None);
    }

    #[test]
    fn scan_aapcs_va_list_declines_compact_vr_offs_zero() {
        // gcc -O2 writes __vr_offs = 0 (`stp …, wzr`) for a compacted FP save
        // area when no FP varargs are consumed. That is the canonical value for
        // 8 named floats; deriving the count from it would fabricate parameters,
        // so the full tag must be declined (codex P1 on PR #49).
        let sp = || aarch64_x(31, 64);
        let x = aarch64_x;
        let add_sp = |dst: u16, imm: i128| {
            (
                "add",
                Operation::Add,
                vec![
                    Operand::Register(x(dst, 64)),
                    Operand::Register(sp()),
                    Operand::imm(imm, 64),
                ],
            )
        };
        let str_reg = |reg: u16, bits: u16, slot: i64| {
            (
                "str",
                Operation::Store,
                vec![Operand::Register(x(reg, bits)), aarch64_mem(sp(), slot)],
            )
        };
        let stp = |r1: u16, r2: u16, slot: i64| {
            (
                "stp",
                Operation::Store,
                vec![
                    Operand::Register(x(r1, 64)),
                    Operand::Register(x(r2, 64)),
                    aarch64_mem(sp(), slot),
                ],
            )
        };
        let movn = |reg: u16, k: i128| {
            (
                "movn",
                Operation::Move,
                vec![Operand::Register(x(reg, 32)), Operand::imm(k, 32)],
            )
        };
        let mov0 = |reg: u16| {
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(x(reg, 32)), Operand::imm(0, 32)],
            )
        };
        // Full tag shape but __vr_offs = 0 (compact). Must decline.
        let cfg = aarch64_single_block_cfg(vec![
            add_sp(8, 0x110),
            add_sp(9, 0x110),
            stp(8, 9, 24),
            add_sp(10, 0xd0),
            str_reg(10, 64, 40),
            movn(0, 55), // __gr_offs = -56 (named_gp = 1)
            str_reg(0, 32, 48),
            mov0(0), // __vr_offs = 0 (compact sentinel)
            str_reg(0, 32, 52),
        ]);
        assert_eq!(scan_aapcs_va_list(&cfg), None);
    }

    #[test]
    fn scan_aapcs_va_list_handles_chained_adds_and_stp_pairs() {
        let sp = || aarch64_x(31, 64);
        let x = aarch64_x;
        let add = |dst: u16, base: u16, imm: i128| {
            (
                "add",
                Operation::Add,
                vec![
                    Operand::Register(x(dst, 64)),
                    Operand::Register(x(base, 64)),
                    Operand::imm(imm, 64),
                ],
            )
        };
        let add_sp = |dst: u16, imm: i128| {
            (
                "add",
                Operation::Add,
                vec![
                    Operand::Register(x(dst, 64)),
                    Operand::Register(sp()),
                    Operand::imm(imm, 64),
                ],
            )
        };
        let str_reg = |reg: u16, bits: u16, slot: i64| {
            (
                "str",
                Operation::Store,
                vec![Operand::Register(x(reg, bits)), aarch64_mem(sp(), slot)],
            )
        };
        let stp = |r1: u16, r2: u16, slot: i64| {
            (
                "stp",
                Operation::Store,
                vec![
                    Operand::Register(x(r1, 64)),
                    Operand::Register(x(r2, 64)),
                    aarch64_mem(sp(), slot),
                ],
            )
        };
        let movn = |reg: u16, k: i128| {
            (
                "movn",
                Operation::Move,
                vec![Operand::Register(x(reg, 32)), Operand::imm(k, 32)],
            )
        };
        // __stack@24 + __gr_top@32 written by one STP of two frame pointers;
        // __vr_top@40 via a chained `add x10, sp, #..; add x10, x10, #..`.
        let cfg = aarch64_single_block_cfg(vec![
            add_sp(8, 0x110),
            add_sp(9, 0x110),
            stp(8, 9, 24),
            add_sp(10, 0x80),
            add(10, 10, 0x50),
            str_reg(10, 64, 40),
            movn(0, 55),
            str_reg(0, 32, 48),
            movn(0, 127),
            str_reg(0, 32, 52),
        ]);
        assert_eq!(scan_aapcs_va_list(&cfg), Some((1, 0)));

        // The two 32-bit offset fields written by one `stp w0, w1, [sp, #48]`:
        // w0 at 48 (__gr_offs), w1 at 48+4=52 (__vr_offs).
        let stp_w = |r1: u16, r2: u16, slot: i64| {
            (
                "stp",
                Operation::Store,
                vec![
                    Operand::Register(aarch64_x(r1, 32)),
                    Operand::Register(aarch64_x(r2, 32)),
                    aarch64_mem(sp(), slot),
                ],
            )
        };
        let cfg2 = aarch64_single_block_cfg(vec![
            add_sp(8, 0x110),
            add_sp(9, 0x110),
            stp(8, 9, 24), // __stack@24, __gr_top@32
            add_sp(10, 0xd0),
            str_reg(10, 64, 40), // __vr_top@40
            movn(0, 55),         // w0 = __gr_offs = -56
            movn(1, 127),        // w1 = __vr_offs = -128
            stp_w(0, 1, 48),     // 32-bit pair: w0@48, w1@52
        ]);
        assert_eq!(scan_aapcs_va_list(&cfg2), Some((1, 0)));

        // clang -O1/-O2 packs both 32-bit offset fields into one x register
        // with `mov`+`movk` and stores it 64-bit wide.
        let mov = |reg: u16, v: i128| {
            (
                "mov",
                Operation::Move,
                vec![Operand::Register(aarch64_x(reg, 64)), Operand::imm(v, 64)],
            )
        };
        let movk = |reg: u16, k: i128, shift: i128| {
            (
                "movk",
                Operation::Move,
                vec![
                    Operand::Register(aarch64_x(reg, 64)),
                    Operand::imm(k, 32),
                    Operand::imm(shift, 8),
                ],
            )
        };
        // tag base 176: pointers@176/184/192, packed offsets in x11 stored at 200
        // -> __gr_offs@200, __vr_offs@204. mov x11,#-56 then movk #0xff80,lsl#32
        // gives 0xffffff80_ffffffc8 -> gr=-56 (named_gp=1), vr=-128 (named_fp=0).
        let cfg3 = aarch64_single_block_cfg(vec![
            add_sp(8, 0x100),
            add_sp(9, 0x100),
            stp(8, 9, 176), // __stack@176, __gr_top@184
            add_sp(10, 0x80),
            str_reg(10, 64, 192), // __vr_top@192
            mov(11, -56),
            movk(11, 0xff80, 32),
            str_reg(11, 64, 200), // packed -> gr@200, vr@204
        ]);
        assert_eq!(scan_aapcs_va_list(&cfg3), Some((1, 0)));
    }

    #[test]
    fn test_signature_recovery_marks_multi_named_sysv_va_start_user_variadic() {
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));

        let buf = Expr::var(Variable::stack(-0x28, 8));
        let bufsize = Expr::var(Variable::stack(-0x30, 8));
        let format = Expr::var(Variable::stack(-0x38, 8));
        let gp_offset = Expr::var(Variable::stack(-0x10, 4));
        let fp_offset = Expr::var(Variable::stack(-0xc, 4));
        let overflow = Expr::var(Variable::stack(-0x8, 8));
        let reg_save = Expr::var(Variable::stack(-0x18, 8));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(buf, rdi),
                    Expr::assign(bufsize, rsi),
                    Expr::assign(format, rdx),
                    Expr::assign(gp_offset, Expr::int(24)),
                    Expr::assign(fp_offset, Expr::int(48)),
                    Expr::assign(
                        overflow,
                        Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                    ),
                    Expr::assign(reg_save, Expr::binop(BinOpKind::Sub, rbp, Expr::int(176))),
                ],
                address_range: (0x1000, 0x1030),
            }],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.is_variadic);
        assert_eq!(sig.parameters.len(), 3);
        assert!(sig.to_c_declaration("my_snlog").contains("..."));
    }

    #[test]
    fn test_signature_recovery_keeps_unused_named_prefix_from_sysv_gp_offset() {
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let gp_offset = Expr::var(Variable::stack(-0x10, 4));
        let fp_offset = Expr::var(Variable::stack(-0xc, 4));
        let overflow = Expr::var(Variable::stack(-0x8, 8));
        let reg_save = Expr::var(Variable::stack(-0x18, 8));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(gp_offset, Expr::int(8)),
                    Expr::assign(fp_offset, Expr::int(48)),
                    Expr::assign(
                        overflow,
                        Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(16)),
                    ),
                    Expr::assign(reg_save, Expr::binop(BinOpKind::Sub, rbp, Expr::int(176))),
                ],
                address_range: (0x1000, 0x1020),
            }],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.is_variadic);
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert!(sig.to_c_declaration("via_pointer").contains("arg0, ..."));
    }

    #[test]
    fn test_signature_recovery_marks_optimized_sysv_va_start_user_variadic() {
        let rsp = Expr::var(Variable::reg("rsp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));
        let rcx = Expr::var(Variable::reg("rcx", 8));
        let r8 = Expr::var(Variable::reg("r8", 8));
        let r9 = Expr::var(Variable::reg("r9", 8));

        let gp_offset = Expr::deref(rsp.clone(), 4);
        let reg_save = Expr::var(Variable::stack(-0x10, 8));
        let overflow = Expr::var(Variable::stack(-0x8, 8));
        let spill_28 = Expr::var(Variable::stack(-0x28, 8));
        let spill_30 = Expr::var(Variable::stack(-0x30, 8));
        let spill_38 = Expr::var(Variable::stack(-0x38, 8));
        let spill_40 = Expr::var(Variable::stack(-0x40, 8));
        let spill_48 = Expr::var(Variable::stack(-0x48, 8));

        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Block {
                    id: BasicBlockId::new(0),
                    statements: vec![
                        Expr::assign(spill_28, rsi),
                        Expr::assign(spill_30, rdx),
                        Expr::assign(spill_38, rcx),
                        Expr::assign(spill_40, r8),
                        Expr::assign(spill_48, r9),
                        Expr::assign(gp_offset, Expr::int(8)),
                        Expr::assign(
                            overflow,
                            Expr::binop(BinOpKind::Add, rsp.clone(), Expr::int(96)),
                        ),
                        Expr::assign(
                            reg_save,
                            Expr::binop(BinOpKind::Add, rsp.clone(), Expr::int(32)),
                        ),
                    ],
                    address_range: (0x1000, 0x1020),
                },
                StructuredNode::If {
                    condition: Expr::binop(BinOpKind::Gt, rdi, Expr::int(0)),
                    then_body: vec![StructuredNode::Block {
                        id: BasicBlockId::new(1),
                        statements: vec![Expr::assign(
                            Expr::var(Variable::stack(-0x58, 4)),
                            Expr::int(0),
                        )],
                        address_range: (0x1020, 0x1030),
                    }],
                    else_body: None,
                },
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.is_variadic);
        assert_eq!(sig.parameters.len(), 1);
        assert!(sig.to_c_declaration("my_sum").contains("..."));
    }

    #[test]
    fn test_return_value_detection() {
        use hexray_core::BasicBlockId;

        // Function that sets eax before return (32-bit return)
        let eax = Expr::var(Variable::reg("eax", 4));
        let result = Expr::assign(eax, Expr::int(42));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![result],
            address_range: (0x1000, 0x1008),
        };

        let ret_node = StructuredNode::Return(Some(Expr::var(Variable::reg("eax", 4))));

        let cfg = StructuredCfg {
            body: vec![block, ret_node],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        println!("sig = {:?}", sig);

        assert!(sig.has_return);
        // Return type should be detected
        assert!(!matches!(sig.return_type, ParamType::Void));
    }

    #[test]
    fn test_main_signature_forces_int32_return_type() {
        use hexray_core::BasicBlockId;

        let narrow_cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(Expr::int(0)),
                to_size: 1,
                signed: false,
            },
        };
        let set_ret = Expr::assign(Expr::var(Variable::reg("w0", 4)), narrow_cast);
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x1000, 0x1010),
        };
        let ret = StructuredNode::Return(None);
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery =
            SignatureRecovery::new(CallingConvention::Aarch64).with_function_name("_main");
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(matches!(sig.return_type, ParamType::SignedInt(32)));
        assert!(
            sig.return_provenance
                .iter()
                .any(|r| r == "main ABI default return type"),
            "provenance: {:?}",
            sig.return_provenance
        );
    }

    #[test]
    fn test_accumulator_initialized_from_zero_stays_int32_on_return() {
        use hexray_core::BasicBlockId;

        let acc = Expr::var(Variable {
            kind: crate::decompiler::expression::VarKind::Temp(0),
            name: "acc".to_string(),
            size: 1,
        });
        let ptr = Expr::var(Variable::reg("rdi", 8));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(acc.clone(), Expr::int(0)),
                Expr::assign(
                    acc.clone(),
                    Expr::call(
                        CallTarget::Named("max".to_string()),
                        vec![acc.clone(), Expr::deref(ptr, 4)],
                    ),
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let ret = StructuredNode::Return(Some(acc));
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(matches!(sig.return_type, ParamType::SignedInt(32)));
    }

    #[test]
    fn test_arm64_signature() {
        use hexray_core::BasicBlockId;

        // ARM64 function using x0, x1, x2
        let x0 = Expr::var(Variable::reg("x0", 8));
        let x1 = Expr::var(Variable::reg("x1", 8));
        let x2 = Expr::var(Variable::reg("w2", 4)); // 32-bit variant

        // x0 + x1 + x2
        let add1 = Expr::binop(BinOpKind::Add, x0, x1);
        let add2 = Expr::binop(BinOpKind::Add, add1, x2);

        let stmt = Expr::assign(Expr::var(Variable::reg("x3", 8)), add2);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        // Should detect 3 parameters
        assert_eq!(sig.parameters.len(), 3);
        // Third parameter should be 32-bit (from w2)
        assert!(matches!(
            sig.parameters[2].param_type,
            ParamType::SignedInt(32)
        ));
    }

    #[test]
    fn test_alias_dereference_marks_arm64_param_as_pointer() {
        use hexray_core::BasicBlockId;

        // Simulate:
        //   var_18 = x0;
        //   tmp = var_18[0];
        let assign_alias = Expr::assign(Expr::unknown("var_18"), Expr::var(Variable::reg("x0", 8)));
        let base = Expr::var(Variable::reg("var_18", 8));
        let load_indexed = Expr::assign(
            Expr::unknown("tmp"),
            Expr::array_access(base, Expr::int(0), 4),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![assign_alias, load_indexed],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);
        assert!(
            !sig.parameters.is_empty(),
            "expected at least one recovered parameter"
        );
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "expected arg0 to be inferred as pointer or typed pointer, got {:?}",
            sig.parameters[0].param_type
        );
    }

    #[test]
    fn test_lifted_alias_dereference_marks_sysv_param_as_pointer() {
        use hexray_core::BasicBlockId;

        // Simulate lifted form:
        //   var_18 = rdi;
        //   tmp = var_18[rsi];
        let assign_alias =
            Expr::assign(Expr::unknown("var_18"), Expr::var(Variable::reg("rdi", 8)));
        let load_indexed = Expr::assign(
            Expr::unknown("tmp"),
            Expr::array_access(
                Expr::unknown("var_18"),
                Expr::var(Variable::reg("rsi", 8)),
                4,
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![assign_alias, load_indexed],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        assert!(
            !sig.parameters.is_empty(),
            "expected at least one recovered parameter"
        );
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "expected arg0 to be inferred as pointer or typed pointer, got {:?}",
            sig.parameters[0].param_type
        );
    }

    #[test]
    fn test_unknown_lifted_alias_dereference_marks_sysv_param_as_pointer() {
        use hexray_core::BasicBlockId;

        // Simulate heavily lifted form:
        //   var_18 = arg0;
        //   tmp = var_18[arg1];
        let assign_alias = Expr::assign(Expr::unknown("var_18"), Expr::unknown("arg0"));
        let load_indexed = Expr::assign(
            Expr::unknown("tmp"),
            Expr::array_access(Expr::unknown("var_18"), Expr::unknown("arg1"), 4),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![assign_alias, load_indexed],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        assert!(
            !sig.parameters.is_empty(),
            "expected at least one recovered parameter"
        );
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "expected arg0 to be inferred as pointer or typed pointer, got {:?}",
            sig.parameters[0].param_type
        );
    }

    /// SSE gap 1 from `[[project_structurer_ordering_refactor]]`:
    /// at `-O0` saxpy_dot spills `rdi` (xs) and `rsi` (ys) and then
    /// reloads them per iteration to compute `xs[i]` / `ys[i]`. The
    /// structurer's simplifier folds the `rax = *(rbp-16)` reload
    /// After PR #36 the saxpy_dot recovery preserves scratch xmm
    /// reads but the signature still showed phantom `farg1`/`farg2`
    /// params. Root cause: the body has `Var(xmm2) = arr[i]; ... *
    /// Var(xmm2)` AND a stabilized rename to `Unknown("farg2")` in
    /// some positions. The `analyze_expr_reads_with_context` paths
    /// that observe float-arg-named operands must NOT count a read
    /// as a parameter observation when the body has already written
    /// to that name. This test models the post-PR-#36 shape: the
    /// float-arg seed contains only xmm0 (the real `a` parameter),
    /// and the body writes xmm2 then reads xmm0 and xmm2.
    #[test]
    fn test_float_arg_observation_skips_xmm_written_before_read() {
        use hexray_core::BasicBlockId;
        let write_xmm2 = Expr::assign(
            Expr::var(Variable::reg("xmm2", 8)),
            Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 8),
        );
        let use_xmm = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("xmm0", 8)),
                Expr::var(Variable::reg("xmm2", 8)),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![write_xmm2, use_xmm],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        // The prologue scan would have seen `xmm0 = a` (the real
        // float arg) so seed xmm0 only — not xmm2.
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_float_arg_seeds(vec![(0, "xmm0".to_string(), 8)]);
        let sig = recovery.analyze(&cfg);

        let float_param_indices: Vec<usize> = sig
            .parameters
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::FloatRegister { index, .. } => Some(*index),
                _ => None,
            })
            .collect();

        assert!(
            float_param_indices.contains(&0),
            "farg0 should be recovered (it was seeded and read first): {:?}",
            sig.parameters
        );
        assert!(
            !float_param_indices.contains(&2),
            "xmm2 was written before read — must NOT be a float param: {:?}",
            sig.parameters
        );
    }

    /// Same shape but with the structurer's `Unknown("farg2")`
    /// rename — the explicit write-tracking for farg-named Unknown
    /// LHS values must catch this too.
    #[test]
    fn test_float_arg_observation_skips_farg_unknown_written_before_read() {
        use hexray_core::BasicBlockId;
        let write_farg2 = Expr::assign(
            Expr::unknown("farg2"),
            Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 8),
        );
        let use_xmm = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("xmm0", 8)),
                Expr::unknown("farg2"),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![write_farg2, use_xmm],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_float_arg_seeds(vec![(0, "xmm0".to_string(), 8)]);
        let sig = recovery.analyze(&cfg);

        let float_param_indices: Vec<usize> = sig
            .parameters
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::FloatRegister { index, .. } => Some(*index),
                _ => None,
            })
            .collect();

        assert!(
            !float_param_indices.contains(&2),
            "Unknown(farg2) was written before read — must NOT be a float param: {:?}",
            sig.parameters
        );
    }

    /// Codex review on PR #37 pass 1: a write under one spelling
    /// (`Var(xmm2)`) and a read under the other (`Unknown(farg2)`)
    /// must also be paired by the use-before-write filter. The
    /// `canonical_float_arg_register_name` now maps `farg{n}` ↔
    /// `xmm{n}`, AND the explicit Unknown-LHS write records both
    /// spellings, so either direction works.
    #[test]
    fn test_float_arg_observation_mixed_xmm_write_farg_read() {
        use hexray_core::BasicBlockId;
        let write_xmm2 = Expr::assign(
            Expr::var(Variable::reg("xmm2", 8)),
            Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 8),
        );
        // Read uses the Unknown(farg2) spelling.
        let use_farg2 = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("xmm0", 8)),
                Expr::unknown("farg2"),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![write_xmm2, use_farg2],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_float_arg_seeds(vec![(0, "xmm0".to_string(), 8)]);
        let sig = recovery.analyze(&cfg);
        let float_param_indices: Vec<usize> = sig
            .parameters
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::FloatRegister { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert!(
            !float_param_indices.contains(&2),
            "Var(xmm2) write + Unknown(farg2) read must NOT count as a param: {:?}",
            sig.parameters
        );
    }

    /// Companion: write under `Unknown(farg2)` then read under
    /// `Var(xmm2)`.
    #[test]
    fn test_float_arg_observation_mixed_farg_write_xmm_read() {
        use hexray_core::BasicBlockId;
        let write_farg2 = Expr::assign(
            Expr::unknown("farg2"),
            Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 8),
        );
        let use_xmm2 = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("xmm0", 8)),
                Expr::var(Variable::reg("xmm2", 8)),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![write_farg2, use_xmm2],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_float_arg_seeds(vec![(0, "xmm0".to_string(), 8)]);
        let sig = recovery.analyze(&cfg);
        let float_param_indices: Vec<usize> = sig
            .parameters
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::FloatRegister { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert!(
            !float_param_indices.contains(&2),
            "Unknown(farg2) write + Var(xmm2) read must NOT count as a param: {:?}",
            sig.parameters
        );
    }

    /// SSE-double loads land in the float bank — `movsd xmm2,
    /// [arr+i*8]` lifts to `Var(xmm2) = ArrayAccess(arr, i, 8)`.
    /// The Assign handler stashes the float-dest size while
    /// walking the rhs so the ArrayAccess handler picks
    /// `Float(64)` for the base pointer's element type, not the
    /// default `SignedInt(64)`. Without this, `double *xs`
    /// recovers as `int64_t *xs`.
    #[test]
    fn test_sse_double_load_yields_double_pointer_element_type() {
        use hexray_core::BasicBlockId;
        let load_xmm = Expr::assign(
            Expr::var(Variable::reg("xmm2", 8)),
            Expr::array_access(Expr::unknown("rdi"), Expr::unknown("i"), 8),
        );
        // Touch xmm0 once so the integer arg appears in the
        // recovered signature.
        let use_xmm = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::var(Variable::reg("xmm2", 8)),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![load_xmm, use_xmm],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // rdi → arg 0 should be TypedPointer(Float(64)).
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        assert!(
            matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner) if matches!(inner.as_ref(), ParamType::Float(64))
            ),
            "rdi should be `double*` (TypedPointer(Float(64))) — got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #38 pass 6: integer-to-float conversion
    /// (`cvtsi2sd xmm0, [rdi+i*4]`) lifts as
    /// `Var(xmm0) = Cast(ArrayAccess(rdi, i, 4), Float(64))`. The
    /// memory source is INTEGER data; the destination being a
    /// float-bank register is irrelevant. Setting the float-context
    /// flag only when the rhs is a DIRECT ArrayAccess (no Cast
    /// wrap) handles this — rdi stays as `int32_t*` /
    /// `uint32_t*`, not promoted to `float*`.
    #[test]
    fn test_cvtsi2sd_int_to_float_does_not_float_type_source() {
        use hexray_core::BasicBlockId;
        let cvt_load = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr {
                kind: ExprKind::Cast {
                    expr: Box::new(Expr::array_access(
                        Expr::unknown("rdi"),
                        Expr::unknown("i"),
                        4,
                    )),
                    to_size: 8,
                    signed: true,
                },
            },
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![cvt_load],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        assert!(
            !matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(_))
            ),
            "cvtsi2sd source must NOT recover as `float*`/`double*` — got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #38 pass 6: RISC-V `s0`-`s11` are saved
    /// INTEGER registers, but the spelling collides with AArch64
    /// SIMD-FP `s0`-`s31`. Gating the FP-alias detection by
    /// convention prevents a RISC-V `s0 = ArrayAccess(a0, i, 8)`
    /// from promoting `a0` to `double*`.
    #[test]
    fn test_riscv_s_register_not_treated_as_float_bank() {
        use hexray_core::BasicBlockId;
        let load = Expr::assign(
            Expr::var(Variable::reg("s0", 8)),
            Expr::array_access(Expr::unknown("a0"), Expr::unknown("i"), 8),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![load],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::RiscV);
        let sig = recovery.analyze(&cfg);
        // Whatever `a0` recovers as, it MUST NOT be float-typed
        // (the s0 LHS is an integer-saved register in RISC-V,
        // not an FP scalar destination).
        if let Some(a0_param) = sig.parameters.iter().find(|p| {
            matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "a0"
            )
        }) {
            assert!(
                !matches!(
                    &a0_param.param_type,
                    ParamType::TypedPointer(inner)
                        if matches!(inner.as_ref(), ParamType::Float(_))
                ),
                "RISC-V `s0 = a0[i]` must NOT recover a0 as float pointer (s0 is integer-saved), got {:?}",
                a0_param.param_type,
            );
        }
    }

    /// Codex review on PR #38 pass 4: a nested ArrayAccess as the
    /// BASE of an outer SSE-load (`xmm0 = ptrs[i][j]` for a
    /// pointer table) — the inner access loads a pointer, the
    /// outer loads the float through it. The inner base must NOT
    /// be float-typed.
    #[test]
    fn test_nested_array_base_does_not_inherit_float_context() {
        use hexray_core::BasicBlockId;
        // xmm0 = ArrayAccess(ArrayAccess(rdi, i, 8), j, 8)
        let outer_load = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::array_access(
                Expr::array_access(Expr::unknown("rdi"), Expr::unknown("i"), 8),
                Expr::unknown("j"),
                8,
            ),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![outer_load],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        // rdi is the OUTER table base — it holds pointers (or
        // pointer-sized values), NOT raw doubles. Must not be
        // `double*`.
        assert!(
            !matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(_))
            ),
            "nested-base rdi must NOT recover as `double*`/`float*` — got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #38 pass 3: a nested ArrayAccess in the
    /// INDEX subexpression of an outer SSE-load is its own
    /// separate integer load — its base must NOT inherit the
    /// outer float context. For `xmm0 = ArrayAccess(xs,
    /// ArrayAccess(idx, i, 4), 8)`, xs gets `double*` but idx
    /// must stay `int32_t*`.
    #[test]
    fn test_nested_array_index_does_not_inherit_float_context() {
        use hexray_core::BasicBlockId;
        let outer_load = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::array_access(
                Expr::unknown("rdi"),
                Expr::array_access(Expr::unknown("rsi"), Expr::unknown("i"), 4),
                8,
            ),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![outer_load],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        assert!(
            matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(64))
            ),
            "outer base (rdi) should still recover as `double*`, got {:?}",
            rdi_param.param_type
        );

        let rsi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rsi"
            ))
            .expect("rsi parameter recovered");
        assert!(
            !matches!(
                &rsi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(_))
            ),
            "nested-index base (rsi) must NOT inherit float context, got {:?}",
            rsi_param.param_type
        );
    }

    /// Codex review on PR #38 pass 2: `movq xmm0, [rdi]` is a
    /// plain `Deref(rdi)` load (not ArrayAccess) and is an
    /// integer-SIMD operation despite landing in an xmm
    /// destination. The float-context override is scoped to
    /// ArrayAccess patterns (`arr[i]` — the canonical scalar SSE
    /// indexed load); plain Deref keeps the int default.
    #[test]
    fn test_xmm_plain_deref_is_not_float_typed() {
        use hexray_core::BasicBlockId;
        // Var(xmm0, size=8) = Deref(rdi, 8) — the `movq xmm0,
        // [rdi]` shape codex flagged.
        let load = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::deref(Expr::unknown("rdi"), 8),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![load],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        assert!(
            !matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(_))
            ),
            "plain Deref(rdi) into xmm must NOT recover as `double*` / `float*` — got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #38 pass 1: a 16-byte SIMD load
    /// (`movdqa xmm0, [rdi]` or similar integer-SIMD) lifts to a
    /// `Var(xmm0, size=16)` LHS. Must NOT be treated as a scalar
    /// float context — otherwise an `int128_t* p` would be
    /// mis-recovered as `double* p`.
    #[test]
    fn test_simd_wide_load_is_not_float_context() {
        use hexray_core::BasicBlockId;
        // `Var(xmm0)` with size=16 simulates movdqa/vmovdqu.
        let load_simd = Expr::assign(
            Expr::var(Variable::reg("xmm0", 16)),
            Expr::array_access(Expr::unknown("rdi"), Expr::unknown("i"), 8),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![load_simd],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            ))
            .expect("rdi parameter recovered");
        // The element type must NOT be Float — should stay as the
        // int default since the SIMD register width signals an
        // integer-SIMD load, not a scalar SSE one.
        assert!(
            !matches!(
                &rdi_param.param_type,
                ParamType::TypedPointer(inner)
                    if matches!(inner.as_ref(), ParamType::Float(_))
            ),
            "wide-SIMD load must NOT recover rdi as `double*` / `float*` — got {:?}",
            rdi_param.param_type
        );
    }

    /// Float observation across multiple array accesses on different
    /// pointer args — saxpy's body has both `xmm2 = xs[i]` and
    /// `xmm1 = ys[i]`. Both base pointers must recover their float
    /// element type independently.
    #[test]
    fn test_sse_double_loads_on_distinct_pointers_both_get_double_typed() {
        use hexray_core::BasicBlockId;
        let load_xs = Expr::assign(
            Expr::var(Variable::reg("xmm2", 8)),
            Expr::array_access(Expr::unknown("rdi"), Expr::unknown("i"), 8),
        );
        let load_ys = Expr::assign(
            Expr::var(Variable::reg("xmm1", 8)),
            Expr::array_access(Expr::unknown("rsi"), Expr::unknown("i"), 8),
        );
        let use_xmm = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Add,
                Expr::var(Variable::reg("xmm2", 8)),
                Expr::var(Variable::reg("xmm1", 8)),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![load_xs, load_ys, use_xmm],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        for reg in &["rdi", "rsi"] {
            let p = sig
                .parameters
                .iter()
                .find(|p| matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == reg
                ))
                .unwrap_or_else(|| panic!("expected {reg} parameter"));
            assert!(
                matches!(
                    &p.param_type,
                    ParamType::TypedPointer(inner)
                        if matches!(inner.as_ref(), ParamType::Float(64))
                ),
                "{reg} should be `double*`, got {:?}",
                p.param_type
            );
        }
    }

    /// Codex review on PR #37 pass 2: vector-width aliases. A
    /// `ymm2` / `zmm2` write followed by an `xmm2` read must also
    /// be paired by the use-before-write filter.
    /// `record_register_write` now records the canonical `xmm2`
    /// alongside the literal `ymm2`/`zmm2`.
    #[test]
    fn test_float_arg_observation_skips_ymm_written_then_xmm_read() {
        use hexray_core::BasicBlockId;
        // Body: `ymm2 = ...`  then `xmm0 = xmm0 * xmm2`.
        // The xmm2 read must be filtered because ymm2 was written.
        let write_ymm2 = Expr::assign(
            Expr::var(Variable::reg("ymm2", 16)),
            Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 8),
        );
        let use_xmm2 = Expr::assign(
            Expr::var(Variable::reg("xmm0", 8)),
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("xmm0", 8)),
                Expr::var(Variable::reg("xmm2", 8)),
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![write_ymm2, use_xmm2],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_float_arg_seeds(vec![(0, "xmm0".to_string(), 8)]);
        let sig = recovery.analyze(&cfg);
        let float_param_indices: Vec<usize> = sig
            .parameters
            .iter()
            .filter_map(|p| match &p.location {
                ParameterLocation::FloatRegister { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert!(
            !float_param_indices.contains(&2),
            "ymm2 write + xmm2 read must NOT count as a param: {:?}",
            sig.parameters
        );
    }

    /// into the index expression, leaving
    /// `Deref(Add(Deref(stack_-16), Mul(idx, 8)))` — with the
    /// original `rdi` name gone. Without the spill-slot → arg
    /// bridge, the analysis would see only `rbp` at the base and
    /// recover `xs`/`ys` as `int32_t`, not pointers. The prologue
    /// spill scan tells us which arg lived at -16/-24, so we
    /// propagate the deref/array-access hints to those args.
    #[test]
    fn test_saxpy_indexed_spill_reload_recovers_pointer_args() {
        use hexray_core::BasicBlockId;
        // Mimic post-simplification IR for the inner loop of:
        //   double saxpy_dot(double a, double *xs, double *ys, int n)
        //       { for (int i=0; i<n; i++) total += a*xs[i] + ys[i]; }
        //
        // At -O0 clang spills xmm0/rdi/rsi/edx to home slots in
        // source order, then reloads xs/ys per iteration to compute
        // xs[i] / ys[i]. The structurer's copy-prop folds the
        // intermediate `rax = *(rbp-16)` into the indexed deref, so
        // the body shape is:
        //   tmp_xs = *(*(rbp-16) + i*8)
        //   tmp_ys = *(*(rbp-24) + i*8)
        // with i materialized as the stack local `var_2c` (the loop
        // counter slot), not as a register. Without the spill-slot
        // → arg bridge in `analyze_expr_reads_with_context`, xs and
        // ys recover as `int32_t`; with it they recover as pointers.
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        let spill_load = |off: i128| {
            Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(off)), 8)
        };
        let scaled_index = || {
            Expr::binop(
                BinOpKind::Mul,
                Expr::unknown("var_2c"),
                Expr::int(8),
            )
        };
        let xs_i = Expr::deref(
            Expr::binop(BinOpKind::Add, spill_load(16), scaled_index()),
            8,
        );
        let ys_i = Expr::deref(
            Expr::binop(BinOpKind::Add, spill_load(24), scaled_index()),
            8,
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("tmp_xs"), xs_i),
                Expr::assign(Expr::unknown("tmp_ys"), ys_i),
            ],
            address_range: (0x1000, 0x1030),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -16,
                },
                ParamSpillObservation {
                    register: "rsi".to_string(),
                    offset: -24,
                },
                ParamSpillObservation {
                    register: "edx".to_string(),
                    offset: -28,
                },
            ]);
        let sig = recovery.analyze(&cfg);

        // The two int args that get array-indexed must come back as
        // pointers; this is the fix for the saxpy gap. We don't
        // assert anything about additional recovered params (n
        // wasn't read in this body slice and may or may not show
        // up depending on whether the spill scan alone is enough).
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| {
                matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
                )
            })
            .expect("rdi parameter present");
        let rsi_param = sig
            .parameters
            .iter()
            .find(|p| {
                matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == "rsi"
                )
            })
            .expect("rsi parameter present");
        assert!(
            matches!(
                rdi_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "rdi (xs) should be pointer, got {:?} (full sig: {:?})",
            rdi_param.param_type,
            sig.parameters
        );
        assert!(
            matches!(
                rsi_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "rsi (ys) should be pointer, got {:?} (full sig: {:?})",
            rsi_param.param_type,
            sig.parameters
        );
    }

    /// Codex review on PR #32 pass 9: if the spill slot gets
    /// overwritten by a non-spill store later in the body, the
    /// prologue evidence is stale — subsequent loads from that
    /// offset are NOT the original arg, so the bridge must not
    /// propagate. Codex example:
    ///   spill prologue: *(rbp-8) = rdi
    ///   body write:     *(rbp-8) = some_other_pointer
    ///   later use:      tmp = *(*(rbp-8))
    /// `rdi` should NOT become a pointer just because the slot was
    /// later loaded; the slot no longer holds rdi.
    #[test]
    fn test_overwritten_spill_slot_does_not_propagate_to_original_arg() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        // 1. Prologue spill: *(rbp-8) = rdi
        let prologue_spill = Expr::assign(
            Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(8)), 8),
            Expr::var(Variable::reg("rdi", 8)),
        );
        // 2. Body write to same slot from a NON-arg source:
        //    *(rbp-8) = arbitrary value (here, an Unknown).
        let body_write = Expr::assign(
            Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(8)), 8),
            Expr::unknown("other_value"),
        );
        // 3. Later: tmp = *(*(rbp-8))
        let later_load = Expr::assign(
            Expr::unknown("tmp"),
            Expr::deref(
                Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(8)), 8),
                8,
            ),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![prologue_spill, body_write, later_load],
            address_range: (0x1000, 0x1030),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -8,
            }]);
        let sig = recovery.analyze(&cfg);
        if let Some(rdi_param) = sig.parameters.iter().find(|p| {
            matches!(
                &p.location,
                ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
            )
        }) {
            assert!(
                !matches!(
                    rdi_param.param_type,
                    ParamType::Pointer | ParamType::TypedPointer(_)
                ),
                "rdi MUST NOT be typed as pointer after its spill slot was overwritten, got {:?}",
                rdi_param.param_type
            );
        }
    }

    /// Codex review on PR #32 pass 8: if the spilled arg register
    /// is clobbered (written) before its folded spill-reload is
    /// analyzed, the regular `record_usage_hint` resolver discards
    /// the hint because the register isn't "read before written".
    /// But the spill-offset evidence is HARD evidence — the prologue
    /// scan recorded that this slot is the param's home regardless
    /// of subsequent register reuse. The dedicated
    /// `record_hint_for_arg_register` bypass keeps the hint.
    #[test]
    fn test_spilled_pointer_recovers_even_when_register_clobbered_first() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        // Body:
        //   rdi = 0;                ; clobber rdi as a scratch
        //   tmp = *(*(rbp-16) + idx*8)  ; indexed access via spill
        let clobber = Expr::assign(Expr::var(Variable::reg("rdi", 8)), Expr::int(0));
        let xs_reload = Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(16)), 8);
        let scaled = Expr::binop(BinOpKind::Mul, Expr::unknown("var_2c"), Expr::int(8));
        let elem = Expr::deref(
            Expr::binop(BinOpKind::Add, xs_reload, scaled),
            8,
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![clobber, Expr::assign(Expr::unknown("tmp"), elem)],
            address_range: (0x1000, 0x1030),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -16,
            }]);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| {
                matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
                )
            })
            .expect("rdi parameter present");
        assert!(
            matches!(
                rdi_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "spilled pointer should be recovered even after rdi was clobbered, got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #32 pass 7: the structurer can fold the
    /// addend pair in either order, so `idx*8 + *(rbp-16)` is the
    /// commuted form of the saxpy pattern and must also propagate.
    #[test]
    fn test_commuted_spill_pointer_arithmetic_recovers_pointer() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        let xs_reload = Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(16)), 8);
        let scaled = Expr::binop(
            BinOpKind::Mul,
            Expr::unknown("var_2c"),
            Expr::int(8),
        );
        // Commuted: scaled-index on the LEFT, spill load on the RIGHT.
        let elem = Expr::deref(Expr::binop(BinOpKind::Add, scaled, xs_reload), 8);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::assign(Expr::unknown("tmp"), elem)],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![
                ParamSpillObservation {
                    register: "xmm0".to_string(),
                    offset: -8,
                },
                ParamSpillObservation {
                    register: "rdi".to_string(),
                    offset: -16,
                },
            ]);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| {
                matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
                )
            })
            .expect("rdi parameter present");
        assert!(
            matches!(
                rdi_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "commuted Add (idx*8 + spill) should still recover rdi as pointer, got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #32 pass 4: `long f(long n) { return n+1; }`
    /// lifts to `Deref(rbp-8, 8) + 1` — same shape as a pointer
    /// reload with an IntLit offset. Width gate alone (`>= 8`) lets
    /// it through; we additionally require a scaled-index rhs
    /// (`Mul` / `Shl`) before claiming pointer arithmetic.
    #[test]
    fn test_long_scalar_plus_one_does_not_force_pointer_typing() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        let n_reload = || Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(8)), 8);
        let n_plus_one = Expr::binop(BinOpKind::Add, n_reload(), Expr::int(1));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::assign(Expr::unknown("tmp"), n_plus_one)],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -8,
            }]);
        let sig = recovery.analyze(&cfg);
        for p in &sig.parameters {
            assert!(
                !matches!(
                    p.param_type,
                    ParamType::Pointer | ParamType::TypedPointer(_)
                ),
                "scalar 64-bit add must not force pointer typing on {:?} (full sig: {:?})",
                p,
                sig.parameters
            );
        }
    }

    /// Codex review on PR #32 pass 3: a spilled `int *p` reloaded
    /// and dereferenced as `Deref(Deref(rbp-8, 8), 4)` must still
    /// recover as pointer even though the OUTER pointee width is 4.
    /// The gate keys on the ADDRESS load width (8 bytes here),
    /// not the pointee width.
    #[test]
    fn test_spilled_pointer_with_narrow_pointee_recovers_as_pointer() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        // *p where p = rdi was spilled at -8 and p points to int (4 bytes).
        let p_reload = Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(8)), 8);
        let star_p = Expr::deref(p_reload, 4);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::assign(Expr::unknown("tmp"), star_p)],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![ParamSpillObservation {
                register: "rdi".to_string(),
                offset: -8,
            }]);
        let sig = recovery.analyze(&cfg);
        let rdi_param = sig
            .parameters
            .iter()
            .find(|p| {
                matches!(
                    &p.location,
                    ParameterLocation::IntegerRegister { name, .. } if name == "rdi"
                )
            })
            .expect("rdi parameter present");
        assert!(
            matches!(
                rdi_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "rdi should recover as pointer despite narrow pointee, got {:?}",
            rdi_param.param_type
        );
    }

    /// Codex review on PR #32 pass 2: the initial spill-slot bridge
    /// mis-typed scalar args as pointers when they were just being
    /// reloaded for plain integer use. Two scenarios:
    ///   tmp = *(rbp-4)      ← `int n` reload, value used as int
    ///   tmp = *(rbp-4) + 1  ← `n + 1`, value used as int
    /// Both must keep the spilled `edi` as int, not pointer.
    #[test]
    fn test_scalar_spill_reload_does_not_force_pointer_typing() {
        use hexray_core::BasicBlockId;
        let rbp = || Expr::var(Variable::reg("rbp", 8));
        let n_reload = || {
            Expr::deref(Expr::binop(BinOpKind::Sub, rbp(), Expr::int(4)), 4)
        };

        // Body shape:
        //   tmp_a = *(rbp-4)            ; scalar reload
        //   tmp_b = *(rbp-4) + 1        ; n + 1
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("tmp_a"), n_reload()),
                Expr::assign(
                    Expr::unknown("tmp_b"),
                    Expr::binop(BinOpKind::Add, n_reload(), Expr::int(1)),
                ),
            ],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_param_spill_order(vec![ParamSpillObservation {
                register: "edi".to_string(),
                offset: -4,
            }]);
        let sig = recovery.analyze(&cfg);

        // No recovered parameter may be a pointer just because its
        // spill slot was reloaded for plain scalar use. (The arg
        // may or may not surface at all — what matters is the
        // false-positive pointer hint stays off.)
        for p in &sig.parameters {
            assert!(
                !matches!(
                    p.param_type,
                    ParamType::Pointer | ParamType::TypedPointer(_)
                ),
                "scalar int spill reload mis-typed param {:?} as pointer (full sig: {:?})",
                p,
                sig.parameters
            );
        }
    }

    #[test]
    fn test_signature_recovery_keeps_cpuid_output_pointer_param() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    Expr::unknown("ret_0"),
                    Expr::call(
                        CallTarget::Named("cpuid".to_string()),
                        vec![Expr::unknown("arg0")],
                    ),
                ),
                Expr::assign(
                    Expr::deref(Expr::unknown("arg1"), 4),
                    Expr::unknown("ret_0"),
                ),
            ],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2, "params: {:?}", sig.parameters);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert!(
            matches!(
                sig.parameters[1].param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ),
            "expected arg1 to be inferred as pointer, got {:?}",
            sig.parameters[1].param_type
        );
    }

    #[test]
    fn test_lifted_stack_local_alias_does_not_create_spurious_param() {
        use hexray_core::BasicBlockId;

        // Simulate a lifted local-stack flow:
        //   var_18 = stack_-8;
        //   tmp = var_18[iter];
        //
        // stack_-8 should not be treated as an implicit ABI parameter by itself.
        let bind_local = Expr::assign(Expr::unknown("var_18"), Expr::unknown("stack_-8"));
        let load_indexed = Expr::assign(
            Expr::unknown("tmp"),
            Expr::array_access(Expr::unknown("var_18"), Expr::unknown("iter"), 4),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind_local, load_indexed],
            address_range: (0x1000, 0x1020),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);
        assert!(
            sig.parameters.is_empty(),
            "expected no inferred parameters for local stack alias, got {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_detects_lifted_arg_slot_read_as_param() {
        use hexray_core::BasicBlockId;

        let read_lifted_arg = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg_8"));
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![read_lifted_arg],
            address_range: (0x1200, 0x1210),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(
            sig.parameters.len(),
            1,
            "expected lifted arg slot read to recover arg0, got {:?}",
            sig.parameters
        );
        assert!(matches!(
            sig.parameters[0].location,
            ParameterLocation::IntegerRegister { index: 0, .. }
        ));
    }

    #[test]
    fn test_windows_calling_convention() {
        use hexray_core::BasicBlockId;

        // Windows x64: uses RCX, RDX, R8, R9
        let rcx = Expr::var(Variable::reg("rcx", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));

        let add = Expr::binop(BinOpKind::Add, rcx, rdx);
        let stmt = Expr::assign(Expr::var(Variable::reg("rax", 8)), add);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Win64);
        let sig = recovery.analyze(&cfg);

        // Should detect 2 parameters
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    #[test]
    fn test_riscv_calling_convention() {
        use hexray_core::BasicBlockId;

        // RISC-V: uses a0-a7
        let a0 = Expr::var(Variable::reg("a0", 8));
        let a1 = Expr::var(Variable::reg("a1", 8));
        let a2 = Expr::var(Variable::reg("a2", 8));

        let add1 = Expr::binop(BinOpKind::Add, a0, a1);
        let add2 = Expr::binop(BinOpKind::Add, add1, a2);
        let stmt = Expr::assign(Expr::var(Variable::reg("t0", 8)), add2);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::RiscV);
        let sig = recovery.analyze(&cfg);

        // Should detect 3 parameters
        assert_eq!(sig.parameters.len(), 3);
    }

    #[test]
    fn test_params_string() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.parameters.push(Parameter::new(
            "arg0",
            ParamType::SignedInt(32),
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(Parameter::new(
            "arg1",
            ParamType::SignedInt(64),
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let params = sig.params_string();
        assert_eq!(params, "int32_t arg0, int64_t arg1");
    }

    #[test]
    fn test_param_type_size() {
        assert_eq!(ParamType::Void.size(), 0);
        assert_eq!(ParamType::Bool.size(), 1);
        assert_eq!(ParamType::SignedInt(8).size(), 1);
        assert_eq!(ParamType::SignedInt(16).size(), 2);
        assert_eq!(ParamType::SignedInt(32).size(), 4);
        assert_eq!(ParamType::SignedInt(64).size(), 8);
        assert_eq!(ParamType::Float(32).size(), 4);
        assert_eq!(ParamType::Float(64).size(), 8);
        assert_eq!(ParamType::Float(80).size(), 10);
        assert_eq!(ParamType::SimdFloat(32).size(), 32);
        assert_eq!(ParamType::Pointer.size(), 8);
        assert_eq!(
            ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::Pointer],
            }
            .size(),
            8
        );
    }

    #[test]
    fn test_signature_recovery_detects_qsort_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert!(
            matches!(
                sig.parameters[3].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("cmp"),
            "int32_t (*cmp)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_qsort_callback_via_direct_symbol_table_name() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Direct {
                target: 0x401000,
                call_site: 0x1000,
            },
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut symbols = SymbolTable::new();
        symbols.insert(0x401000, "_qsort@plt".to_string());

        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_symbol_table(Some(symbols));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert!(
            matches!(
                sig.parameters[3].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_detects_bsearch_callback_when_lifted_to_arg4() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("bsearch".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::int(4),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // With use-before-def analysis, only 4 args (0,1,2,4) are detected, not 5
        assert_eq!(sig.parameters.len(), 4);
        // The callback (originally arg4/r8) is now at index 3 in the params vector
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_indirect_call_argument() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::var(Variable::reg("rdi", 8)))),
            vec![Expr::var(Variable::reg("rsi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty());
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*)"
        );
    }

    #[test]
    fn test_signature_recovery_inferrs_indirect_call_prototype() {
        use hexray_core::BasicBlockId;

        let fn_ptr = Expr::var(Variable::reg("rdi", 8));
        let by_ref_local = Expr::address_of(Expr::var(Variable::stack(-8, 8)));
        let call = Expr::call(
            CallTarget::Indirect(Box::new(fn_ptr)),
            vec![by_ref_local, Expr::int(7)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*, int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_lifted_arg_name_indirect_call_prototype() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::unknown("arg1"))),
            vec![Expr::unknown("arg0"), Expr::unknown("arg2")],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.parameters.len() >= 2, "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[1].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert_eq!(
            sig.parameters[1].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_tracks_alias_to_function_pointer_parameter() {
        use hexray_core::BasicBlockId;

        let alias_assign = Expr::assign(
            Expr::var(Variable::stack(-8, 8)),
            Expr::var(Variable::reg("rdi", 8)),
        );
        let indirect_call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::var(Variable::stack(-8, 8)))),
            vec![Expr::var(Variable::reg("rsi", 8)), Expr::int(1)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![alias_assign, indirect_call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty());
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*, int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_resolves_indirect_got_target_name() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::IndirectGot {
                got_address: 0x4040,
                expr: Box::new(Expr::var(Variable::reg("rax", 8))),
            },
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut relocs = RelocationTable::new();
        relocs.insert_got(0x4040, "qsort".to_string());

        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_relocation_table(Some(relocs));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_uses_summary_for_callback_types() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("bsearch".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let summary_db = Arc::new(super::super::interprocedural::SummaryDatabase::new());
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_summary_database(Some(summary_db));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_propagates_callback_hint_through_alias() {
        use hexray_core::BasicBlockId;

        let rbp = Expr::var(Variable::reg("rbp", 8));
        let stack_slot = Expr::deref(Expr::binop(BinOpKind::Add, rbp, Expr::int(-8)), 8);
        let save_arg = Expr::assign(stack_slot.clone(), Expr::var(Variable::reg("rsi", 8)));
        let call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), stack_slot],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![save_arg, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // With use-before-def: only rsi (index 1) is detected -> 1 param at params[0]
        assert!(matches!(
            sig.parameters[0].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_propagates_callback_hint_through_lifted_var_alias() {
        use hexray_core::BasicBlockId;

        let save_arg = Expr::assign(Expr::unknown("var_8"), Expr::var(Variable::reg("rdx", 8)));
        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::int(4),
                Expr::unknown("var_8"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![save_arg, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(matches!(
            sig.parameters[2].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_handles_reused_lifted_alias_in_qsort_callback() {
        use hexray_core::BasicBlockId;

        let stmt1 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg0"));
        let stmt2 = Expr::assign(Expr::unknown("var_10"), Expr::unknown("arg1"));
        let stmt3 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg2"));
        let call = Expr::call(
            CallTarget::Named("_qsort".to_string()),
            vec![
                Expr::unknown("arg_8"),
                Expr::unknown("var_10"),
                Expr::int(4),
                Expr::unknown("arg_8"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt1, stmt2, stmt3, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // Callback should resolve to the rdx/x2 slot (register index 2).
        assert!(
            sig.parameters.iter().any(|p| {
                matches!(p.param_type, ParamType::FunctionPointer { .. })
                    && matches!(
                        p.location,
                        ParameterLocation::IntegerRegister { index: 2, .. }
                    )
            }),
            "params: {:?}",
            sig.parameters
        );
        let reasons = sig
            .parameter_provenance
            .get(&2) // still index 2 (the register index)
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons.iter().any(|r| r.contains("[source=alias]")),
            "provenance: {:?}",
            reasons
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("[source=shape-fallback]")),
            "provenance: {:?}",
            reasons
        );
    }

    #[test]
    fn test_signature_recovery_resolves_array_access_alias_in_qsort_callback() {
        use hexray_core::BasicBlockId;

        let fp_slot = Expr::array_access(Expr::var(Variable::reg("x29", 8)), Expr::int(-1), 8);
        let sp_slot_arg1 = Expr::array_access(Expr::var(Variable::reg("sp", 8)), Expr::int(2), 8);
        let sp_slot_cb = Expr::array_access(Expr::var(Variable::reg("sp", 8)), Expr::int(1), 8);
        let stmt1 = Expr::assign(fp_slot.clone(), Expr::unknown("arg0"));
        let stmt2 = Expr::assign(sp_slot_arg1.clone(), Expr::unknown("arg1"));
        let stmt3 = Expr::assign(sp_slot_cb.clone(), Expr::unknown("arg2"));
        let call = Expr::call(
            CallTarget::Named("_qsort".to_string()),
            vec![fp_slot, sp_slot_arg1, Expr::int(4), sp_slot_cb],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt1, stmt2, stmt3, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        // Callback should resolve to the x2 slot (register index 2), while
        // arg0/arg1 may still be surfaced as ordinary parameters.
        assert!(
            sig.parameters.iter().any(|p| {
                matches!(p.param_type, ParamType::FunctionPointer { .. })
                    && matches!(
                        p.location,
                        ParameterLocation::IntegerRegister { index: 2, .. }
                    )
            }),
            "params: {:?}",
            sig.parameters
        );
        let reasons = sig
            .parameter_provenance
            .get(&2) // still register index 2
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons.iter().any(|r| r.contains("[source=alias]")),
            "provenance: {:?}",
            reasons
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("[source=shape-fallback]")),
            "provenance: {:?}",
            reasons
        );
    }

    #[test]
    fn test_signature_recovery_resolves_unknown_lifted_arg_slot_before_shape_fallback() {
        use hexray_core::BasicBlockId;

        let bind_cb = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg0"));
        let bind_ctx = Expr::assign(Expr::unknown("var_10"), Expr::unknown("arg1"));
        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![Expr::unknown("arg_8"), Expr::unknown("var_10")],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind_cb, bind_ctx, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty(), "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        if sig.parameters.len() > 1 {
            assert!(
                !matches!(
                    sig.parameters[1].param_type,
                    ParamType::FunctionPointer { .. }
                ),
                "params: {:?}",
                sig.parameters
            );
        }
    }

    #[test]
    fn test_signature_recovery_resolves_multihop_lifted_alias_chain_for_qsort_callback() {
        use hexray_core::BasicBlockId;

        let bind0 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg0"));
        let bind1 = Expr::assign(Expr::unknown("arg_10"), Expr::unknown("arg1"));
        let bind2 = Expr::assign(Expr::unknown("var_18"), Expr::unknown("arg2"));
        let bind3 = Expr::assign(Expr::unknown("arg_10"), Expr::unknown("var_18"));
        let bind4 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg_10"));
        let bind5 = Expr::assign(Expr::unknown("var_0"), Expr::unknown("arg_8"));
        let call = Expr::call(
            CallTarget::Named("_qsort".to_string()),
            vec![
                Expr::unknown("arg_8"),
                Expr::unknown("arg_10"),
                Expr::int(4),
                Expr::unknown("var_0"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind0, bind1, bind2, bind3, bind4, bind5, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(
            sig.parameters.iter().any(|p| {
                matches!(p.param_type, ParamType::FunctionPointer { .. })
                    && matches!(
                        p.location,
                        ParameterLocation::IntegerRegister { index: 2, .. }
                    )
            }),
            "params: {:?}",
            sig.parameters
        );
        let reasons = sig
            .parameter_provenance
            .get(&2)
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons.iter().any(|r| r.contains("[source=alias]")),
            "provenance: {:?}",
            reasons
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("[source=shape-fallback]")),
            "provenance: {:?}",
            reasons
        );
    }

    #[test]
    fn test_signature_recovery_resolves_arm64_stack_hop_alias_chain_for_qsort_callback() {
        use hexray_core::BasicBlockId;

        let bind0 = Expr::assign(Expr::unknown("arg_8"), Expr::var(Variable::reg("x0", 8)));
        let bind1 = Expr::assign(Expr::unknown("arg_10"), Expr::var(Variable::reg("x1", 8)));
        let bind2 = Expr::assign(Expr::unknown("var_18"), Expr::var(Variable::reg("x2", 8)));
        let bind3 = Expr::assign(Expr::unknown("arg_10"), Expr::unknown("var_18"));
        let bind4 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg_10"));
        let bind5 = Expr::assign(Expr::unknown("var_0"), Expr::unknown("arg_8"));
        let call = Expr::call(
            CallTarget::Named("_qsort".to_string()),
            vec![
                Expr::unknown("arg_8"),
                Expr::unknown("arg_10"),
                Expr::int(4),
                Expr::unknown("var_0"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind0, bind1, bind2, bind3, bind4, bind5, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(
            sig.parameters.iter().any(|p| {
                matches!(p.param_type, ParamType::FunctionPointer { .. })
                    && matches!(
                        p.location,
                        ParameterLocation::IntegerRegister { index: 2, .. }
                    )
            }),
            "params: {:?}",
            sig.parameters
        );
        let reasons = sig
            .parameter_provenance
            .get(&2)
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons.iter().any(|r| r.contains("[source=alias]")),
            "provenance: {:?}",
            reasons
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("[source=shape-fallback]")),
            "provenance: {:?}",
            reasons
        );
    }

    #[test]
    fn test_signature_recovery_uses_slot_ordinal_fallback_for_ambiguous_multi_callback_alias() {
        use hexray_core::BasicBlockId;

        let bind_prepare = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg0"));
        let bind_parent = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg1"));
        let bind_child = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg2"));
        let call = Expr::call(
            CallTarget::Named("pthread_atfork".to_string()),
            vec![
                Expr::unknown("tmp"),
                Expr::unknown("tmp"),
                Expr::unknown("tmp"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind_prepare, bind_parent, bind_child, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.parameters.len() >= 3, "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert!(
            matches!(
                sig.parameters[1].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert!(
            matches!(
                sig.parameters[2].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        let reasons = sig
            .parameter_provenance
            .get(&2)
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons.iter().any(|r| r.contains("[source=alias]")),
            "provenance: {:?}",
            reasons
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r.contains("[source=shape-fallback]")),
            "provenance: {:?}",
            reasons
        );
    }

    #[test]
    fn test_signature_recovery_does_not_force_fp_for_non_parameter_callback_arg() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::int(4),
                Expr::unknown("cmp_ints"),
            ],
        );
        // Keep a fourth argument register live so fallback "last parameter" behavior
        // would previously mislabel it as a callback.
        let keep_r8_live = Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("r8", 8)));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call, keep_r8_live],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // With use-before-def: 3 registers used (rdi=0, rsi=1, r8=4) -> 3 params
        assert_eq!(sig.parameters.len(), 3);
        // r8 (originally arg4) is now at index 2 and should NOT be a function pointer
        assert!(!matches!(
            sig.parameters[2].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_detects_function_pointer_return() {
        use hexray_core::BasicBlockId;

        let signal_call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), Expr::var(Variable::reg("rdi", 8))],
        );

        let ret = StructuredNode::Return(Some(signal_call));
        let cfg = StructuredCfg {
            body: vec![ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(matches!(sig.return_type, ParamType::FunctionPointer { .. }));
        assert_eq!(
            sig.return_type.format_with_name("handler"),
            "void (*handler)(int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_uses_summary_fallback_for_function_pointer_return() {
        use hexray_core::BasicBlockId;

        // "__signal" bypasses the direct hardcoded name match and exercises summary fallback.
        let signal_call = Expr::call(
            CallTarget::Named("__signal".to_string()),
            vec![Expr::int(2), Expr::var(Variable::reg("rdi", 8))],
        );

        let ret = StructuredNode::Return(Some(signal_call));
        let cfg = StructuredCfg {
            body: vec![ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let summary_db = Arc::new(super::super::interprocedural::SummaryDatabase::new());
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_summary_database(Some(summary_db));
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(matches!(sig.return_type, ParamType::FunctionPointer { .. }));
        assert_eq!(
            sig.return_type.format_with_name("handler"),
            "void (*handler)(int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_pthread_create_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_create".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert_eq!(
            sig.parameters[2]
                .param_type
                .format_with_name("start_routine"),
            "void* (*start_routine)(void*)"
        );
    }

    #[test]
    fn test_signature_recovery_does_not_mark_pthread_arg_when_static_start_is_used() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_create".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::int(0),
                Expr::unknown("thread_trampoline"),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert!(!matches!(
            sig.parameters[1].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_does_not_mark_signal_param_when_static_handler_is_used() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), Expr::unknown("static_handler")],
        );
        let keep_param_live =
            Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("rdi", 8)));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call, keep_param_live],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert!(!matches!(
            sig.parameters[0].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_detects_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_bsd_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("bsd_qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_on_exit_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("fn"),
            "void (*fn)(int32_t, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_hexray_on_exit_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("fn"),
            "void (*fn)(int32_t, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_pthread_atfork_callbacks() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_atfork".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 3);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("prepare"),
            "void (*prepare)(void)"
        );
        assert_eq!(
            sig.parameters[1].param_type.format_with_name("parent"),
            "void (*parent)(void)"
        );
        assert_eq!(
            sig.parameters[2].param_type.format_with_name("child"),
            "void (*child)(void)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_hexray_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_infers_tail_call_forwarded_return_type() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_ignores_discardable_tail_call_forwarding_return_type() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_mutex_unlock".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_ignores_sigsuspend_tail_call_forwarding_return_type() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("sigsuspend".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_keeps_explicit_discardable_call_return_type() {
        use hexray_core::BasicBlockId;

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::Named("pthread_mutex_unlock".to_string()),
                vec![Expr::var(Variable::reg("rdi", 8))],
            )))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(!matches!(sig.return_type, ParamType::Void));
    }

    #[test]
    fn test_signature_recovery_last_discardable_tail_call_clears_prior_candidate() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::call(
                    CallTarget::Named("pthread_create".to_string()),
                    vec![
                        Expr::var(Variable::reg("rdi", 8)),
                        Expr::var(Variable::reg("rsi", 8)),
                        Expr::var(Variable::reg("rdx", 8)),
                        Expr::var(Variable::reg("rcx", 8)),
                    ],
                ),
                Expr::call(
                    CallTarget::Named("pthread_detach".to_string()),
                    vec![Expr::var(Variable::reg("rdi", 8))],
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_uses_known_tail_call_params_for_wrapper() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("strcpy@GLIBC_2.2.5".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "dst");
        assert_eq!(sig.parameters[1].name, "src");
        assert_eq!(sig.parameters[0].param_type, ParamType::Pointer);
        assert_eq!(sig.parameters[1].param_type, ParamType::Pointer);
    }

    #[test]
    fn test_signature_recovery_uses_builtin_tail_call_param_type_for_clone3_wrapper() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("clone3".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8)), Expr::int(88)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].name, "args");
        assert_eq!(
            sig.parameters[0].param_type,
            ParamType::TypedPointer(Box::new(ParamType::Named("struct clone_args".to_string())))
        );
    }

    #[test]
    fn test_signature_recovery_pads_known_tail_call_wrapper_arity() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("strcpy@GLIBC_2.2.5".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "dst");
        assert_eq!(sig.parameters[1].name, "src");
    }

    #[test]
    fn test_signature_recovery_does_not_extend_non_passthrough_chk_wrapper_arity() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("__sprintf_chk@GLIBC_2.3.4".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::int(2),
                Expr::int(-1),
                Expr::unknown("\"x=%d\""),
                Expr::var(Variable::reg("esi", 4)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "dst");
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    #[test]
    fn test_parse_printf_format_param_types_honors_size_modifiers_and_pointers() {
        let inferred = SignatureRecovery::parse_printf_format_param_types(
            "ull=%llu sz=%zu pd=%td ptr=%p n=%n\n",
        );

        assert_eq!(
            inferred,
            vec![
                ParamType::UnsignedLongLong,
                ParamType::SizeT,
                ParamType::PtrDiffT,
                ParamType::Pointer,
                ParamType::TypedPointer(Box::new(ParamType::SignedInt(32))),
            ]
        );
    }

    #[test]
    fn test_signature_recovery_infers_printf_chk_wrapper_variadic_types_from_format() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("__printf_chk@GLIBC_2.3.4".to_string()),
            vec![
                Expr::int(2),
                Expr::unknown("\"ull=%llu sz=%zu pd=%td\\n\""),
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 3);
        assert_eq!(sig.parameters[0].param_type, ParamType::UnsignedLongLong);
        assert_eq!(sig.parameters[1].param_type, ParamType::SizeT);
        assert_eq!(sig.parameters[2].param_type, ParamType::PtrDiffT);
    }

    #[test]
    fn test_signature_recovery_tracks_temp_value_width_for_return() {
        use hexray_core::BasicBlockId;

        let tmp0 = Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: "tmp0".to_string(),
            size: 8,
        });
        let acc_init = Expr::assign(tmp0.clone(), Expr::int(0));
        let acc_add = Expr::assign(
            tmp0.clone(),
            Expr::binop(
                BinOpKind::Add,
                tmp0.clone(),
                Expr::deref(Expr::var(Variable::reg("x1", 8)), 4),
            ),
        );
        let move_ret = Expr::assign(Expr::var(Variable::reg("x0", 8)), tmp0.clone());

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![acc_init, acc_add, move_ret],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(
            sig.return_type,
            ParamType::SignedInt(32),
            "expected 32-bit return width from tmp accumulator, got {:?}",
            sig.return_type
        );
    }

    #[test]
    fn test_signature_recovery_prefers_return_register_width_for_literal_return() {
        use hexray_core::BasicBlockId;

        let set_ret = Expr::assign(Expr::var(Variable::reg("w0", 4)), Expr::int(0));
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x1000, 0x1008),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_keeps_x0_width_for_literal_zero_return() {
        use hexray_core::BasicBlockId;

        let set_ret = Expr::assign(Expr::var(Variable::reg("x0", 8)), Expr::int(0));
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x2000, 0x2008),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(64));
    }

    #[test]
    fn test_signature_recovery_keeps_x0_width_for_literal_nonzero_return() {
        use hexray_core::BasicBlockId;

        let set_ret = Expr::assign(Expr::var(Variable::reg("x0", 8)), Expr::int(1));
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x2100, 0x2108),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(64));
    }

    #[test]
    fn test_signature_recovery_keeps_eax_width_for_literal_nonzero_return() {
        use hexray_core::BasicBlockId;

        let set_ret = Expr::assign(Expr::var(Variable::reg("eax", 4)), Expr::int(1));
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x2200, 0x2208),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_keeps_lea_int_wrapper_as_int32() {
        use hexray_core::BasicBlockId;

        let set_ret = Expr::assign(
            Expr::var(Variable::reg("rax", 4)),
            Expr::binop(
                BinOpKind::Add,
                Expr::var(Variable::reg("rdi", 4)),
                Expr::int(1),
            ),
        );
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![set_ret],
            address_range: (0x2300, 0x2303),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].param_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_propagates_w_to_x_temp_width_for_return() {
        use hexray_core::BasicBlockId;

        let w8 = Expr::var(Variable::reg("w8", 4));
        let init = Expr::assign(w8.clone(), Expr::int(0));
        let add = Expr::assign(
            w8.clone(),
            Expr::binop(
                BinOpKind::Add,
                w8.clone(),
                Expr::deref(Expr::var(Variable::reg("x0", 8)), 4),
            ),
        );
        let set_ret = Expr::assign(
            Expr::var(Variable::reg("x0", 8)),
            Expr::var(Variable::reg("x8", 8)),
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![init, add, set_ret],
            address_range: (0x3000, 0x3010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_does_not_infer_tail_return_for_void_callee() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_does_not_infer_tail_return_for_noreturn_callee() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("__longjmp_chk@GLIBC_2.11@plt".to_string()),
            vec![Expr::unknown("&env"), Expr::int(2)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_does_not_infer_tail_return_for_std_throw_helper() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("std::__throw_bad_optional_access".to_string()),
            vec![],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_does_not_infer_tail_return_for_builtin_prefetch() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("__builtin_prefetch".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::int(0),
                Expr::int(3),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1100, 0x1110),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_infers_tail_call_return_when_void_return_node_is_separate() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let ret = StructuredNode::Return(None);
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_falls_back_for_unresolved_tail_call_return() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("helper".to_string()),
            vec![Expr::var(Variable::reg("edi", 4))],
        );

        let call_block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1100, 0x1110),
        };
        let padding_block = StructuredNode::Block {
            id: BasicBlockId::new(1),
            statements: vec![Expr::unknown("/* nop */")],
            address_range: (0x1110, 0x1112),
        };
        let cfg = StructuredCfg {
            body: vec![call_block, padding_block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_falls_back_for_indirect_tail_call_return() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::var(Variable::reg("rdx", 8)))),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1200, 0x1210),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_defaults_literal_return_node_to_int32() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![],
            address_range: (0x6000, 0x6004),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::int(1)))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(
            sig.return_type,
            ParamType::SignedInt(32),
            "expected direct literal return node to default to int32_t, got {:?}",
            sig.return_type
        );
    }

    #[test]
    fn test_callee_saved_registers() {
        let sysv = CallingConvention::SystemV;
        let callee_saved = sysv.callee_saved_registers();
        assert!(callee_saved.contains(&"rbx"));
        assert!(callee_saved.contains(&"rbp"));
        assert!(callee_saved.contains(&"r12"));

        let aarch64 = CallingConvention::Aarch64;
        let callee_saved = aarch64.callee_saved_registers();
        assert!(callee_saved.contains(&"x19"));
        assert!(callee_saved.contains(&"x29"));
    }

    #[test]
    fn test_max_args() {
        let sysv = CallingConvention::SystemV;
        assert_eq!(sysv.max_int_args(), 6);
        assert_eq!(sysv.max_float_args(), 8);

        let win64 = CallingConvention::Win64;
        assert_eq!(win64.max_int_args(), 4);
        assert_eq!(win64.max_float_args(), 4);

        let aarch64 = CallingConvention::Aarch64;
        assert_eq!(aarch64.max_int_args(), 8);
        assert_eq!(aarch64.max_float_args(), 8);
    }

    #[test]
    fn test_parameter_from_helpers() {
        let param = Parameter::from_int_register(0, "rdi", ParamType::SignedInt(64));
        assert_eq!(param.name, "arg0");
        assert_eq!(param.param_type, ParamType::SignedInt(64));
        if let ParameterLocation::IntegerRegister { name, index } = param.location {
            assert_eq!(name, "rdi");
            assert_eq!(index, 0);
        } else {
            panic!("Expected IntegerRegister location");
        }

        let fparam = Parameter::from_float_register(0, "xmm0");
        assert_eq!(fparam.name, "farg0");
        assert_eq!(fparam.param_type, ParamType::Float(64));
    }

    #[test]
    fn test_signature_recovery_infers_float32_for_addss() {
        use crate::decompiler::expression::Expr;
        use hexray_core::{
            register::x86, Architecture, BasicBlockId, Instruction, Operand, Operation, Register,
            RegisterClass,
        };

        let xmm0 = Register::new(
            Architecture::X86_64,
            RegisterClass::FloatingPoint,
            x86::XMM0,
            128,
        );
        let xmm1 = Register::new(
            Architecture::X86_64,
            RegisterClass::FloatingPoint,
            x86::XMM1,
            128,
        );
        let addss = Instruction::new(0x1000, 4, vec![0xf3, 0x0f, 0x58, 0xc1], "addss")
            .with_operation(Operation::Add)
            .with_operands(vec![Operand::Register(xmm0), Operand::Register(xmm1)]);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::from_instruction(&addss)],
            address_range: (0x1000, 0x1004),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.return_type, ParamType::Float(32));
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].param_type, ParamType::Float(32));
        assert_eq!(sig.parameters[1].param_type, ParamType::Float(32));
    }

    #[test]
    fn test_signature_recovery_treats_explicit_float_binop_return_as_float() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: Vec::new(),
            address_range: (0x1000, 0x1000),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::binop(
                    BinOpKind::Add,
                    Expr::var(Variable::reg("farg0", 4)),
                    Expr::var(Variable::reg("farg1", 4)),
                ))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.return_type, ParamType::Float(32));
    }

    #[test]
    fn test_signature_recovery_treats_unknown_scalar_return_register_as_float() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::assign(
                Expr::var(Variable::reg("xmm0", 4)),
                Expr::binop(
                    BinOpKind::Add,
                    Expr::var(Variable::reg("xmm2", 4)),
                    Expr::binop(
                        BinOpKind::Mul,
                        Expr::var(Variable::reg("xmm0", 4)),
                        Expr::var(Variable::reg("xmm1", 4)),
                    ),
                ),
            )],
            address_range: (0x1000, 0x1000),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::unknown("xmm0")))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.return_type, ParamType::Float(32));
    }

    #[test]
    fn test_signature_recovery_treats_unknown_ymm_return_as_m256() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: Vec::new(),
            address_range: (0x1000, 0x1000),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::unknown("ymm0")))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.return_type, ParamType::SimdFloat(32));
    }

    #[test]
    fn test_signature_recovery_matches_unresolved_float_return_to_observed_arg_width() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("tmp0"), Expr::var(Variable::reg("xmm0", 4))),
                Expr::assign(Expr::unknown("tmp1"), Expr::var(Variable::reg("xmm1", 4))),
                Expr::assign(Expr::unknown("tmp2"), Expr::var(Variable::reg("xmm2", 4))),
            ],
            address_range: (0x1000, 0x1000),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::binop(
                    BinOpKind::Add,
                    Expr::unknown("farg2"),
                    Expr::binop(
                        BinOpKind::Mul,
                        Expr::unknown("farg0"),
                        Expr::unknown("farg1"),
                    ),
                ))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.return_type, ParamType::Float(32));
    }

    #[test]
    fn test_signature_recovery_marks_compound_write_to_xmm0_as_float_return() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    Expr::var(Variable::reg("xmm1", 16)),
                    Expr::var(Variable::reg("xmm0", 16)),
                ),
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Mul,
                        lhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                        rhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                    },
                },
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Add,
                        lhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                        rhs: Box::new(Expr::var(Variable::reg("xmm1", 16))),
                    },
                },
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Float(64));
    }

    #[test]
    fn test_signature_recovery_keeps_explicit_xmm0_return_as_float() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Mul,
                    lhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                    rhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                },
            }],
            address_range: (0x1000, 0x1008),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::var(Variable::reg("xmm0", 16)))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Float(64));
    }

    #[test]
    fn test_signature_recovery_classifies_integer_simd_lane_extract() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::unknown("/* SSE: punpckhdq */"),
                Expr::unknown("/* SSE: paddd */"),
                Expr::assign(
                    Expr::var(Variable::reg("eax", 4)),
                    Expr::var(Variable::reg("xmm0", 16)),
                ),
            ],
            address_range: (0x1000, 0x100c),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::var(Variable::reg("eax", 4)))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].param_type, ParamType::SimdInt128);
        assert!(matches!(
            sig.parameters[0].location,
            ParameterLocation::FloatRegister { ref name, index: 0 } if name == "xmm0"
        ));
    }

    #[test]
    fn test_signature_recovery_classifies_integer_simd_return_forwarded_via_xmm0() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::unknown("/* SSE: paddd */"),
                Expr::assign(
                    Expr::var(Variable::reg("xmm0", 16)),
                    Expr::var(Variable::reg("rax", 4)),
                ),
            ],
            address_range: (0x1000, 0x1008),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::var(Variable::reg("xmm0", 16)))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_function_name("sse_hsum");
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].param_type, ParamType::SimdInt128);
    }

    #[test]
    fn test_signature_recovery_recovers_scalar_integer_return_from_mixed_simd_returns() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::unknown("/* SSE: pmaxsd */")],
            address_range: (0x1000, 0x1004),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::If {
                    condition: Expr::binop(
                        BinOpKind::Gt,
                        Expr::var(Variable::reg("esi", 4)),
                        Expr::int(1),
                    ),
                    then_body: vec![StructuredNode::Return(Some(Expr::var(Variable::reg(
                        "xmm0", 16,
                    ))))],
                    else_body: Some(vec![StructuredNode::Return(Some(Expr::int(1)))]),
                },
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
        assert!(sig.return_provenance.iter().any(|reason| {
            reason == "integer scalar return recovered from integer SIMD branches"
        }));
    }

    #[test]
    fn test_signature_recovery_classifies_x87_fp80_stack_signature() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::call(
                    CallTarget::Named("fld".to_string()),
                    vec![Expr::unknown("var_8")],
                ),
                Expr::call(
                    CallTarget::Named("fld".to_string()),
                    vec![Expr::var(Variable::reg("st(0)", 10))],
                ),
                Expr::call(
                    CallTarget::Named("fmul".to_string()),
                    vec![
                        Expr::var(Variable::reg("st(0)", 10)),
                        Expr::var(Variable::reg("st(1)", 10)),
                    ],
                ),
            ],
            address_range: (0x1000, 0x100c),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::call(
                    CallTarget::Named("faddp".to_string()),
                    vec![
                        Expr::var(Variable::reg("st(1)", 10)),
                        Expr::var(Variable::reg("st(0)", 10)),
                    ],
                ))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Float(80));
        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].param_type, ParamType::Float(80));
        assert!(matches!(
            sig.parameters[0].location,
            ParameterLocation::Stack { offset: 8 }
        ));
    }

    #[test]
    fn test_signature_recovery_redirects_shadow_arg_hints_to_original_param() {
        use hexray_core::BasicBlockId;

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    Expr::var(Variable::reg("r8", 8)),
                    Expr::var(Variable::reg("rdi", 8)),
                ),
                Expr::assign(
                    Expr::var(Variable::reg("edx", 4)),
                    Expr::var(Variable::reg("esi", 4)),
                ),
                Expr::assign(
                    Expr::var(Variable::reg("ecx", 4)),
                    Expr::var(Variable::reg("edx", 4)),
                ),
                Expr::assign(
                    Expr::var(Variable::reg("eax", 4)),
                    Expr::array_access(
                        Expr::var(Variable::reg("r8", 8)),
                        Expr::var(Variable::reg("ecx", 4)),
                        4,
                    ),
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::var(Variable::reg("eax", 4)))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(
            sig.parameters.len(),
            2,
            "shadow arg copies should not become new params"
        );
        assert!(matches!(
            sig.parameters[0].param_type,
            ParamType::TypedPointer(_)
        ));
        assert!(matches!(
            sig.parameters[1].param_type,
            ParamType::SignedInt(32) | ParamType::UnsignedInt(32)
        ));
    }

    #[test]
    fn test_parameter_usage_hints_prefers_signed_scalar_comparisons() {
        let hints = ParameterUsageHints {
            is_signed_comparison: true,
            is_unsigned_ops: true,
            ..Default::default()
        };

        assert_eq!(hints.infer_type(4), ParamType::SignedInt(32));
    }

    #[test]
    fn test_mixed_register_sizes_x86() {
        use hexray_core::BasicBlockId;

        // Function with mixed register sizes
        let rdi = Expr::var(Variable::reg("rdi", 8)); // 64-bit
        let esi = Expr::var(Variable::reg("esi", 4)); // 32-bit

        let add = Expr::binop(BinOpKind::Add, rdi, esi);
        let stmt = Expr::assign(Expr::var(Variable::reg("rax", 8)), add);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        // First param is 64-bit (from rdi)
        assert!(matches!(
            sig.parameters[0].param_type,
            ParamType::SignedInt(64)
        ));
        // Second param is 32-bit (from esi)
        assert!(matches!(
            sig.parameters[1].param_type,
            ParamType::SignedInt(32)
        ));
    }

    #[test]
    fn test_known_function_params_main() {
        // Test that main() gets argc and argv parameter names
        let params = get_known_function_params("main").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "argc");
        assert!(matches!(params[0].1, ParamType::SignedInt(32)));
        assert_eq!(params[1].0, "argv");
        assert!(matches!(params[1].1, ParamType::Pointer));

        // Also test _main (macOS)
        let params2 = get_known_function_params("_main").unwrap();
        assert_eq!(params2.len(), 2);
        assert_eq!(params2[0].0, "argc");
    }

    #[test]
    fn test_known_function_params_memory() {
        // Test malloc
        let params = get_known_function_params("malloc").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "size");
        assert!(matches!(params[0].1, ParamType::UnsignedInt(64)));

        // Test memcpy
        let params = get_known_function_params("memcpy").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "dst");
        assert_eq!(params[1].0, "src");
        assert_eq!(params[2].0, "n");

        // Test free
        let params = get_known_function_params("free").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "ptr");
    }

    #[test]
    fn test_known_function_params_file_io() {
        // Test open
        let params = get_known_function_params("open").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "pathname");
        assert_eq!(params[1].0, "flags");
        assert_eq!(params[2].0, "mode");

        // Test read
        let params = get_known_function_params("read").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "fd");
        assert_eq!(params[1].0, "buf");
        assert_eq!(params[2].0, "count");

        // Test close
        let params = get_known_function_params("close").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "fd");
    }

    #[test]
    fn test_known_function_params_string() {
        // Test strlen
        let params = get_known_function_params("strlen").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "s");

        // Test strcmp
        let params = get_known_function_params("strcmp").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "s1");
        assert_eq!(params[1].0, "s2");

        // Test strstr
        let params = get_known_function_params("strstr").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "haystack");
        assert_eq!(params[1].0, "needle");
    }

    #[test]
    fn test_known_function_params_chk_variants() {
        let strcpy_chk = get_known_function_params("__strcpy_chk@GLIBC_2.3.4").unwrap();
        assert_eq!(strcpy_chk.len(), 3);
        assert_eq!(strcpy_chk[0].0, "dst");
        assert_eq!(strcpy_chk[2].0, "dstlen");

        let memcpy_chk = get_known_function_params("__memcpy_chk@GLIBC_2.3.4").unwrap();
        assert_eq!(memcpy_chk.len(), 4);
        assert_eq!(memcpy_chk[3].0, "dstlen");

        let sprintf_chk = get_known_function_params("__sprintf_chk@GLIBC_2.3.4").unwrap();
        assert_eq!(sprintf_chk.len(), 4);
        assert_eq!(sprintf_chk[3].0, "format");

        let snprintf_chk = get_known_function_params("__snprintf_chk@GLIBC_2.3.4").unwrap();
        assert_eq!(snprintf_chk.len(), 5);
        assert_eq!(snprintf_chk[4].0, "format");

        assert_eq!(
            known_function_param_count("__strcpy_chk@GLIBC_2.3.4"),
            Some(3)
        );
        assert_eq!(
            known_function_param_count("__snprintf_chk@GLIBC_2.3.4"),
            Some(5)
        );
    }

    #[test]
    fn test_known_function_params_socket() {
        // Test socket
        let params = get_known_function_params("socket").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "domain");
        assert_eq!(params[1].0, "type_");
        assert_eq!(params[2].0, "protocol");

        // Test bind
        let params = get_known_function_params("bind").unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0].0, "sockfd");
        assert_eq!(params[1].0, "addr");
        assert_eq!(params[2].0, "addrlen");
    }

    #[test]
    fn test_known_function_params_unknown() {
        // Unknown function should return None
        assert!(get_known_function_params("my_custom_function").is_none());
        assert!(get_known_function_params("foo_bar_baz").is_none());
    }

    #[test]
    fn test_signature_recovery_with_known_function_name() {
        // Create a simple CFG that reads rdi and rsi (first two args)
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));
        let add = Expr::binop(BinOpKind::Add, rdi, rsi);
        let ret_stmt = StructuredNode::Return(Some(add));

        let cfg = StructuredCfg {
            body: vec![ret_stmt],
            cfg_entry: BasicBlockId::new(0),
        };

        // Test with main function - should get argc/argv names
        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_function_name("main");
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "argc");
        assert_eq!(sig.parameters[1].name, "argv");
    }

    #[test]
    fn test_signature_recovery_malloc_like() {
        // Create a CFG that reads rdi (first arg)
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let ret_stmt = StructuredNode::Return(Some(rdi));

        let cfg = StructuredCfg {
            body: vec![ret_stmt],
            cfg_entry: BasicBlockId::new(0),
        };

        // Test with malloc function - should get "size" name
        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_function_name("malloc");
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(sig.parameters[0].name, "size");
    }

    #[test]
    fn test_signature_recovery_defaults_ifunc_returns_to_pointer() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::var(Variable::reg(
                "rax", 8,
            ))))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_current_function_kind(Some(SymbolKind::IndirectFunction));
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Pointer);
        assert!(sig
            .return_provenance
            .iter()
            .any(|reason| reason == "IFUNC resolver default return type"));
    }

    #[test]
    fn test_signature_recovery_uses_builtin_return_type_for_versioned_malloc_call() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::Named("malloc@GLIBC_2.2.5".to_string()),
                vec![Expr::var(Variable::reg("rdi", 8))],
            )))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Pointer);
    }

    #[test]
    fn test_signature_recovery_tracks_pointer_alias_return_from_versioned_malloc_call() {
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Expr(Expr::assign(
                    Expr::unknown("local_8"),
                    Expr {
                        kind: ExprKind::Cast {
                            expr: Box::new(Expr::call(
                                CallTarget::Named("malloc@GLIBC_2.2.5".to_string()),
                                vec![Expr::var(Variable::reg("rdi", 8))],
                            )),
                            to_size: 4,
                            signed: true,
                        },
                    },
                )),
                StructuredNode::Return(Some(Expr::unknown("local_8"))),
            ],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::Pointer);
    }

    #[test]
    fn test_signature_recovery_infers_atomic_exchange_return_width_from_pointee() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::Named("atomic_exchange".to_string()),
                vec![
                    Expr::address_of(Expr::var(Variable::global(0x404028, 4))),
                    Expr::var(Variable::reg("rdi", 4)),
                ],
            )))],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }
}
