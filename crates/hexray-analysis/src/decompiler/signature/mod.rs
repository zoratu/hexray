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
            // Store ops (the `-O0` arg spill is the dominant case)
            // can carry one or more register operands, each a source
            // value stored to memory. x86 movsd uses `[mem, reg]`
            // order; aarch64 STR uses `[reg, mem]`; aarch64 STP uses
            // `[reg, reg, mem]` so a prologue
            // `stp d0, d1, [sp, #-16]!` carries BOTH float-arg
            // registers as sources. Iterate ALL register operands
            // and treat each as a source read — never as a
            // destination write, regardless of position. Codex
            // review on PR #25 flagged the find_map / single-op form
            // as undercounting STP-spilled float args.
            let is_store = matches!(inst.operation, Operation::Store);
            if is_store {
                for operand in &inst.operands {
                    let Operand::Register(reg) = operand else {
                        continue;
                    };
                    let name = reg.name().to_lowercase();
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
            // Float-bank registers in any source position are reads —
            // but the `pxor %xmm,%xmm` / `xorps`/`xorpd` self-xor is a
            // zeroing idiom (`reg = 0`), not a read of an incoming
            // argument. Iterate over operand[1..] so 3-operand
            // instructions are fully covered: x86 AVX VEX-encoded
            // `vfmadd231sd xmm0, xmm1, xmm2` and the aarch64
            // 3-operand FP form `fadd d0, d0, d1` both carry sources
            // past operand[1]. Codex review on PR #25 flagged the
            // single-operand-1 form as undercounting aarch64 FP arg
            // arity for any function that uses its args directly
            // instead of spilling.
            let is_self_zero = matches!(inst.operation, Operation::Xor)
                && operands_are_same_register(&inst.operands);
            if !is_self_zero {
                for operand in inst.operands.iter().skip(1) {
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
            'q' => return 16,
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
        if matches!(
            inst.operation,
            Operation::Return | Operation::Push | Operation::Pop | Operation::Nop
            // Store ops: on aarch64 `str d0, [sp, #N]` (an arg spill,
            // common in the entry block when the return block happens
            // to be the entry block too) carries d0 as operand[0] —
            // the SOURCE being stored, not a destination write. Without
            // skipping Store the return classifier would treat the
            // spill as a `d0 = ...` and mistakenly seed a float
            // return on integer/void leaf functions whose only float
            // reference is the incoming arg spill. Codex review on
            // PR #25 pass 2.
            | Operation::Store
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
            // aarch64 epilogue: `ldp x29, x30, [sp, #N]` / `add sp, sp,
            // #M` aren't the value-producing writes either; the actual
            // return value sits in d0/v0 / x0 set earlier.
            || m == "ldp"
            || m.starts_with("stp")
        {
            continue;
        }
        // The stack-canary guard compare (`cmp`/`sub` against %fs:0x28).
        if instruction_references_stack_guard(inst) {
            saw_guard = true;
            continue;
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
            x87_stack_arg_offsets: BTreeSet::new(),
            return_function_pointer: None,
            tail_call_return_type: None,
            tail_call_min_arity: None,
            return_is_pointer: false,
            return_provenance: Vec::new(),
            return_confidence: 0,
            param_names: HashMap::new(),
            arg_spill_offsets: HashMap::new(),
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
                // First, analyze the RHS for reads
                self.analyze_expr_reads(rhs);
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
                    self.observed_float_arg_regs.insert(observed_name.clone());
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
                    self.observed_float_arg_regs.insert(observed_name);
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

                    if right_is_offset {
                        if let ExprKind::Var(var) = &left.kind {
                            let base_width =
                                self.infer_expr_size(left).unwrap_or(var.size).max(var.size);
                            if base_width >= 8 {
                                self.record_usage_hint(&var.name.to_lowercase(), |h| {
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
                // The address expression is being dereferenced
                self.analyze_expr_reads_with_context(addr, true, false);

                // Track element type and dereference count for base variables
                if let Some(base_name) = self.extract_var_name(addr) {
                    let elem_type = Self::infer_type_from_size(*size as usize);
                    self.record_usage_hint(&base_name, |h| {
                        h.deref_count += 1;
                        if h.deref_element_type.is_none() {
                            h.deref_element_type = Some(elem_type.clone());
                        }
                    });
                }
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                // Base is being used as a pointer/array
                self.analyze_expr_reads_with_context(base, true, false);

                // Mark base as array access and track element type
                if let Some(base_name) = self.extract_var_name(base) {
                    let elem_type = Self::infer_type_from_size(*element_size);
                    self.record_usage_hint(&base_name, |h| {
                        h.is_array_access = true;
                        h.deref_count += 1;
                        if h.deref_element_type.is_none() {
                            h.deref_element_type = Some(elem_type.clone());
                        }
                    });
                }

                // Index might be an array index parameter
                if let ExprKind::Var(var) = &index.kind {
                    self.record_usage_hint(&var.name.to_lowercase(), |h| h.is_array_index = true);
                }
                self.analyze_expr_reads_with_context(index, false, false);
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
        for (idx, reg) in float_regs.iter().enumerate() {
            if variadic_fixed_param_count.is_some_and(|fixed_count| idx >= fixed_count) {
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
