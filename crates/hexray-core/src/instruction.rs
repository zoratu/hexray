//! Architecture-agnostic instruction representation.

use crate::{Operand, Register};

/// An architecture-agnostic instruction.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Instruction {
    /// Virtual address of this instruction.
    pub address: u64,
    /// Size in bytes.
    pub size: usize,
    /// Raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// High-level operation category.
    pub operation: Operation,
    /// Mnemonic string (e.g., "mov", "add", "bl").
    pub mnemonic: String,
    /// Operands (destination first, then sources).
    pub operands: Vec<Operand>,
    /// Control flow information.
    pub control_flow: ControlFlow,
    /// Registers read by this instruction.
    pub reads: Vec<Register>,
    /// Registers written by this instruction.
    pub writes: Vec<Register>,
}

impl Instruction {
    /// Creates a new instruction with minimal fields.
    pub fn new(address: u64, size: usize, bytes: Vec<u8>, mnemonic: impl Into<String>) -> Self {
        Self {
            address,
            size,
            bytes,
            operation: Operation::Other(0),
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            control_flow: ControlFlow::Sequential,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    /// Sets the operation.
    pub fn with_operation(mut self, op: Operation) -> Self {
        self.operation = op;
        self
    }

    /// Adds an operand.
    pub fn with_operand(mut self, op: Operand) -> Self {
        self.operands.push(op);
        self
    }

    /// Sets operands.
    pub fn with_operands(mut self, ops: Vec<Operand>) -> Self {
        self.operands = ops;
        self
    }

    /// Sets the control flow.
    pub fn with_control_flow(mut self, cf: ControlFlow) -> Self {
        self.control_flow = cf;
        self
    }

    /// Returns the end address (address + size).
    pub fn end_address(&self) -> u64 {
        self.address + self.size as u64
    }

    /// Returns true if this instruction is a branch (jump/call).
    pub fn is_branch(&self) -> bool {
        !matches!(self.control_flow, ControlFlow::Sequential)
    }

    /// Returns true if this instruction is a call.
    pub fn is_call(&self) -> bool {
        matches!(
            self.control_flow,
            ControlFlow::Call { .. } | ControlFlow::IndirectCall { .. }
        )
    }

    /// Returns true if this instruction is a return.
    pub fn is_return(&self) -> bool {
        matches!(self.control_flow, ControlFlow::Return)
    }

    /// Returns true if this instruction terminates a basic block.
    pub fn is_terminator(&self) -> bool {
        !matches!(self.control_flow, ControlFlow::Sequential)
    }
}

/// High-level operation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Operation {
    // Data movement
    Move,
    Load,
    Store,
    Push,
    Pop,
    Exchange,
    LoadEffectiveAddress,

    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Neg,
    Inc,
    Dec,

    // Sign extension
    /// Sign-extend accumulator (CBW, CWDE, CDQE, CWD, CDQ, CQO)
    SignExtend,

    // Logical
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,

    // Bit manipulation
    Popcnt,
    Lzcnt,
    Tzcnt,
    // BMI1 instructions
    AndNot,           // ANDN: dest = ~src1 & src2
    BitExtract,       // BEXTR: Bit field extract
    ExtractLowestBit, // BLSI: Extract lowest set bit
    MaskUpToLowest,   // BLSMSK: Get mask up to lowest set bit
    ResetLowestBit,   // BLSR: Reset lowest set bit
    // BMI2 instructions
    ZeroHighBits,    // BZHI: Zero high bits starting from specified position
    ParallelDeposit, // PDEP: Parallel bits deposit
    ParallelExtract, // PEXT: Parallel bits extract
    MulNoFlags,      // MULX: Unsigned multiply without affecting flags
    // Bit test instructions
    BitTest, // BT/BTS/BTR/BTC: Bit test (and set/reset/complement)

    // Comparison
    Compare,
    Test,
    /// Set byte on condition (SETcc instructions)
    SetConditional,
    /// Conditional move (CMOVcc instructions)
    ConditionalMove,

    // Control flow
    Jump,
    ConditionalJump,
    Call,
    Return,

    // System
    Syscall,
    Interrupt,
    Nop,
    Halt,

    // Privileged system instructions
    /// Store Global Descriptor Table (SGDT)
    StoreGdt,
    /// Store Interrupt Descriptor Table (SIDT)
    StoreIdt,
    /// Load Global Descriptor Table (LGDT)
    LoadGdt,
    /// Load Interrupt Descriptor Table (LIDT)
    LoadIdt,
    /// Store Machine Status Word (SMSW)
    StoreMsw,
    /// Load Machine Status Word (LMSW)
    LoadMsw,
    /// Invalidate TLB Entry (INVLPG)
    InvalidateTlb,
    /// Read Model Specific Register (RDMSR)
    ReadMsr,
    /// Write Model Specific Register (WRMSR)
    WriteMsr,
    /// CPU Identification (CPUID)
    CpuId,
    /// Read Time Stamp Counter (RDTSC)
    ReadTsc,
    /// Read Time Stamp Counter and Processor ID (RDTSCP)
    ReadTscP,

    // Atomic/Synchronization
    /// Load exclusive (LDXR, LDAXR, etc.)
    LoadExclusive,
    /// Store exclusive (STXR, STLXR, etc.)
    StoreExclusive,
    /// Atomic add (LDADD)
    AtomicAdd,
    /// Atomic clear/AND-NOT (LDCLR)
    AtomicClear,
    /// Atomic XOR (LDEOR)
    AtomicXor,
    /// Atomic set/OR (LDSET)
    AtomicSet,
    /// Atomic signed max (LDSMAX)
    AtomicSignedMax,
    /// Atomic signed min (LDSMIN)
    AtomicSignedMin,
    /// Atomic unsigned max (LDUMAX)
    AtomicUnsignedMax,
    /// Atomic unsigned min (LDUMIN)
    AtomicUnsignedMin,
    /// Atomic swap (SWP)
    AtomicSwap,
    /// Compare and swap (CAS)
    CompareAndSwap,

    // SVE (Scalable Vector Extension) operations
    /// SVE contiguous load (LD1B, LD1H, LD1W, LD1D)
    SveLoad,
    /// SVE contiguous store (ST1B, ST1H, ST1W, ST1D)
    SveStore,
    /// SVE vector add (predicated)
    SveAdd,
    /// SVE vector subtract (predicated)
    SveSub,
    /// SVE vector multiply (predicated)
    SveMul,
    /// SVE logical AND (predicated)
    SveAnd,
    /// SVE logical OR (predicated)
    SveOr,
    /// SVE logical XOR (predicated)
    SveXor,
    /// SVE comparison (CMPEQ, CMPNE, CMPGT, etc.)
    SveCompare,
    /// SVE reduction operations (SADDV, UADDV, etc.)
    SveReduce,
    /// SVE element count (CNTB, CNTH, CNTW, CNTD)
    SveCount,
    /// SVE duplicate/broadcast (DUP)
    SveDup,
    /// SVE permute operations (TBL, ZIP, UZP, TRN)
    SvePermute,
    /// SVE predicate operations (PTRUE, PFALSE, etc.)
    SvePredicate,

    // SVE2 (Scalable Vector Extension 2) operations
    /// SVE2 absolute difference and accumulate (SABA/UABA)
    Sve2AbsDiffAccum,
    /// SVE2 absolute difference accumulate long (SABALB/SABALT/UABALB/UABALT)
    Sve2AbsDiffAccumLong,
    /// SVE2 saturating absolute/negate (SQABS/SQNEG)
    Sve2SatAbsNeg,
    /// SVE2 saturating doubling multiply high (SQDMULH/SQRDMULH)
    Sve2SatDoublingMulHigh,
    /// SVE2 saturating doubling multiply-add long (SQDMLALB/SQDMLALT/SQDMLSLB/SQDMLSLT)
    Sve2SatDoublingMulAddLong,
    /// SVE2 bit manipulation - bit deposit (BDEP)
    Sve2BitDeposit,
    /// SVE2 bit manipulation - bit extract (BEXT)
    Sve2BitExtract,
    /// SVE2 bit manipulation - bit group (BGRP)
    Sve2BitGroup,
    /// SVE2 histogram operations (HISTCNT/HISTSEG)
    Sve2Histogram,
    /// SVE2 pattern matching (MATCH/NMATCH)
    Sve2Match,
    /// SVE2 non-temporal signed loads (LDNT1SB/LDNT1SH/LDNT1SW)
    Sve2NonTempLoad,

    // SVE2 Crypto extensions
    /// SVE2-AES encryption/decryption (AESE/AESD/AESMC/AESIMC)
    Sve2Aes,
    /// SVE2-SHA3 rotation (RAX1)
    Sve2Sha3Rotate,
    /// SVE2-SM4 operations (SM4E/SM4EKEY)
    Sve2Sm4,

    // SME (Scalable Matrix Extension) operations
    /// SME streaming mode start (SMSTART)
    SmeStart,
    /// SME streaming mode stop (SMSTOP)
    SmeStop,
    /// SME zero ZA array (ZERO {ZA})
    SmeZeroZa,
    /// SME load ZA row (LDR ZA[...])
    SmeLoadZa,
    /// SME store ZA row (STR ZA[...])
    SmeStoreZa,
    /// SME move to/from ZA (MOVA)
    SmeMova,
    /// SME FP outer product accumulate (FMOPA)
    SmeFmopa,
    /// SME FP outer product subtract (FMOPS)
    SmeFmops,
    /// SME BFloat16 outer product (BFMOPA/BFMOPS)
    SmeBfmop,
    /// SME signed integer outer product (SMOPA/SMOPS)
    SmeSmop,
    /// SME unsigned integer outer product (UMOPA/UMOPS)
    SmeUmop,
    /// SME signed/unsigned mixed outer product (SUMOPA/USMOPA)
    SmeSumop,

    // AMX (Advanced Matrix Extensions) operations - x86
    /// AMX load tile configuration (LDTILECFG)
    AmxLoadTileConfig,
    /// AMX store tile configuration (STTILECFG)
    AmxStoreTileConfig,
    /// AMX release tile resources (TILERELEASE)
    AmxTileRelease,
    /// AMX zero tile (TILEZERO)
    AmxTileZero,
    /// AMX load tile data (TILELOADD/TILELOADDT1)
    AmxTileLoad,
    /// AMX store tile data (TILESTORED)
    AmxTileStore,
    /// AMX tile dot product signed bytes (TDPBSSD)
    AmxDotProductSS,
    /// AMX tile dot product signed/unsigned bytes (TDPBSUD)
    AmxDotProductSU,
    /// AMX tile dot product unsigned/signed bytes (TDPBUSD)
    AmxDotProductUS,
    /// AMX tile dot product unsigned bytes (TDPBUUD)
    AmxDotProductUU,
    /// AMX FP16 matrix multiply (TDPFP16PS)
    AmxFp16Multiply,

    // CET (Control-flow Enforcement Technology) operations - x86
    /// CET increment shadow stack pointer (INCSSPD/INCSSPQ)
    CetIncSsp,
    /// CET read shadow stack pointer (RDSSPD/RDSSPQ)
    CetReadSsp,
    /// CET save previous shadow stack pointer (SAVEPREVSSP)
    CetSavePrevSsp,
    /// CET restore shadow stack pointer (RSTORSSP)
    CetRestoreSsp,
    /// CET write to shadow stack (WRSSD/WRSSQ)
    CetWriteSs,
    /// CET write to user shadow stack (WRUSSD/WRUSSQ)
    CetWriteUss,
    /// CET end branch 32-bit (ENDBR32)
    CetEndBranch32,
    /// CET end branch 64-bit (ENDBR64)
    CetEndBranch64,

    // RISC-V Floating-Point (F/D extensions)
    /// Floating-point load (FLW, FLD)
    FloatLoad,
    /// Floating-point store (FSW, FSD)
    FloatStore,
    /// Floating-point add (FADD.S, FADD.D)
    FloatAdd,
    /// Floating-point subtract (FSUB.S, FSUB.D)
    FloatSub,
    /// Floating-point multiply (FMUL.S, FMUL.D)
    FloatMul,
    /// Floating-point divide (FDIV.S, FDIV.D)
    FloatDiv,
    /// Floating-point square root (FSQRT.S, FSQRT.D)
    FloatSqrt,
    /// Floating-point min (FMIN.S, FMIN.D)
    FloatMin,
    /// Floating-point max (FMAX.S, FMAX.D)
    FloatMax,
    /// Floating-point fused multiply-add (FMADD.S, FMADD.D)
    FloatMulAdd,
    /// Floating-point fused multiply-sub (FMSUB.S, FMSUB.D)
    FloatMulSub,
    /// Floating-point negated fused multiply-add (FNMADD.S, FNMADD.D)
    FloatNegMulAdd,
    /// Floating-point negated fused multiply-sub (FNMSUB.S, FNMSUB.D)
    FloatNegMulSub,
    /// Floating-point convert (FCVT.W.S, FCVT.S.W, FCVT.D.S, etc.)
    FloatConvert,
    /// Floating-point sign injection (FSGNJ.S, FSGNJN.S, FSGNJX.S)
    FloatSignInject,
    /// Floating-point compare (FEQ.S, FLT.S, FLE.S)
    FloatCompare,
    /// Floating-point classify (FCLASS.S, FCLASS.D)
    FloatClassify,
    /// Floating-point move to/from integer register (FMV.X.W, FMV.W.X)
    FloatMove,

    // RISC-V Vector (V extension)
    /// Vector configuration (VSETVLI, VSETIVLI, VSETVL)
    VectorConfig,
    /// Vector load (VLE8.V, VLE16.V, VLE32.V, VLE64.V)
    VectorLoad,
    /// Vector store (VSE8.V, VSE16.V, VSE32.V, VSE64.V)
    VectorStore,
    /// Vector strided load (VLSE8.V, VLSE16.V, etc.)
    VectorStridedLoad,
    /// Vector strided store (VSSE8.V, VSSE16.V, etc.)
    VectorStridedStore,
    /// Vector indexed load (VLUXEI, VLOXEI)
    VectorIndexedLoad,
    /// Vector indexed store (VSUXEI, VSOXEI)
    VectorIndexedStore,
    /// Vector add (VADD.VV, VADD.VX, VADD.VI)
    VectorAdd,
    /// Vector subtract (VSUB.VV, VSUB.VX)
    VectorSub,
    /// Vector multiply (VMUL.VV, VMUL.VX)
    VectorMul,
    /// Vector divide (VDIV.VV, VDIV.VX, VDIVU.VV, VDIVU.VX)
    VectorDiv,
    /// Vector remainder (VREM.VV, VREM.VX, VREMU.VV, VREMU.VX)
    VectorRem,
    /// Vector and (VAND.VV, VAND.VX, VAND.VI)
    VectorAnd,
    /// Vector or (VOR.VV, VOR.VX, VOR.VI)
    VectorOr,
    /// Vector xor (VXOR.VV, VXOR.VX, VXOR.VI)
    VectorXor,
    /// Vector shift left (VSLL.VV, VSLL.VX, VSLL.VI)
    VectorShl,
    /// Vector shift right logical (VSRL.VV, VSRL.VX, VSRL.VI)
    VectorShr,
    /// Vector shift right arithmetic (VSRA.VV, VSRA.VX, VSRA.VI)
    VectorSar,
    /// Vector compare set mask (VMSEQ, VMSNE, VMSLT, VMSLE, VMSGT, VMSGE)
    VectorCompare,
    /// Vector min (VMIN.VV, VMIN.VX, VMINU.VV, VMINU.VX)
    VectorMin,
    /// Vector max (VMAX.VV, VMAX.VX, VMAXU.VV, VMAXU.VX)
    VectorMax,
    /// Vector merge/move (VMERGE, VMV)
    VectorMerge,
    /// Vector mask operations (VMAND, VMNAND, VMOR, VMNOR, VMXOR, etc.)
    VectorMask,
    /// Vector reduction (VREDSUM, VREDMAX, VREDMIN, etc.)
    VectorReduce,
    /// Vector floating-point add (VFADD.VV, VFADD.VF)
    VectorFloatAdd,
    /// Vector floating-point subtract (VFSUB.VV, VFSUB.VF)
    VectorFloatSub,
    /// Vector floating-point multiply (VFMUL.VV, VFMUL.VF)
    VectorFloatMul,
    /// Vector floating-point divide (VFDIV.VV, VFDIV.VF)
    VectorFloatDiv,
    /// Vector floating-point fused multiply-add (VFMADD, VFNMADD, VFMSUB, VFNMSUB)
    VectorFloatMulAdd,
    /// Vector widening operations
    VectorWiden,
    /// Vector narrowing operations
    VectorNarrow,
    /// Vector slide (VSLIDEUP, VSLIDEDOWN, VSLIDE1UP, VSLIDE1DOWN)
    VectorSlide,
    /// Vector gather (VRGATHER, VRGATHEREI16)
    VectorGather,
    /// Vector compress (VCOMPRESS)
    VectorCompress,

    // x87 FPU operations (legacy floating-point)
    /// x87 FPU load (FLD, FILD)
    X87Load,
    /// x87 FPU store (FST, FSTP, FIST, FISTP)
    X87Store,
    /// x87 FPU add (FADD, FADDP, FIADD)
    X87Add,
    /// x87 FPU subtract (FSUB, FSUBP, FSUBR, FSUBRP, FISUB, FISUBR)
    X87Sub,
    /// x87 FPU multiply (FMUL, FMULP, FIMUL)
    X87Mul,
    /// x87 FPU divide (FDIV, FDIVP, FDIVR, FDIVRP, FIDIV, FIDIVR)
    X87Div,
    /// x87 FPU compare (FCOM, FCOMP, FCOMPP, FCOMI, FCOMIP, FUCOMI, FUCOMIP, FTST, FXAM, FICOM, FICOMP)
    X87Compare,
    /// x87 FPU transcendental (FSIN, FCOS, FSINCOS, FPTAN, FPATAN, F2XM1, FYL2X, FYL2XP1)
    X87Transcendental,
    /// x87 FPU misc (FABS, FCHS, FSQRT, FRNDINT, FSCALE, FXTRACT, FPREM, FPREM1)
    X87Misc,
    /// x87 FPU control (FLDCW, FSTCW, FNSTCW, FLDENV, FSTENV, FSAVE, FRSTOR, FINIT, FNINIT, FCLEX, FNCLEX, FWAIT)
    X87Control,
    /// x87 FPU stack (FXCH, FFREE, FINCSTP, FDECSTP, FLD1, FLDZ, FLDPI, FLDL2E, FLDL2T, FLDLG2, FLDLN2)
    X87Stack,

    // Other
    Other(u16),
}

impl Operation {
    /// Returns the name of this operation.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Move => "move",
            Self::Load => "load",
            Self::Store => "store",
            Self::Push => "push",
            Self::Pop => "pop",
            Self::Exchange => "exchange",
            Self::LoadEffectiveAddress => "lea",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Neg => "neg",
            Self::Inc => "inc",
            Self::Dec => "dec",
            Self::SignExtend => "sign_extend",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::Shl => "shl",
            Self::Shr => "shr",
            Self::Sar => "sar",
            Self::Rol => "rol",
            Self::Ror => "ror",
            Self::Popcnt => "popcnt",
            Self::Lzcnt => "lzcnt",
            Self::Tzcnt => "tzcnt",
            Self::AndNot => "andnot",
            Self::BitExtract => "bit_extract",
            Self::ExtractLowestBit => "extract_lowest_bit",
            Self::MaskUpToLowest => "mask_up_to_lowest",
            Self::ResetLowestBit => "reset_lowest_bit",
            Self::ZeroHighBits => "zero_high_bits",
            Self::ParallelDeposit => "parallel_deposit",
            Self::ParallelExtract => "parallel_extract",
            Self::MulNoFlags => "mul_no_flags",
            Self::BitTest => "bit_test",
            Self::Compare => "compare",
            Self::Test => "test",
            Self::Jump => "jump",
            Self::ConditionalJump => "cond_jump",
            Self::Call => "call",
            Self::Return => "return",
            Self::Syscall => "syscall",
            Self::Interrupt => "interrupt",
            Self::Nop => "nop",
            Self::Halt => "halt",
            Self::StoreGdt => "store_gdt",
            Self::StoreIdt => "store_idt",
            Self::LoadGdt => "load_gdt",
            Self::LoadIdt => "load_idt",
            Self::StoreMsw => "store_msw",
            Self::LoadMsw => "load_msw",
            Self::InvalidateTlb => "invalidate_tlb",
            Self::ReadMsr => "read_msr",
            Self::WriteMsr => "write_msr",
            Self::CpuId => "cpuid",
            Self::ReadTsc => "read_tsc",
            Self::ReadTscP => "read_tsc_p",
            Self::LoadExclusive => "load_exclusive",
            Self::StoreExclusive => "store_exclusive",
            Self::AtomicAdd => "atomic_add",
            Self::AtomicClear => "atomic_clear",
            Self::AtomicXor => "atomic_xor",
            Self::AtomicSet => "atomic_set",
            Self::AtomicSignedMax => "atomic_smax",
            Self::AtomicSignedMin => "atomic_smin",
            Self::AtomicUnsignedMax => "atomic_umax",
            Self::AtomicUnsignedMin => "atomic_umin",
            Self::AtomicSwap => "atomic_swap",
            Self::CompareAndSwap => "compare_and_swap",
            Self::SveLoad => "sve_load",
            Self::SveStore => "sve_store",
            Self::SveAdd => "sve_add",
            Self::SveSub => "sve_sub",
            Self::SveMul => "sve_mul",
            Self::SveAnd => "sve_and",
            Self::SveOr => "sve_or",
            Self::SveXor => "sve_xor",
            Self::SveCompare => "sve_compare",
            Self::SveReduce => "sve_reduce",
            Self::SveCount => "sve_count",
            Self::SveDup => "sve_dup",
            Self::SvePermute => "sve_permute",
            Self::SvePredicate => "sve_predicate",
            // SVE2 operations
            Self::Sve2AbsDiffAccum => "sve2_abs_diff_accum",
            Self::Sve2AbsDiffAccumLong => "sve2_abs_diff_accum_long",
            Self::Sve2SatAbsNeg => "sve2_sat_abs_neg",
            Self::Sve2SatDoublingMulHigh => "sve2_sat_doubling_mul_high",
            Self::Sve2SatDoublingMulAddLong => "sve2_sat_doubling_mul_add_long",
            Self::Sve2BitDeposit => "sve2_bit_deposit",
            Self::Sve2BitExtract => "sve2_bit_extract",
            Self::Sve2BitGroup => "sve2_bit_group",
            Self::Sve2Histogram => "sve2_histogram",
            Self::Sve2Match => "sve2_match",
            Self::Sve2NonTempLoad => "sve2_non_temp_load",
            Self::Sve2Aes => "sve2_aes",
            Self::Sve2Sha3Rotate => "sve2_sha3_rotate",
            Self::Sve2Sm4 => "sve2_sm4",
            // SME operations
            Self::SmeStart => "sme_start",
            Self::SmeStop => "sme_stop",
            Self::SmeZeroZa => "sme_zero_za",
            Self::SmeLoadZa => "sme_load_za",
            Self::SmeStoreZa => "sme_store_za",
            Self::SmeMova => "sme_mova",
            Self::SmeFmopa => "sme_fmopa",
            Self::SmeFmops => "sme_fmops",
            Self::SmeBfmop => "sme_bfmop",
            Self::SmeSmop => "sme_smop",
            Self::SmeUmop => "sme_umop",
            Self::SmeSumop => "sme_sumop",
            // AMX operations
            Self::AmxLoadTileConfig => "amx_load_tile_config",
            Self::AmxStoreTileConfig => "amx_store_tile_config",
            Self::AmxTileRelease => "amx_tile_release",
            Self::AmxTileZero => "amx_tile_zero",
            Self::AmxTileLoad => "amx_tile_load",
            Self::AmxTileStore => "amx_tile_store",
            Self::AmxDotProductSS => "amx_dot_product_ss",
            Self::AmxDotProductSU => "amx_dot_product_su",
            Self::AmxDotProductUS => "amx_dot_product_us",
            Self::AmxDotProductUU => "amx_dot_product_uu",
            Self::AmxFp16Multiply => "amx_fp16_multiply",
            // CET operations
            Self::CetIncSsp => "cet_inc_ssp",
            Self::CetReadSsp => "cet_read_ssp",
            Self::CetSavePrevSsp => "cet_save_prev_ssp",
            Self::CetRestoreSsp => "cet_restore_ssp",
            Self::CetWriteSs => "cet_write_ss",
            Self::CetWriteUss => "cet_write_uss",
            Self::CetEndBranch32 => "cet_endbr32",
            Self::CetEndBranch64 => "cet_endbr64",
            // RISC-V floating-point operations
            Self::FloatLoad => "float_load",
            Self::FloatStore => "float_store",
            Self::FloatAdd => "float_add",
            Self::FloatSub => "float_sub",
            Self::FloatMul => "float_mul",
            Self::FloatDiv => "float_div",
            Self::FloatSqrt => "float_sqrt",
            Self::FloatMin => "float_min",
            Self::FloatMax => "float_max",
            Self::FloatMulAdd => "float_mul_add",
            Self::FloatMulSub => "float_mul_sub",
            Self::FloatNegMulAdd => "float_neg_mul_add",
            Self::FloatNegMulSub => "float_neg_mul_sub",
            Self::FloatConvert => "float_convert",
            Self::FloatSignInject => "float_sign_inject",
            Self::FloatCompare => "float_compare",
            Self::FloatClassify => "float_classify",
            Self::FloatMove => "float_move",
            // RISC-V vector operations
            Self::VectorConfig => "vector_config",
            Self::VectorLoad => "vector_load",
            Self::VectorStore => "vector_store",
            Self::VectorStridedLoad => "vector_strided_load",
            Self::VectorStridedStore => "vector_strided_store",
            Self::VectorIndexedLoad => "vector_indexed_load",
            Self::VectorIndexedStore => "vector_indexed_store",
            Self::VectorAdd => "vector_add",
            Self::VectorSub => "vector_sub",
            Self::VectorMul => "vector_mul",
            Self::VectorDiv => "vector_div",
            Self::VectorRem => "vector_rem",
            Self::VectorAnd => "vector_and",
            Self::VectorOr => "vector_or",
            Self::VectorXor => "vector_xor",
            Self::VectorShl => "vector_shl",
            Self::VectorShr => "vector_shr",
            Self::VectorSar => "vector_sar",
            Self::VectorCompare => "vector_compare",
            Self::VectorMin => "vector_min",
            Self::VectorMax => "vector_max",
            Self::VectorMerge => "vector_merge",
            Self::VectorMask => "vector_mask",
            Self::VectorReduce => "vector_reduce",
            Self::VectorFloatAdd => "vector_float_add",
            Self::VectorFloatSub => "vector_float_sub",
            Self::VectorFloatMul => "vector_float_mul",
            Self::VectorFloatDiv => "vector_float_div",
            Self::VectorFloatMulAdd => "vector_float_mul_add",
            Self::VectorWiden => "vector_widen",
            Self::VectorNarrow => "vector_narrow",
            Self::VectorSlide => "vector_slide",
            Self::VectorGather => "vector_gather",
            Self::VectorCompress => "vector_compress",
            Self::SetConditional => "set_conditional",
            Self::ConditionalMove => "conditional_move",
            // x87 FPU operations
            Self::X87Load => "x87_load",
            Self::X87Store => "x87_store",
            Self::X87Add => "x87_add",
            Self::X87Sub => "x87_sub",
            Self::X87Mul => "x87_mul",
            Self::X87Div => "x87_div",
            Self::X87Compare => "x87_compare",
            Self::X87Transcendental => "x87_transcendental",
            Self::X87Misc => "x87_misc",
            Self::X87Control => "x87_control",
            Self::X87Stack => "x87_stack",
            Self::Other(_) => "other",
        }
    }
}

/// Branch condition for conditional jumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Condition {
    // Unsigned comparisons
    Equal,
    NotEqual,
    Above,        // CF=0 and ZF=0
    AboveOrEqual, // CF=0
    Below,        // CF=1
    BelowOrEqual, // CF=1 or ZF=1

    // Signed comparisons
    Greater,        // ZF=0 and SF=OF
    GreaterOrEqual, // SF=OF
    Less,           // SF!=OF
    LessOrEqual,    // ZF=1 or SF!=OF

    // Flag-based
    Sign,        // SF=1
    NotSign,     // SF=0
    Overflow,    // OF=1
    NotOverflow, // OF=0
    Parity,      // PF=1
    NotParity,   // PF=0

    // Counter-based (x86)
    CounterZero,
    CounterNotZero,
}

impl Condition {
    /// Returns the inverse condition.
    pub fn inverse(&self) -> Self {
        match self {
            Self::Equal => Self::NotEqual,
            Self::NotEqual => Self::Equal,
            Self::Above => Self::BelowOrEqual,
            Self::AboveOrEqual => Self::Below,
            Self::Below => Self::AboveOrEqual,
            Self::BelowOrEqual => Self::Above,
            Self::Greater => Self::LessOrEqual,
            Self::GreaterOrEqual => Self::Less,
            Self::Less => Self::GreaterOrEqual,
            Self::LessOrEqual => Self::Greater,
            Self::Sign => Self::NotSign,
            Self::NotSign => Self::Sign,
            Self::Overflow => Self::NotOverflow,
            Self::NotOverflow => Self::Overflow,
            Self::Parity => Self::NotParity,
            Self::NotParity => Self::Parity,
            Self::CounterZero => Self::CounterNotZero,
            Self::CounterNotZero => Self::CounterZero,
        }
    }

    /// Returns the x86 mnemonic suffix for this condition.
    pub fn x86_suffix(&self) -> &'static str {
        match self {
            Self::Equal => "e",
            Self::NotEqual => "ne",
            Self::Above => "a",
            Self::AboveOrEqual => "ae",
            Self::Below => "b",
            Self::BelowOrEqual => "be",
            Self::Greater => "g",
            Self::GreaterOrEqual => "ge",
            Self::Less => "l",
            Self::LessOrEqual => "le",
            Self::Sign => "s",
            Self::NotSign => "ns",
            Self::Overflow => "o",
            Self::NotOverflow => "no",
            Self::Parity => "p",
            Self::NotParity => "np",
            Self::CounterZero => "cxz",
            Self::CounterNotZero => "ecxz",
        }
    }
}

/// Control flow classification.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ControlFlow {
    /// Sequential - falls through to next instruction.
    Sequential,

    /// Unconditional branch to a known address.
    UnconditionalBranch { target: u64 },

    /// Conditional branch - may fall through or jump.
    ConditionalBranch {
        target: u64,
        condition: Condition,
        fallthrough: u64,
    },

    /// Indirect jump (target in register or memory).
    IndirectBranch {
        /// Possible targets if known (from jump tables, etc.).
        possible_targets: Vec<u64>,
    },

    /// Function call to known address.
    Call { target: u64, return_addr: u64 },

    /// Indirect call.
    IndirectCall { return_addr: u64 },

    /// Return from function.
    Return,

    /// System call.
    Syscall,

    /// Halts execution (trap, undefined, etc.).
    Halt,
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#010x}:  ", self.address)?;

        // Print bytes
        for byte in &self.bytes {
            write!(f, "{:02x} ", byte)?;
        }

        // Pad to align mnemonic
        for _ in self.bytes.len()..8 {
            write!(f, "   ")?;
        }

        // Print mnemonic and operands
        write!(f, " {}", self.mnemonic)?;

        if !self.operands.is_empty() {
            write!(f, " ")?;
            for (i, op) in self.operands.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", op)?;
            }
        }

        Ok(())
    }
}
