//! x87 FPU instruction decoding.
//!
//! x87 FPU instructions use escape opcodes 0xD8-0xDF.
//! The encoding depends on both the escape byte and the ModR/M byte:
//! - When ModR/M < 0xC0: memory operand, reg field (bits 5:3) selects the instruction
//! - When ModR/M >= 0xC0: register operand ST(i), different instruction table

use hexray_core::Operation;

/// x87 instruction info
#[derive(Clone, Copy)]
pub struct X87Entry {
    pub mnemonic: &'static str,
    pub operation: Operation,
    /// Number of operands (0, 1, or 2)
    pub operand_count: u8,
    /// For memory ops: operand size (32, 64, 80 bits for floats; 16, 32, 64 for ints)
    #[allow(dead_code)]
    pub mem_size: u8,
    /// Is this a pop instruction (FSTP, FISTP, etc.)
    #[allow(dead_code)]
    pub is_pop: bool,
}

impl X87Entry {
    const fn new(mnemonic: &'static str, operation: Operation) -> Self {
        Self {
            mnemonic,
            operation,
            operand_count: 0,
            mem_size: 0,
            is_pop: false,
        }
    }

    const fn mem(mnemonic: &'static str, operation: Operation, size: u8) -> Self {
        Self {
            mnemonic,
            operation,
            operand_count: 1,
            mem_size: size,
            is_pop: false,
        }
    }

    const fn mem_pop(mnemonic: &'static str, operation: Operation, size: u8) -> Self {
        Self {
            mnemonic,
            operation,
            operand_count: 1,
            mem_size: size,
            is_pop: true,
        }
    }

    const fn reg(mnemonic: &'static str, operation: Operation) -> Self {
        Self {
            mnemonic,
            operation,
            operand_count: 1,
            mem_size: 0,
            is_pop: false,
        }
    }

    const fn reg2(mnemonic: &'static str, operation: Operation) -> Self {
        Self {
            mnemonic,
            operation,
            operand_count: 2,
            mem_size: 0,
            is_pop: false,
        }
    }
}

// ============================================================================
// D8: float32 memory ops (ModR/M < 0xC0) and ST(0), ST(i) ops (ModR/M >= 0xC0)
// ============================================================================

/// D8 /r with memory operand (ModR/M < 0xC0): single-precision (32-bit) memory ops
pub static X87_D8_MEM: [X87Entry; 8] = [
    X87Entry::mem("fadd", Operation::X87Add, 32), // /0: FADD m32fp
    X87Entry::mem("fmul", Operation::X87Mul, 32), // /1: FMUL m32fp
    X87Entry::mem("fcom", Operation::X87Compare, 32), // /2: FCOM m32fp
    X87Entry::mem_pop("fcomp", Operation::X87Compare, 32), // /3: FCOMP m32fp
    X87Entry::mem("fsub", Operation::X87Sub, 32), // /4: FSUB m32fp
    X87Entry::mem("fsubr", Operation::X87Sub, 32), // /5: FSUBR m32fp
    X87Entry::mem("fdiv", Operation::X87Div, 32), // /6: FDIV m32fp
    X87Entry::mem("fdivr", Operation::X87Div, 32), // /7: FDIVR m32fp
];

/// D8 with register operand (ModR/M >= 0xC0): FADD/FMUL/etc ST(0), ST(i)
/// Range: D8 C0 - D8 FF (64 entries for 8 instructions × 8 registers)
pub static X87_D8_REG: [X87Entry; 64] = {
    let mut table = [X87Entry::new("", Operation::Other(0)); 64];
    let mut i = 0;
    while i < 8 {
        // C0-C7: FADD ST(0), ST(i)
        table[i] = X87Entry::reg2("fadd", Operation::X87Add);
        // C8-CF: FMUL ST(0), ST(i)
        table[0x08 + i] = X87Entry::reg2("fmul", Operation::X87Mul);
        // D0-D7: FCOM ST(i)
        table[0x10 + i] = X87Entry::reg("fcom", Operation::X87Compare);
        // D8-DF: FCOMP ST(i)
        table[0x18 + i] = X87Entry::reg("fcomp", Operation::X87Compare);
        // E0-E7: FSUB ST(0), ST(i)
        table[0x20 + i] = X87Entry::reg2("fsub", Operation::X87Sub);
        // E8-EF: FSUBR ST(0), ST(i)
        table[0x28 + i] = X87Entry::reg2("fsubr", Operation::X87Sub);
        // F0-F7: FDIV ST(0), ST(i)
        table[0x30 + i] = X87Entry::reg2("fdiv", Operation::X87Div);
        // F8-FF: FDIVR ST(0), ST(i)
        table[0x38 + i] = X87Entry::reg2("fdivr", Operation::X87Div);
        i += 1;
    }
    table
};

// ============================================================================
// D9: misc float ops (load, store, control, transcendental)
// ============================================================================

/// D9 /r with memory operand (ModR/M < 0xC0)
pub static X87_D9_MEM: [X87Entry; 8] = [
    X87Entry::mem("fld", Operation::X87Load, 32), // /0: FLD m32fp
    X87Entry::new("", Operation::Other(0)),       // /1: (reserved)
    X87Entry::mem("fst", Operation::X87Store, 32), // /2: FST m32fp
    X87Entry::mem_pop("fstp", Operation::X87Store, 32), // /3: FSTP m32fp
    X87Entry::mem("fldenv", Operation::X87Control, 0), // /4: FLDENV m14/28byte
    X87Entry::mem("fldcw", Operation::X87Control, 16), // /5: FLDCW m2byte
    X87Entry::mem("fnstenv", Operation::X87Control, 0), // /6: FNSTENV m14/28byte
    X87Entry::mem("fnstcw", Operation::X87Control, 16), // /7: FNSTCW m2byte
];

/// D9 with register operand (ModR/M >= 0xC0)
/// This range has a mix of register ops and special instructions
pub fn lookup_d9_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FLD ST(i) - push ST(i) onto stack
        0xC0..=0xC7 => Some(X87Entry::reg("fld", Operation::X87Load)),
        // C8-CF: FXCH ST(i)
        0xC8..=0xCF => Some(X87Entry::reg("fxch", Operation::X87Stack)),
        // D0: FNOP
        0xD0 => Some(X87Entry::new("fnop", Operation::Nop)),
        // D8-DF: FSTP ST(i) - some sources say this is also FSTP1
        0xD8..=0xDF => Some(X87Entry::reg("fstp", Operation::X87Store)),
        // E0: FCHS - change sign
        0xE0 => Some(X87Entry::new("fchs", Operation::X87Misc)),
        // E1: FABS - absolute value
        0xE1 => Some(X87Entry::new("fabs", Operation::X87Misc)),
        // E4: FTST - compare ST(0) with 0.0
        0xE4 => Some(X87Entry::new("ftst", Operation::X87Compare)),
        // E5: FXAM - examine ST(0)
        0xE5 => Some(X87Entry::new("fxam", Operation::X87Compare)),
        // E8: FLD1 - push +1.0
        0xE8 => Some(X87Entry::new("fld1", Operation::X87Stack)),
        // E9: FLDL2T - push log2(10)
        0xE9 => Some(X87Entry::new("fldl2t", Operation::X87Stack)),
        // EA: FLDL2E - push log2(e)
        0xEA => Some(X87Entry::new("fldl2e", Operation::X87Stack)),
        // EB: FLDPI - push pi
        0xEB => Some(X87Entry::new("fldpi", Operation::X87Stack)),
        // EC: FLDLG2 - push log10(2)
        0xEC => Some(X87Entry::new("fldlg2", Operation::X87Stack)),
        // ED: FLDLN2 - push ln(2)
        0xED => Some(X87Entry::new("fldln2", Operation::X87Stack)),
        // EE: FLDZ - push +0.0
        0xEE => Some(X87Entry::new("fldz", Operation::X87Stack)),
        // F0: F2XM1 - compute 2^x - 1
        0xF0 => Some(X87Entry::new("f2xm1", Operation::X87Transcendental)),
        // F1: FYL2X - compute y * log2(x)
        0xF1 => Some(X87Entry::new("fyl2x", Operation::X87Transcendental)),
        // F2: FPTAN - compute partial tangent
        0xF2 => Some(X87Entry::new("fptan", Operation::X87Transcendental)),
        // F3: FPATAN - compute partial arctangent
        0xF3 => Some(X87Entry::new("fpatan", Operation::X87Transcendental)),
        // F4: FXTRACT - extract exponent and significand
        0xF4 => Some(X87Entry::new("fxtract", Operation::X87Misc)),
        // F5: FPREM1 - IEEE partial remainder
        0xF5 => Some(X87Entry::new("fprem1", Operation::X87Misc)),
        // F6: FDECSTP - decrement stack pointer
        0xF6 => Some(X87Entry::new("fdecstp", Operation::X87Stack)),
        // F7: FINCSTP - increment stack pointer
        0xF7 => Some(X87Entry::new("fincstp", Operation::X87Stack)),
        // F8: FPREM - partial remainder (non-IEEE)
        0xF8 => Some(X87Entry::new("fprem", Operation::X87Misc)),
        // F9: FYL2XP1 - compute y * log2(x + 1)
        0xF9 => Some(X87Entry::new("fyl2xp1", Operation::X87Transcendental)),
        // FA: FSQRT - square root
        0xFA => Some(X87Entry::new("fsqrt", Operation::X87Misc)),
        // FB: FSINCOS - compute sine and cosine
        0xFB => Some(X87Entry::new("fsincos", Operation::X87Transcendental)),
        // FC: FRNDINT - round to integer
        0xFC => Some(X87Entry::new("frndint", Operation::X87Misc)),
        // FD: FSCALE - scale by power of 2
        0xFD => Some(X87Entry::new("fscale", Operation::X87Misc)),
        // FE: FSIN - sine
        0xFE => Some(X87Entry::new("fsin", Operation::X87Transcendental)),
        // FF: FCOS - cosine
        0xFF => Some(X87Entry::new("fcos", Operation::X87Transcendental)),
        _ => None,
    }
}

// ============================================================================
// DA: int32 memory ops and conditional move
// ============================================================================

/// DA /r with memory operand (ModR/M < 0xC0): 32-bit integer memory ops
pub static X87_DA_MEM: [X87Entry; 8] = [
    X87Entry::mem("fiadd", Operation::X87Add, 32), // /0: FIADD m32int
    X87Entry::mem("fimul", Operation::X87Mul, 32), // /1: FIMUL m32int
    X87Entry::mem("ficom", Operation::X87Compare, 32), // /2: FICOM m32int
    X87Entry::mem_pop("ficomp", Operation::X87Compare, 32), // /3: FICOMP m32int
    X87Entry::mem("fisub", Operation::X87Sub, 32), // /4: FISUB m32int
    X87Entry::mem("fisubr", Operation::X87Sub, 32), // /5: FISUBR m32int
    X87Entry::mem("fidiv", Operation::X87Div, 32), // /6: FIDIV m32int
    X87Entry::mem("fidivr", Operation::X87Div, 32), // /7: FIDIVR m32int
];

/// DA with register operand (ModR/M >= 0xC0): FCMOV instructions
pub fn lookup_da_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FCMOVB ST(0), ST(i) - move if below
        0xC0..=0xC7 => Some(X87Entry::reg2("fcmovb", Operation::X87Stack)),
        // C8-CF: FCMOVE ST(0), ST(i) - move if equal
        0xC8..=0xCF => Some(X87Entry::reg2("fcmove", Operation::X87Stack)),
        // D0-D7: FCMOVBE ST(0), ST(i) - move if below or equal
        0xD0..=0xD7 => Some(X87Entry::reg2("fcmovbe", Operation::X87Stack)),
        // D8-DF: FCMOVU ST(0), ST(i) - move if unordered
        0xD8..=0xDF => Some(X87Entry::reg2("fcmovu", Operation::X87Stack)),
        // E9: FUCOMPP - unordered compare and pop twice
        0xE9 => Some(X87Entry::new("fucompp", Operation::X87Compare)),
        _ => None,
    }
}

// ============================================================================
// DB: misc (load/store int, conditional move, compare)
// ============================================================================

/// DB /r with memory operand (ModR/M < 0xC0)
pub static X87_DB_MEM: [X87Entry; 8] = [
    X87Entry::mem("fild", Operation::X87Load, 32), // /0: FILD m32int
    X87Entry::mem_pop("fisttp", Operation::X87Store, 32), // /1: FISTTP m32int
    X87Entry::mem("fist", Operation::X87Store, 32), // /2: FIST m32int
    X87Entry::mem_pop("fistp", Operation::X87Store, 32), // /3: FISTP m32int
    X87Entry::new("", Operation::Other(0)),        // /4: (reserved)
    X87Entry::mem("fld", Operation::X87Load, 80),  // /5: FLD m80fp (extended precision)
    X87Entry::new("", Operation::Other(0)),        // /6: (reserved)
    X87Entry::mem_pop("fstp", Operation::X87Store, 80), // /7: FSTP m80fp
];

/// DB with register operand (ModR/M >= 0xC0)
pub fn lookup_db_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FCMOVNB ST(0), ST(i) - move if not below
        0xC0..=0xC7 => Some(X87Entry::reg2("fcmovnb", Operation::X87Stack)),
        // C8-CF: FCMOVNE ST(0), ST(i) - move if not equal
        0xC8..=0xCF => Some(X87Entry::reg2("fcmovne", Operation::X87Stack)),
        // D0-D7: FCMOVNBE ST(0), ST(i) - move if not below or equal
        0xD0..=0xD7 => Some(X87Entry::reg2("fcmovnbe", Operation::X87Stack)),
        // D8-DF: FCMOVNU ST(0), ST(i) - move if not unordered
        0xD8..=0xDF => Some(X87Entry::reg2("fcmovnu", Operation::X87Stack)),
        // E2: FNCLEX - clear exceptions (no wait)
        0xE2 => Some(X87Entry::new("fnclex", Operation::X87Control)),
        // E3: FNINIT - initialize FPU (no wait)
        0xE3 => Some(X87Entry::new("fninit", Operation::X87Control)),
        // E8-EF: FUCOMI ST(0), ST(i) - unordered compare (sets EFLAGS)
        0xE8..=0xEF => Some(X87Entry::reg2("fucomi", Operation::X87Compare)),
        // F0-F7: FCOMI ST(0), ST(i) - compare (sets EFLAGS)
        0xF0..=0xF7 => Some(X87Entry::reg2("fcomi", Operation::X87Compare)),
        _ => None,
    }
}

// ============================================================================
// DC: float64 memory ops and register arithmetic
// ============================================================================

/// DC /r with memory operand (ModR/M < 0xC0): double-precision (64-bit) memory ops
pub static X87_DC_MEM: [X87Entry; 8] = [
    X87Entry::mem("fadd", Operation::X87Add, 64), // /0: FADD m64fp
    X87Entry::mem("fmul", Operation::X87Mul, 64), // /1: FMUL m64fp
    X87Entry::mem("fcom", Operation::X87Compare, 64), // /2: FCOM m64fp
    X87Entry::mem_pop("fcomp", Operation::X87Compare, 64), // /3: FCOMP m64fp
    X87Entry::mem("fsub", Operation::X87Sub, 64), // /4: FSUB m64fp
    X87Entry::mem("fsubr", Operation::X87Sub, 64), // /5: FSUBR m64fp
    X87Entry::mem("fdiv", Operation::X87Div, 64), // /6: FDIV m64fp
    X87Entry::mem("fdivr", Operation::X87Div, 64), // /7: FDIVR m64fp
];

/// DC with register operand (ModR/M >= 0xC0): ST(i), ST(0) arithmetic
pub static X87_DC_REG: [X87Entry; 64] = {
    let mut table = [X87Entry::new("", Operation::Other(0)); 64];
    let mut i = 0;
    while i < 8 {
        // C0-C7: FADD ST(i), ST(0)
        table[i] = X87Entry::reg2("fadd", Operation::X87Add);
        // C8-CF: FMUL ST(i), ST(0)
        table[0x08 + i] = X87Entry::reg2("fmul", Operation::X87Mul);
        // D0-D7: FCOM ST(i) (same as D8)
        table[0x10 + i] = X87Entry::reg("fcom", Operation::X87Compare);
        // D8-DF: FCOMP ST(i)
        table[0x18 + i] = X87Entry::reg("fcomp", Operation::X87Compare);
        // E0-E7: FSUBR ST(i), ST(0) (note: reversed from D8)
        table[0x20 + i] = X87Entry::reg2("fsubr", Operation::X87Sub);
        // E8-EF: FSUB ST(i), ST(0)
        table[0x28 + i] = X87Entry::reg2("fsub", Operation::X87Sub);
        // F0-F7: FDIVR ST(i), ST(0) (note: reversed from D8)
        table[0x30 + i] = X87Entry::reg2("fdivr", Operation::X87Div);
        // F8-FF: FDIV ST(i), ST(0)
        table[0x38 + i] = X87Entry::reg2("fdiv", Operation::X87Div);
        i += 1;
    }
    table
};

// ============================================================================
// DD: float64 load/store and control
// ============================================================================

/// DD /r with memory operand (ModR/M < 0xC0)
pub static X87_DD_MEM: [X87Entry; 8] = [
    X87Entry::mem("fld", Operation::X87Load, 64), // /0: FLD m64fp
    X87Entry::mem_pop("fisttp", Operation::X87Store, 64), // /1: FISTTP m64int
    X87Entry::mem("fst", Operation::X87Store, 64), // /2: FST m64fp
    X87Entry::mem_pop("fstp", Operation::X87Store, 64), // /3: FSTP m64fp
    X87Entry::mem("frstor", Operation::X87Control, 0), // /4: FRSTOR m94/108byte
    X87Entry::new("", Operation::Other(0)),       // /5: (reserved)
    X87Entry::mem("fnsave", Operation::X87Control, 0), // /6: FNSAVE m94/108byte
    X87Entry::mem("fnstsw", Operation::X87Control, 16), // /7: FNSTSW m2byte
];

/// DD with register operand (ModR/M >= 0xC0)
pub fn lookup_dd_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FFREE ST(i)
        0xC0..=0xC7 => Some(X87Entry::reg("ffree", Operation::X87Stack)),
        // D0-D7: FST ST(i)
        0xD0..=0xD7 => Some(X87Entry::reg("fst", Operation::X87Store)),
        // D8-DF: FSTP ST(i)
        0xD8..=0xDF => Some(X87Entry::reg("fstp", Operation::X87Store)),
        // E0-E7: FUCOM ST(i)
        0xE0..=0xE7 => Some(X87Entry::reg("fucom", Operation::X87Compare)),
        // E8-EF: FUCOMP ST(i)
        0xE8..=0xEF => Some(X87Entry::reg("fucomp", Operation::X87Compare)),
        _ => None,
    }
}

// ============================================================================
// DE: int16 memory ops and pop arithmetic
// ============================================================================

/// DE /r with memory operand (ModR/M < 0xC0): 16-bit integer memory ops
pub static X87_DE_MEM: [X87Entry; 8] = [
    X87Entry::mem("fiadd", Operation::X87Add, 16), // /0: FIADD m16int
    X87Entry::mem("fimul", Operation::X87Mul, 16), // /1: FIMUL m16int
    X87Entry::mem("ficom", Operation::X87Compare, 16), // /2: FICOM m16int
    X87Entry::mem_pop("ficomp", Operation::X87Compare, 16), // /3: FICOMP m16int
    X87Entry::mem("fisub", Operation::X87Sub, 16), // /4: FISUB m16int
    X87Entry::mem("fisubr", Operation::X87Sub, 16), // /5: FISUBR m16int
    X87Entry::mem("fidiv", Operation::X87Div, 16), // /6: FIDIV m16int
    X87Entry::mem("fidivr", Operation::X87Div, 16), // /7: FIDIVR m16int
];

/// DE with register operand (ModR/M >= 0xC0): arithmetic with pop
pub fn lookup_de_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FADDP ST(i), ST(0)
        0xC0..=0xC7 => Some(X87Entry::reg2("faddp", Operation::X87Add)),
        // C8-CF: FMULP ST(i), ST(0)
        0xC8..=0xCF => Some(X87Entry::reg2("fmulp", Operation::X87Mul)),
        // D9: FCOMPP - compare and pop twice
        0xD9 => Some(X87Entry::new("fcompp", Operation::X87Compare)),
        // E0-E7: FSUBRP ST(i), ST(0)
        0xE0..=0xE7 => Some(X87Entry::reg2("fsubrp", Operation::X87Sub)),
        // E8-EF: FSUBP ST(i), ST(0)
        0xE8..=0xEF => Some(X87Entry::reg2("fsubp", Operation::X87Sub)),
        // F0-F7: FDIVRP ST(i), ST(0)
        0xF0..=0xF7 => Some(X87Entry::reg2("fdivrp", Operation::X87Div)),
        // F8-FF: FDIVP ST(i), ST(0)
        0xF8..=0xFF => Some(X87Entry::reg2("fdivp", Operation::X87Div)),
        _ => None,
    }
}

// ============================================================================
// DF: int16/64 memory ops and misc
// ============================================================================

/// DF /r with memory operand (ModR/M < 0xC0)
pub static X87_DF_MEM: [X87Entry; 8] = [
    X87Entry::mem("fild", Operation::X87Load, 16), // /0: FILD m16int
    X87Entry::mem_pop("fisttp", Operation::X87Store, 16), // /1: FISTTP m16int
    X87Entry::mem("fist", Operation::X87Store, 16), // /2: FIST m16int
    X87Entry::mem_pop("fistp", Operation::X87Store, 16), // /3: FISTP m16int
    X87Entry::mem("fbld", Operation::X87Load, 80), // /4: FBLD m80bcd
    X87Entry::mem("fild", Operation::X87Load, 64), // /5: FILD m64int
    X87Entry::mem_pop("fbstp", Operation::X87Store, 80), // /6: FBSTP m80bcd
    X87Entry::mem_pop("fistp", Operation::X87Store, 64), // /7: FISTP m64int
];

/// DF with register operand (ModR/M >= 0xC0)
pub fn lookup_df_reg(modrm: u8) -> Option<X87Entry> {
    match modrm {
        // C0-C7: FFREEP ST(i) - free and pop (undocumented but common)
        0xC0..=0xC7 => Some(X87Entry::reg("ffreep", Operation::X87Stack)),
        // E0: FNSTSW AX - store status word to AX
        0xE0 => Some(X87Entry::new("fnstsw", Operation::X87Control)),
        // E8-EF: FUCOMIP ST(0), ST(i)
        0xE8..=0xEF => Some(X87Entry::reg2("fucomip", Operation::X87Compare)),
        // F0-F7: FCOMIP ST(0), ST(i)
        0xF0..=0xF7 => Some(X87Entry::reg2("fcomip", Operation::X87Compare)),
        _ => None,
    }
}

/// Decode an x87 FPU instruction.
/// Returns (mnemonic, operation, operand_info) or None if invalid.
///
/// escape: The escape byte (0xD8-0xDF)
/// modrm: The ModR/M byte following the escape
pub fn decode_x87(escape: u8, modrm: u8) -> Option<X87Entry> {
    let is_memory = modrm < 0xC0;
    let reg = ((modrm >> 3) & 7) as usize;

    match escape {
        0xD8 => {
            if is_memory {
                Some(X87_D8_MEM[reg])
            } else {
                let idx = (modrm - 0xC0) as usize;
                Some(X87_D8_REG[idx])
            }
        }
        0xD9 => {
            if is_memory {
                let entry = X87_D9_MEM[reg];
                if entry.mnemonic.is_empty() {
                    None
                } else {
                    Some(entry)
                }
            } else {
                lookup_d9_reg(modrm)
            }
        }
        0xDA => {
            if is_memory {
                Some(X87_DA_MEM[reg])
            } else {
                lookup_da_reg(modrm)
            }
        }
        0xDB => {
            if is_memory {
                let entry = X87_DB_MEM[reg];
                if entry.mnemonic.is_empty() {
                    None
                } else {
                    Some(entry)
                }
            } else {
                lookup_db_reg(modrm)
            }
        }
        0xDC => {
            if is_memory {
                Some(X87_DC_MEM[reg])
            } else {
                let idx = (modrm - 0xC0) as usize;
                Some(X87_DC_REG[idx])
            }
        }
        0xDD => {
            if is_memory {
                let entry = X87_DD_MEM[reg];
                if entry.mnemonic.is_empty() {
                    None
                } else {
                    Some(entry)
                }
            } else {
                lookup_dd_reg(modrm)
            }
        }
        0xDE => {
            if is_memory {
                Some(X87_DE_MEM[reg])
            } else {
                lookup_de_reg(modrm)
            }
        }
        0xDF => {
            if is_memory {
                Some(X87_DF_MEM[reg])
            } else {
                lookup_df_reg(modrm)
            }
        }
        _ => None,
    }
}
