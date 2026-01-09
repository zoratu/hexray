//! x86_64 opcode definitions and lookup.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use hexray_core::Operation;

/// Operand encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandEncoding {
    /// No operands
    None,
    /// Register in opcode (reg field of last opcode byte)
    OpReg,
    /// ModR/M: r/m, reg
    ModRmRm_Reg,
    /// ModR/M: reg, r/m
    ModRmReg_Rm,
    /// ModR/M: r/m only (reg field is opcode extension)
    ModRmRmOnly,
    /// AL/AX/EAX/RAX, immediate
    Acc_Imm,
    /// r/m, immediate
    Rm_Imm,
    /// r/m, immediate (sign-extended 8-bit)
    Rm_Imm8,
    /// Relative offset (calls/jumps)
    Rel8,
    Rel32,
    /// Immediate only
    Imm8,
    Imm16,
    Imm32,
    Imm64,
}

/// Opcode table entry.
#[derive(Debug, Clone)]
pub struct OpcodeEntry {
    /// Mnemonic
    pub mnemonic: &'static str,
    /// Operation category
    pub operation: Operation,
    /// Operand encoding
    pub encoding: OperandEncoding,
    /// Default operand size (0 = use prefix-determined size)
    pub default_size: u16,
    /// Is this a 64-bit default operation?
    pub default_64: bool,
}

impl OpcodeEntry {
    pub const fn new(
        mnemonic: &'static str,
        operation: Operation,
        encoding: OperandEncoding,
    ) -> Self {
        Self {
            mnemonic,
            operation,
            encoding,
            default_size: 0,
            default_64: false,
        }
    }

    pub const fn with_size(mut self, size: u16) -> Self {
        self.default_size = size;
        self
    }

    pub const fn with_default_64(mut self) -> Self {
        self.default_64 = true;
        self
    }
}

/// Const None for array initialization (stable Rust compatibility)
const NONE_ENTRY: Option<OpcodeEntry> = None;

/// One-byte opcode table.
pub static OPCODE_TABLE: [Option<OpcodeEntry>; 256] = {
    let mut table: [Option<OpcodeEntry>; 256] = [NONE_ENTRY; 256];

    // ADD
    table[0x00] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x01] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmRm_Reg));
    table[0x02] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x03] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmReg_Rm));
    table[0x04] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::Acc_Imm).with_size(8));
    table[0x05] = Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::Acc_Imm));

    // OR
    table[0x08] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x09] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmRm_Reg));
    table[0x0A] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x0B] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmReg_Rm));
    table[0x0C] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::Acc_Imm).with_size(8));
    table[0x0D] = Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::Acc_Imm));

    // AND
    table[0x20] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x21] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmRm_Reg));
    table[0x22] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x23] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmReg_Rm));
    table[0x24] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::Acc_Imm).with_size(8));
    table[0x25] = Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::Acc_Imm));

    // SUB
    table[0x28] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x29] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmRm_Reg));
    table[0x2A] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x2B] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmReg_Rm));
    table[0x2C] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::Acc_Imm).with_size(8));
    table[0x2D] = Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::Acc_Imm));

    // XOR
    table[0x30] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x31] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmRm_Reg));
    table[0x32] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x33] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmReg_Rm));
    table[0x34] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::Acc_Imm).with_size(8));
    table[0x35] = Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::Acc_Imm));

    // CMP
    table[0x38] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x39] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmRm_Reg));
    table[0x3A] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x3B] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmReg_Rm));
    table[0x3C] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::Acc_Imm).with_size(8));
    table[0x3D] = Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::Acc_Imm));

    // PUSH r64
    table[0x50] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x51] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x52] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x53] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x54] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x55] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x56] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x57] = Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());

    // POP r64
    table[0x58] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x59] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5A] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5B] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5C] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5D] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5E] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5F] = Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());

    // JMP rel8
    table[0xEB] = Some(OpcodeEntry::new("jmp", Operation::Jump, OperandEncoding::Rel8));

    // JMP rel32
    table[0xE9] = Some(OpcodeEntry::new("jmp", Operation::Jump, OperandEncoding::Rel32));

    // CALL rel32
    table[0xE8] = Some(OpcodeEntry::new("call", Operation::Call, OperandEncoding::Rel32));

    // RET
    table[0xC3] = Some(OpcodeEntry::new("ret", Operation::Return, OperandEncoding::None));

    // RET imm16
    table[0xC2] = Some(OpcodeEntry::new("ret", Operation::Return, OperandEncoding::Imm16));

    // MOV r/m, r
    table[0x88] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x89] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmRm_Reg));

    // MOV r, r/m
    table[0x8A] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x8B] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmReg_Rm));

    // MOV r, imm (B0-B7 for 8-bit, B8-BF for 16/32/64-bit)
    table[0xB0] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB1] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB2] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB3] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB4] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB5] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB6] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB7] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB8] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xB9] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBA] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBB] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBC] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBD] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBE] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));
    table[0xBF] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg));

    // LEA r, m
    table[0x8D] = Some(OpcodeEntry::new("lea", Operation::LoadEffectiveAddress, OperandEncoding::ModRmReg_Rm));

    // MOV r/m, imm
    table[0xC6] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::Rm_Imm).with_size(8));
    table[0xC7] = Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::Rm_Imm));

    // NOP
    table[0x90] = Some(OpcodeEntry::new("nop", Operation::Nop, OperandEncoding::None));

    // TEST r/m, r
    table[0x84] = Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x85] = Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::ModRmRm_Reg));

    // TEST AL/AX/EAX/RAX, imm
    table[0xA8] = Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::Acc_Imm).with_size(8));
    table[0xA9] = Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::Acc_Imm));

    // SYSCALL (0F 05, but we'll mark 0F as special)
    // INT 3
    table[0xCC] = Some(OpcodeEntry::new("int3", Operation::Interrupt, OperandEncoding::None));

    // INT imm8
    table[0xCD] = Some(OpcodeEntry::new("int", Operation::Interrupt, OperandEncoding::Imm8));

    // HLT
    table[0xF4] = Some(OpcodeEntry::new("hlt", Operation::Halt, OperandEncoding::None));

    // Conditional jumps (Jcc rel8)
    table[0x70] = Some(OpcodeEntry::new("jo", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x71] = Some(OpcodeEntry::new("jno", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x72] = Some(OpcodeEntry::new("jb", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x73] = Some(OpcodeEntry::new("jae", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x74] = Some(OpcodeEntry::new("je", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x75] = Some(OpcodeEntry::new("jne", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x76] = Some(OpcodeEntry::new("jbe", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x77] = Some(OpcodeEntry::new("ja", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x78] = Some(OpcodeEntry::new("js", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x79] = Some(OpcodeEntry::new("jns", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7A] = Some(OpcodeEntry::new("jp", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7B] = Some(OpcodeEntry::new("jnp", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7C] = Some(OpcodeEntry::new("jl", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7D] = Some(OpcodeEntry::new("jge", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7E] = Some(OpcodeEntry::new("jle", Operation::ConditionalJump, OperandEncoding::Rel8));
    table[0x7F] = Some(OpcodeEntry::new("jg", Operation::ConditionalJump, OperandEncoding::Rel8));

    // Group 1 (0x80-0x83) - immediate operations on r/m
    // These need special handling based on ModR/M reg field

    // LEAVE
    table[0xC9] = Some(OpcodeEntry::new("leave", Operation::Other(0), OperandEncoding::None));

    table
};

/// Two-byte opcode table (0x0F prefix).
pub static OPCODE_TABLE_0F: [Option<OpcodeEntry>; 256] = {
    let mut table: [Option<OpcodeEntry>; 256] = [NONE_ENTRY; 256];

    // SYSCALL
    table[0x05] = Some(OpcodeEntry::new("syscall", Operation::Syscall, OperandEncoding::None));

    // Conditional jumps (Jcc rel32)
    table[0x80] = Some(OpcodeEntry::new("jo", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x81] = Some(OpcodeEntry::new("jno", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x82] = Some(OpcodeEntry::new("jb", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x83] = Some(OpcodeEntry::new("jae", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x84] = Some(OpcodeEntry::new("je", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x85] = Some(OpcodeEntry::new("jne", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x86] = Some(OpcodeEntry::new("jbe", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x87] = Some(OpcodeEntry::new("ja", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x88] = Some(OpcodeEntry::new("js", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x89] = Some(OpcodeEntry::new("jns", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8A] = Some(OpcodeEntry::new("jp", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8B] = Some(OpcodeEntry::new("jnp", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8C] = Some(OpcodeEntry::new("jl", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8D] = Some(OpcodeEntry::new("jge", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8E] = Some(OpcodeEntry::new("jle", Operation::ConditionalJump, OperandEncoding::Rel32));
    table[0x8F] = Some(OpcodeEntry::new("jg", Operation::ConditionalJump, OperandEncoding::Rel32));

    // MOVZX
    table[0xB6] = Some(OpcodeEntry::new("movzx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0xB7] = Some(OpcodeEntry::new("movzx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(16));

    // MOVSX
    table[0xBE] = Some(OpcodeEntry::new("movsx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0xBF] = Some(OpcodeEntry::new("movsx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(16));

    // IMUL r, r/m
    table[0xAF] = Some(OpcodeEntry::new("imul", Operation::Mul, OperandEncoding::ModRmReg_Rm));

    // NOP (multi-byte) - 0F 1F is the general multi-byte NOP
    table[0x1F] = Some(OpcodeEntry::new("nop", Operation::Nop, OperandEncoding::ModRmRmOnly));

    // 0F 1E - ENDBR64/ENDBR32/NOP (CET hint instructions)
    // With F3 prefix: ENDBR64 (FA) or ENDBR32 (FB)
    // Without prefix: treated as NOP with ModR/M
    table[0x1E] = Some(OpcodeEntry::new("nop", Operation::Nop, OperandEncoding::ModRmRmOnly));

    table
};

/// Group 1 operations (for opcodes 0x80-0x83).
pub static GROUP1_OPS: [(&str, Operation); 8] = [
    ("add", Operation::Add),
    ("or", Operation::Or),
    ("adc", Operation::Add), // ADC - add with carry
    ("sbb", Operation::Sub), // SBB - sub with borrow
    ("and", Operation::And),
    ("sub", Operation::Sub),
    ("xor", Operation::Xor),
    ("cmp", Operation::Compare),
];

/// Group 2 operations (shift/rotate, for opcodes 0xC0-0xC1, 0xD0-0xD3).
pub static GROUP2_OPS: [(&str, Operation); 8] = [
    ("rol", Operation::Rol),      // Rotate left
    ("ror", Operation::Ror),      // Rotate right
    ("rcl", Operation::Other(2)), // Rotate through carry left
    ("rcr", Operation::Other(3)), // Rotate through carry right
    ("shl", Operation::Shl),      // Shift left (also SAL)
    ("shr", Operation::Shr),      // Shift right logical
    ("shl", Operation::Shl),      // (undefined, but some assemblers use SAL)
    ("sar", Operation::Sar),      // Shift right arithmetic
];

/// Group 3 operations (for opcodes 0xF6/0xF7: unary ops with r/m).
pub static GROUP3_OPS: [(&str, Operation); 8] = [
    ("test", Operation::Test),    // /0 TEST r/m, imm
    ("test", Operation::Test),    // /1 TEST r/m, imm (same as /0)
    ("not", Operation::Not),      // /2 NOT r/m
    ("neg", Operation::Neg),      // /3 NEG r/m
    ("mul", Operation::Mul),      // /4 MUL r/m (unsigned)
    ("imul", Operation::Mul),     // /5 IMUL r/m (signed)
    ("div", Operation::Div),      // /6 DIV r/m (unsigned)
    ("idiv", Operation::Div),     // /7 IDIV r/m (signed)
];

/// Group 5 operations (for opcode 0xFF).
pub static GROUP5_OPS: [(&str, Operation); 8] = [
    ("inc", Operation::Inc),      // /0 INC r/m
    ("dec", Operation::Dec),      // /1 DEC r/m
    ("call", Operation::Call),    // /2 CALL r/m64 (indirect call)
    ("call", Operation::Call),    // /3 CALL m16:64 (far call, rare)
    ("jmp", Operation::Jump),     // /4 JMP r/m64 (indirect jump)
    ("jmp", Operation::Jump),     // /5 JMP m16:64 (far jmp, rare)
    ("push", Operation::Push),    // /6 PUSH r/m64
    ("", Operation::Other(255)),  // /7 (reserved)
];
