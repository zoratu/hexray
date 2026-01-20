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
#[derive(Debug, Clone, Copy)]
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
    table[0x00] =
        Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x01] = Some(OpcodeEntry::new(
        "add",
        Operation::Add,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x02] =
        Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x03] = Some(OpcodeEntry::new(
        "add",
        Operation::Add,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x04] =
        Some(OpcodeEntry::new("add", Operation::Add, OperandEncoding::Acc_Imm).with_size(8));
    table[0x05] = Some(OpcodeEntry::new(
        "add",
        Operation::Add,
        OperandEncoding::Acc_Imm,
    ));

    // OR
    table[0x08] =
        Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x09] = Some(OpcodeEntry::new(
        "or",
        Operation::Or,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x0A] =
        Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x0B] = Some(OpcodeEntry::new(
        "or",
        Operation::Or,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x0C] =
        Some(OpcodeEntry::new("or", Operation::Or, OperandEncoding::Acc_Imm).with_size(8));
    table[0x0D] = Some(OpcodeEntry::new(
        "or",
        Operation::Or,
        OperandEncoding::Acc_Imm,
    ));

    // AND
    table[0x20] =
        Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x21] = Some(OpcodeEntry::new(
        "and",
        Operation::And,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x22] =
        Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x23] = Some(OpcodeEntry::new(
        "and",
        Operation::And,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x24] =
        Some(OpcodeEntry::new("and", Operation::And, OperandEncoding::Acc_Imm).with_size(8));
    table[0x25] = Some(OpcodeEntry::new(
        "and",
        Operation::And,
        OperandEncoding::Acc_Imm,
    ));

    // SUB
    table[0x28] =
        Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x29] = Some(OpcodeEntry::new(
        "sub",
        Operation::Sub,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x2A] =
        Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x2B] = Some(OpcodeEntry::new(
        "sub",
        Operation::Sub,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x2C] =
        Some(OpcodeEntry::new("sub", Operation::Sub, OperandEncoding::Acc_Imm).with_size(8));
    table[0x2D] = Some(OpcodeEntry::new(
        "sub",
        Operation::Sub,
        OperandEncoding::Acc_Imm,
    ));

    // XOR
    table[0x30] =
        Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x31] = Some(OpcodeEntry::new(
        "xor",
        Operation::Xor,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x32] =
        Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x33] = Some(OpcodeEntry::new(
        "xor",
        Operation::Xor,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x34] =
        Some(OpcodeEntry::new("xor", Operation::Xor, OperandEncoding::Acc_Imm).with_size(8));
    table[0x35] = Some(OpcodeEntry::new(
        "xor",
        Operation::Xor,
        OperandEncoding::Acc_Imm,
    ));

    // CMP
    table[0x38] = Some(
        OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmRm_Reg).with_size(8),
    );
    table[0x39] = Some(OpcodeEntry::new(
        "cmp",
        Operation::Compare,
        OperandEncoding::ModRmRm_Reg,
    ));
    table[0x3A] = Some(
        OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::ModRmReg_Rm).with_size(8),
    );
    table[0x3B] = Some(OpcodeEntry::new(
        "cmp",
        Operation::Compare,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x3C] =
        Some(OpcodeEntry::new("cmp", Operation::Compare, OperandEncoding::Acc_Imm).with_size(8));
    table[0x3D] = Some(OpcodeEntry::new(
        "cmp",
        Operation::Compare,
        OperandEncoding::Acc_Imm,
    ));

    // PUSH r64
    table[0x50] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x51] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x52] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x53] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x54] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x55] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x56] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());
    table[0x57] =
        Some(OpcodeEntry::new("push", Operation::Push, OperandEncoding::OpReg).with_default_64());

    // POP r64
    table[0x58] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x59] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5A] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5B] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5C] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5D] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5E] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());
    table[0x5F] =
        Some(OpcodeEntry::new("pop", Operation::Pop, OperandEncoding::OpReg).with_default_64());

    // MOVSXD (sign-extend dword to qword) - 0x63 with REX.W
    // In 64-bit mode, this is movsxd; in 32-bit mode it was ARPL
    table[0x63] = Some(OpcodeEntry::new(
        "movsxd",
        Operation::Move,
        OperandEncoding::ModRmReg_Rm,
    ));

    // JMP rel8
    table[0xEB] = Some(OpcodeEntry::new(
        "jmp",
        Operation::Jump,
        OperandEncoding::Rel8,
    ));

    // JMP rel32
    table[0xE9] = Some(OpcodeEntry::new(
        "jmp",
        Operation::Jump,
        OperandEncoding::Rel32,
    ));

    // CALL rel32
    table[0xE8] = Some(OpcodeEntry::new(
        "call",
        Operation::Call,
        OperandEncoding::Rel32,
    ));

    // RET
    table[0xC3] = Some(OpcodeEntry::new(
        "ret",
        Operation::Return,
        OperandEncoding::None,
    ));

    // RET imm16
    table[0xC2] = Some(OpcodeEntry::new(
        "ret",
        Operation::Return,
        OperandEncoding::Imm16,
    ));

    // MOV r/m, r
    table[0x88] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x89] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::ModRmRm_Reg,
    ));

    // MOV r, r/m
    table[0x8A] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0x8B] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::ModRmReg_Rm,
    ));

    // MOV r, imm (B0-B7 for 8-bit, B8-BF for 16/32/64-bit)
    table[0xB0] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB1] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB2] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB3] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB4] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB5] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB6] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB7] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::OpReg).with_size(8));
    table[0xB8] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xB9] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBA] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBB] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBC] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBD] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBE] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));
    table[0xBF] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::OpReg,
    ));

    // LEA r, m
    table[0x8D] = Some(OpcodeEntry::new(
        "lea",
        Operation::LoadEffectiveAddress,
        OperandEncoding::ModRmReg_Rm,
    ));

    // MOV r/m, imm
    table[0xC6] =
        Some(OpcodeEntry::new("mov", Operation::Move, OperandEncoding::Rm_Imm).with_size(8));
    table[0xC7] = Some(OpcodeEntry::new(
        "mov",
        Operation::Move,
        OperandEncoding::Rm_Imm,
    ));

    // NOP
    table[0x90] = Some(OpcodeEntry::new(
        "nop",
        Operation::Nop,
        OperandEncoding::None,
    ));

    // TEST r/m, r
    table[0x84] =
        Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::ModRmRm_Reg).with_size(8));
    table[0x85] = Some(OpcodeEntry::new(
        "test",
        Operation::Test,
        OperandEncoding::ModRmRm_Reg,
    ));

    // TEST AL/AX/EAX/RAX, imm
    table[0xA8] =
        Some(OpcodeEntry::new("test", Operation::Test, OperandEncoding::Acc_Imm).with_size(8));
    table[0xA9] = Some(OpcodeEntry::new(
        "test",
        Operation::Test,
        OperandEncoding::Acc_Imm,
    ));

    // SYSCALL (0F 05, but we'll mark 0F as special)
    // INT 3
    table[0xCC] = Some(OpcodeEntry::new(
        "int3",
        Operation::Interrupt,
        OperandEncoding::None,
    ));

    // INT imm8
    table[0xCD] = Some(OpcodeEntry::new(
        "int",
        Operation::Interrupt,
        OperandEncoding::Imm8,
    ));

    // HLT
    table[0xF4] = Some(OpcodeEntry::new(
        "hlt",
        Operation::Halt,
        OperandEncoding::None,
    ));

    // Conditional jumps (Jcc rel8)
    table[0x70] = Some(OpcodeEntry::new(
        "jo",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x71] = Some(OpcodeEntry::new(
        "jno",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x72] = Some(OpcodeEntry::new(
        "jb",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x73] = Some(OpcodeEntry::new(
        "jae",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x74] = Some(OpcodeEntry::new(
        "je",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x75] = Some(OpcodeEntry::new(
        "jne",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x76] = Some(OpcodeEntry::new(
        "jbe",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x77] = Some(OpcodeEntry::new(
        "ja",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x78] = Some(OpcodeEntry::new(
        "js",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x79] = Some(OpcodeEntry::new(
        "jns",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7A] = Some(OpcodeEntry::new(
        "jp",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7B] = Some(OpcodeEntry::new(
        "jnp",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7C] = Some(OpcodeEntry::new(
        "jl",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7D] = Some(OpcodeEntry::new(
        "jge",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7E] = Some(OpcodeEntry::new(
        "jle",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));
    table[0x7F] = Some(OpcodeEntry::new(
        "jg",
        Operation::ConditionalJump,
        OperandEncoding::Rel8,
    ));

    // Group 1 (0x80-0x83) - immediate operations on r/m
    // These need special handling based on ModR/M reg field

    // LEAVE
    table[0xC9] = Some(OpcodeEntry::new(
        "leave",
        Operation::Other(0),
        OperandEncoding::None,
    ));

    table
};

/// Two-byte opcode table (0x0F prefix).
pub static OPCODE_TABLE_0F: [Option<OpcodeEntry>; 256] = {
    let mut table: [Option<OpcodeEntry>; 256] = [NONE_ENTRY; 256];

    // SYSCALL
    table[0x05] = Some(OpcodeEntry::new(
        "syscall",
        Operation::Syscall,
        OperandEncoding::None,
    ));

    // System instructions
    // 0F 01 - handled specially in decoder (SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG, RDTSCP)
    // We mark 0x01 as having ModRM but handle reg field dispatch in decoder
    table[0x01] = Some(OpcodeEntry::new(
        "system_0f01",
        Operation::Other(0x0F01),
        OperandEncoding::ModRmRmOnly,
    ));

    // WRMSR - Write Model Specific Register (0F 30)
    table[0x30] = Some(OpcodeEntry::new(
        "wrmsr",
        Operation::WriteMsr,
        OperandEncoding::None,
    ));

    // RDTSC - Read Time Stamp Counter (0F 31)
    table[0x31] = Some(OpcodeEntry::new(
        "rdtsc",
        Operation::ReadTsc,
        OperandEncoding::None,
    ));

    // RDMSR - Read Model Specific Register (0F 32)
    table[0x32] = Some(OpcodeEntry::new(
        "rdmsr",
        Operation::ReadMsr,
        OperandEncoding::None,
    ));

    // CPUID - CPU Identification (0F A2)
    table[0xA2] = Some(OpcodeEntry::new(
        "cpuid",
        Operation::CpuId,
        OperandEncoding::None,
    ));

    // Conditional jumps (Jcc rel32)
    table[0x80] = Some(OpcodeEntry::new(
        "jo",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x81] = Some(OpcodeEntry::new(
        "jno",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x82] = Some(OpcodeEntry::new(
        "jb",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x83] = Some(OpcodeEntry::new(
        "jae",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x84] = Some(OpcodeEntry::new(
        "je",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x85] = Some(OpcodeEntry::new(
        "jne",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x86] = Some(OpcodeEntry::new(
        "jbe",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x87] = Some(OpcodeEntry::new(
        "ja",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x88] = Some(OpcodeEntry::new(
        "js",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x89] = Some(OpcodeEntry::new(
        "jns",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8A] = Some(OpcodeEntry::new(
        "jp",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8B] = Some(OpcodeEntry::new(
        "jnp",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8C] = Some(OpcodeEntry::new(
        "jl",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8D] = Some(OpcodeEntry::new(
        "jge",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8E] = Some(OpcodeEntry::new(
        "jle",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));
    table[0x8F] = Some(OpcodeEntry::new(
        "jg",
        Operation::ConditionalJump,
        OperandEncoding::Rel32,
    ));

    // MOVZX
    table[0xB6] =
        Some(OpcodeEntry::new("movzx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0xB7] = Some(
        OpcodeEntry::new("movzx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(16),
    );

    // MOVSX
    table[0xBE] =
        Some(OpcodeEntry::new("movsx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(8));
    table[0xBF] = Some(
        OpcodeEntry::new("movsx", Operation::Move, OperandEncoding::ModRmReg_Rm).with_size(16),
    );

    // IMUL r, r/m
    table[0xAF] = Some(OpcodeEntry::new(
        "imul",
        Operation::Mul,
        OperandEncoding::ModRmReg_Rm,
    ));

    // NOP (multi-byte) - 0F 1F is the general multi-byte NOP
    table[0x1F] = Some(OpcodeEntry::new(
        "nop",
        Operation::Nop,
        OperandEncoding::ModRmRmOnly,
    ));

    // 0F 1E - ENDBR64/ENDBR32/NOP (CET hint instructions)
    // With F3 prefix: ENDBR64 (FA) or ENDBR32 (FB)
    // Without prefix: treated as NOP with ModR/M
    table[0x1E] = Some(OpcodeEntry::new(
        "nop",
        Operation::Nop,
        OperandEncoding::ModRmRmOnly,
    ));

    // CMOVcc - Conditional move (0F 40 - 0F 4F)
    table[0x40] = Some(OpcodeEntry::new(
        "cmovo",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x41] = Some(OpcodeEntry::new(
        "cmovno",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x42] = Some(OpcodeEntry::new(
        "cmovb",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x43] = Some(OpcodeEntry::new(
        "cmovae",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x44] = Some(OpcodeEntry::new(
        "cmove",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x45] = Some(OpcodeEntry::new(
        "cmovne",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x46] = Some(OpcodeEntry::new(
        "cmovbe",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x47] = Some(OpcodeEntry::new(
        "cmova",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x48] = Some(OpcodeEntry::new(
        "cmovs",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x49] = Some(OpcodeEntry::new(
        "cmovns",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4A] = Some(OpcodeEntry::new(
        "cmovp",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4B] = Some(OpcodeEntry::new(
        "cmovnp",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4C] = Some(OpcodeEntry::new(
        "cmovl",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4D] = Some(OpcodeEntry::new(
        "cmovge",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4E] = Some(OpcodeEntry::new(
        "cmovle",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));
    table[0x4F] = Some(OpcodeEntry::new(
        "cmovg",
        Operation::ConditionalMove,
        OperandEncoding::ModRmReg_Rm,
    ));

    // SETcc - Set byte on condition (0F 90 - 0F 9F)
    table[0x90] = Some(
        OpcodeEntry::new(
            "seto",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x91] = Some(
        OpcodeEntry::new(
            "setno",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x92] = Some(
        OpcodeEntry::new(
            "setb",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x93] = Some(
        OpcodeEntry::new(
            "setae",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x94] = Some(
        OpcodeEntry::new(
            "sete",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x95] = Some(
        OpcodeEntry::new(
            "setne",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x96] = Some(
        OpcodeEntry::new(
            "setbe",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x97] = Some(
        OpcodeEntry::new(
            "seta",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x98] = Some(
        OpcodeEntry::new(
            "sets",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x99] = Some(
        OpcodeEntry::new(
            "setns",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9A] = Some(
        OpcodeEntry::new(
            "setp",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9B] = Some(
        OpcodeEntry::new(
            "setnp",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9C] = Some(
        OpcodeEntry::new(
            "setl",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9D] = Some(
        OpcodeEntry::new(
            "setge",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9E] = Some(
        OpcodeEntry::new(
            "setle",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );
    table[0x9F] = Some(
        OpcodeEntry::new(
            "setg",
            Operation::SetConditional,
            OperandEncoding::ModRmRmOnly,
        )
        .with_size(8),
    );

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
    ("test", Operation::Test), // /0 TEST r/m, imm
    ("test", Operation::Test), // /1 TEST r/m, imm (same as /0)
    ("not", Operation::Not),   // /2 NOT r/m
    ("neg", Operation::Neg),   // /3 NEG r/m
    ("mul", Operation::Mul),   // /4 MUL r/m (unsigned)
    ("imul", Operation::Mul),  // /5 IMUL r/m (signed)
    ("div", Operation::Div),   // /6 DIV r/m (unsigned)
    ("idiv", Operation::Div),  // /7 IDIV r/m (signed)
];

/// Group 5 operations (for opcode 0xFF).
pub static GROUP5_OPS: [(&str, Operation); 8] = [
    ("inc", Operation::Inc),     // /0 INC r/m
    ("dec", Operation::Dec),     // /1 DEC r/m
    ("call", Operation::Call),   // /2 CALL r/m64 (indirect call)
    ("call", Operation::Call),   // /3 CALL m16:64 (far call, rare)
    ("jmp", Operation::Jump),    // /4 JMP r/m64 (indirect jump)
    ("jmp", Operation::Jump),    // /5 JMP m16:64 (far jmp, rare)
    ("push", Operation::Push),   // /6 PUSH r/m64
    ("", Operation::Other(255)), // /7 (reserved)
];

// ============================================================================
// SSE/AVX Opcode Tables
// ============================================================================

/// SSE operand encoding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseEncoding {
    /// xmm, xmm/m128
    XmmRm,
    /// xmm/m128, xmm
    RmXmm,
    /// xmm, xmm/m128, imm8
    XmmRmImm8,
    /// xmm, xmm, xmm/m128 (3 operands for VEX)
    XmmXmmRm,
    /// xmm, xmm/m64 (scalar double)
    XmmRmScalar64,
    /// xmm, xmm/m32 (scalar single)
    XmmRmScalar32,
    /// xmm, r/m32 (move to/from general register)
    XmmGpr,
    /// r/m32, xmm
    GprXmm,
    /// xmm (single operand)
    XmmOnly,
    /// r, r/m (GPR to GPR, for POPCNT/LZCNT/TZCNT)
    GprGprRm,
}

/// SSE/AVX opcode entry.
#[derive(Debug, Clone)]
pub struct SseOpcodeEntry {
    /// Mnemonic (SSE version)
    pub mnemonic: &'static str,
    /// VEX mnemonic (None if same as SSE)
    pub vex_mnemonic: Option<&'static str>,
    /// Operation category
    pub operation: Operation,
    /// Encoding type
    pub encoding: SseEncoding,
    /// Required prefix: None, 0x66, 0xF2, or 0xF3
    pub prefix: Option<u8>,
}

impl SseOpcodeEntry {
    pub const fn new(mnemonic: &'static str, operation: Operation, encoding: SseEncoding) -> Self {
        Self {
            mnemonic,
            vex_mnemonic: None,
            operation,
            encoding,
            prefix: None,
        }
    }

    pub const fn with_prefix(mut self, prefix: u8) -> Self {
        self.prefix = Some(prefix);
        self
    }

    pub const fn with_vex_mnemonic(mut self, vex_mnemonic: &'static str) -> Self {
        self.vex_mnemonic = Some(vex_mnemonic);
        self
    }
}

/// Const None for SSE array initialization
const NONE_SSE_ENTRY: Option<SseOpcodeEntry> = None;

/// SSE opcode table (0F xx opcodes).
/// Index is the opcode byte after 0F.
pub static SSE_OPCODE_TABLE: [Option<SseOpcodeEntry>; 256] = {
    let mut table: [Option<SseOpcodeEntry>; 256] = [NONE_SSE_ENTRY; 256];

    // MOVUPS xmm, xmm/m128 (no prefix)
    table[0x10] = Some(
        SseOpcodeEntry::new("movups", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovups"),
    );

    // MOVUPD xmm, xmm/m128 (66 prefix)
    // Note: handled separately based on prefix

    // MOVSS xmm, xmm/m32 (F3 prefix)
    // MOVSD xmm, xmm/m64 (F2 prefix)

    // MOVUPS xmm/m128, xmm (no prefix)
    table[0x11] = Some(
        SseOpcodeEntry::new("movups", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovups"),
    );

    // MOVLPS/MOVHLPS xmm, xmm/m64
    table[0x12] = Some(
        SseOpcodeEntry::new("movlps", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovlps"),
    );

    // MOVLPS m64, xmm
    table[0x13] = Some(
        SseOpcodeEntry::new("movlps", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovlps"),
    );

    // UNPCKLPS xmm, xmm/m128
    table[0x14] = Some(
        SseOpcodeEntry::new("unpcklps", Operation::Other(0x14), SseEncoding::XmmRm)
            .with_vex_mnemonic("vunpcklps"),
    );

    // UNPCKHPS xmm, xmm/m128
    table[0x15] = Some(
        SseOpcodeEntry::new("unpckhps", Operation::Other(0x15), SseEncoding::XmmRm)
            .with_vex_mnemonic("vunpckhps"),
    );

    // MOVHPS/MOVLHPS xmm, xmm/m64
    table[0x16] = Some(
        SseOpcodeEntry::new("movhps", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovhps"),
    );

    // MOVHPS m64, xmm
    table[0x17] = Some(
        SseOpcodeEntry::new("movhps", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovhps"),
    );

    // MOVAPS xmm, xmm/m128
    table[0x28] = Some(
        SseOpcodeEntry::new("movaps", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovaps"),
    );

    // MOVAPS xmm/m128, xmm
    table[0x29] = Some(
        SseOpcodeEntry::new("movaps", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovaps"),
    );

    // CVTSI2SS xmm, r/m32
    table[0x2A] = Some(
        SseOpcodeEntry::new("cvtsi2ss", Operation::Move, SseEncoding::XmmGpr)
            .with_vex_mnemonic("vcvtsi2ss"),
    );

    // MOVNTPS m128, xmm (non-temporal store)
    table[0x2B] = Some(
        SseOpcodeEntry::new("movntps", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovntps"),
    );

    // CVTTSS2SI r32, xmm/m32
    table[0x2C] = Some(
        SseOpcodeEntry::new("cvttss2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvttss2si"),
    );

    // CVTSS2SI r32, xmm/m32
    table[0x2D] = Some(
        SseOpcodeEntry::new("cvtss2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvtss2si"),
    );

    // UCOMISS xmm, xmm/m32
    table[0x2E] = Some(
        SseOpcodeEntry::new("ucomiss", Operation::Compare, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vucomiss"),
    );

    // COMISS xmm, xmm/m32
    table[0x2F] = Some(
        SseOpcodeEntry::new("comiss", Operation::Compare, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vcomiss"),
    );

    // MOVMSKPS r32, xmm
    table[0x50] = Some(
        SseOpcodeEntry::new("movmskps", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vmovmskps"),
    );

    // SQRTPS xmm, xmm/m128
    table[0x51] = Some(
        SseOpcodeEntry::new("sqrtps", Operation::Other(0x51), SseEncoding::XmmRm)
            .with_vex_mnemonic("vsqrtps"),
    );

    // RSQRTPS xmm, xmm/m128
    table[0x52] = Some(
        SseOpcodeEntry::new("rsqrtps", Operation::Other(0x52), SseEncoding::XmmRm)
            .with_vex_mnemonic("vrsqrtps"),
    );

    // RCPPS xmm, xmm/m128
    table[0x53] = Some(
        SseOpcodeEntry::new("rcpps", Operation::Other(0x53), SseEncoding::XmmRm)
            .with_vex_mnemonic("vrcpps"),
    );

    // ANDPS xmm, xmm/m128
    table[0x54] = Some(
        SseOpcodeEntry::new("andps", Operation::And, SseEncoding::XmmRm)
            .with_vex_mnemonic("vandps"),
    );

    // ANDNPS xmm, xmm/m128
    table[0x55] = Some(
        SseOpcodeEntry::new("andnps", Operation::Other(0x55), SseEncoding::XmmRm)
            .with_vex_mnemonic("vandnps"),
    );

    // ORPS xmm, xmm/m128
    table[0x56] = Some(
        SseOpcodeEntry::new("orps", Operation::Or, SseEncoding::XmmRm).with_vex_mnemonic("vorps"),
    );

    // XORPS xmm, xmm/m128
    table[0x57] = Some(
        SseOpcodeEntry::new("xorps", Operation::Xor, SseEncoding::XmmRm)
            .with_vex_mnemonic("vxorps"),
    );

    // ADDPS xmm, xmm/m128
    table[0x58] = Some(
        SseOpcodeEntry::new("addps", Operation::Add, SseEncoding::XmmRm)
            .with_vex_mnemonic("vaddps"),
    );

    // MULPS xmm, xmm/m128
    table[0x59] = Some(
        SseOpcodeEntry::new("mulps", Operation::Mul, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmulps"),
    );

    // CVTPS2PD xmm, xmm/m64
    table[0x5A] = Some(
        SseOpcodeEntry::new("cvtps2pd", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vcvtps2pd"),
    );

    // CVTDQ2PS xmm, xmm/m128
    table[0x5B] = Some(
        SseOpcodeEntry::new("cvtdq2ps", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vcvtdq2ps"),
    );

    // SUBPS xmm, xmm/m128
    table[0x5C] = Some(
        SseOpcodeEntry::new("subps", Operation::Sub, SseEncoding::XmmRm)
            .with_vex_mnemonic("vsubps"),
    );

    // MINPS xmm, xmm/m128
    table[0x5D] = Some(
        SseOpcodeEntry::new("minps", Operation::Other(0x5D), SseEncoding::XmmRm)
            .with_vex_mnemonic("vminps"),
    );

    // DIVPS xmm, xmm/m128
    table[0x5E] = Some(
        SseOpcodeEntry::new("divps", Operation::Div, SseEncoding::XmmRm)
            .with_vex_mnemonic("vdivps"),
    );

    // MAXPS xmm, xmm/m128
    table[0x5F] = Some(
        SseOpcodeEntry::new("maxps", Operation::Other(0x5F), SseEncoding::XmmRm)
            .with_vex_mnemonic("vmaxps"),
    );

    // PUNPCKLBW/PUNPCKLWD/etc - 0x60-0x6F (MMX/SSE2 integer)
    // ... (can be extended)

    // MOVD/MOVQ xmm, r/m32/64
    table[0x6E] = Some(
        SseOpcodeEntry::new("movd", Operation::Move, SseEncoding::XmmGpr)
            .with_prefix(0x66)
            .with_vex_mnemonic("vmovd"),
    );

    // MOVDQA xmm, xmm/m128 (66 prefix)
    table[0x6F] = Some(
        SseOpcodeEntry::new("movdqa", Operation::Move, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vmovdqa"),
    );

    // PSHUFD xmm, xmm/m128, imm8
    table[0x70] = Some(
        SseOpcodeEntry::new("pshufd", Operation::Other(0x70), SseEncoding::XmmRmImm8)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpshufd"),
    );

    // PCMPEQB/PCMPEQW/PCMPEQD - packed compare equal
    table[0x74] = Some(
        SseOpcodeEntry::new("pcmpeqb", Operation::Compare, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpcmpeqb"),
    );
    table[0x75] = Some(
        SseOpcodeEntry::new("pcmpeqw", Operation::Compare, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpcmpeqw"),
    );
    table[0x76] = Some(
        SseOpcodeEntry::new("pcmpeqd", Operation::Compare, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpcmpeqd"),
    );

    // MOVD/MOVQ r/m32/64, xmm
    table[0x7E] = Some(
        SseOpcodeEntry::new("movd", Operation::Store, SseEncoding::GprXmm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vmovd"),
    );

    // MOVDQA xmm/m128, xmm
    table[0x7F] = Some(
        SseOpcodeEntry::new("movdqa", Operation::Store, SseEncoding::RmXmm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vmovdqa"),
    );

    // SHUFPS xmm, xmm/m128, imm8
    table[0xC6] = Some(
        SseOpcodeEntry::new("shufps", Operation::Other(0xC6), SseEncoding::XmmRmImm8)
            .with_vex_mnemonic("vshufps"),
    );

    // PAND xmm, xmm/m128
    table[0xDB] = Some(
        SseOpcodeEntry::new("pand", Operation::And, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpand"),
    );

    // PANDN xmm, xmm/m128
    table[0xDF] = Some(
        SseOpcodeEntry::new("pandn", Operation::Other(0xDF), SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpandn"),
    );

    // PAVGB xmm, xmm/m128
    table[0xE0] = Some(
        SseOpcodeEntry::new("pavgb", Operation::Other(0xE0), SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpavgb"),
    );

    // POR xmm, xmm/m128
    table[0xEB] = Some(
        SseOpcodeEntry::new("por", Operation::Or, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpor"),
    );

    // PXOR xmm, xmm/m128
    table[0xEF] = Some(
        SseOpcodeEntry::new("pxor", Operation::Xor, SseEncoding::XmmRm)
            .with_prefix(0x66)
            .with_vex_mnemonic("vpxor"),
    );

    // MOVDQU xmm, xmm/m128 (F3 prefix)
    // MOVDQU xmm/m128, xmm (F3 prefix)
    // Note: F3 prefix variants handled in decoder with prefix check

    table
};

/// SSE2 opcode variants with 0x66 prefix.
/// These override the no-prefix versions for packed double operations.
pub static SSE2_OPCODE_TABLE_66: [Option<SseOpcodeEntry>; 256] = {
    let mut table: [Option<SseOpcodeEntry>; 256] = [NONE_SSE_ENTRY; 256];

    // MOVUPD xmm, xmm/m128
    table[0x10] = Some(
        SseOpcodeEntry::new("movupd", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovupd"),
    );

    // MOVUPD xmm/m128, xmm
    table[0x11] = Some(
        SseOpcodeEntry::new("movupd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovupd"),
    );

    // MOVLPD xmm, m64
    table[0x12] = Some(
        SseOpcodeEntry::new("movlpd", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovlpd"),
    );

    // MOVLPD m64, xmm
    table[0x13] = Some(
        SseOpcodeEntry::new("movlpd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovlpd"),
    );

    // UNPCKLPD xmm, xmm/m128
    table[0x14] = Some(
        SseOpcodeEntry::new("unpcklpd", Operation::Other(0x14), SseEncoding::XmmRm)
            .with_vex_mnemonic("vunpcklpd"),
    );

    // UNPCKHPD xmm, xmm/m128
    table[0x15] = Some(
        SseOpcodeEntry::new("unpckhpd", Operation::Other(0x15), SseEncoding::XmmRm)
            .with_vex_mnemonic("vunpckhpd"),
    );

    // MOVHPD xmm, m64
    table[0x16] = Some(
        SseOpcodeEntry::new("movhpd", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovhpd"),
    );

    // MOVHPD m64, xmm
    table[0x17] = Some(
        SseOpcodeEntry::new("movhpd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovhpd"),
    );

    // MOVAPD xmm, xmm/m128
    table[0x28] = Some(
        SseOpcodeEntry::new("movapd", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovapd"),
    );

    // MOVAPD xmm/m128, xmm
    table[0x29] = Some(
        SseOpcodeEntry::new("movapd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovapd"),
    );

    // CVTPI2PD xmm, mm/m64
    table[0x2A] = Some(
        SseOpcodeEntry::new("cvtpi2pd", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vcvtpi2pd"),
    );

    // MOVNTPD m128, xmm
    table[0x2B] = Some(
        SseOpcodeEntry::new("movntpd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovntpd"),
    );

    // UCOMISD xmm, xmm/m64
    table[0x2E] = Some(
        SseOpcodeEntry::new("ucomisd", Operation::Compare, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vucomisd"),
    );

    // COMISD xmm, xmm/m64
    table[0x2F] = Some(
        SseOpcodeEntry::new("comisd", Operation::Compare, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vcomisd"),
    );

    // MOVMSKPD r32, xmm
    table[0x50] = Some(
        SseOpcodeEntry::new("movmskpd", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vmovmskpd"),
    );

    // SQRTPD xmm, xmm/m128
    table[0x51] = Some(
        SseOpcodeEntry::new("sqrtpd", Operation::Other(0x51), SseEncoding::XmmRm)
            .with_vex_mnemonic("vsqrtpd"),
    );

    // ANDPD xmm, xmm/m128
    table[0x54] = Some(
        SseOpcodeEntry::new("andpd", Operation::And, SseEncoding::XmmRm)
            .with_vex_mnemonic("vandpd"),
    );

    // ANDNPD xmm, xmm/m128
    table[0x55] = Some(
        SseOpcodeEntry::new("andnpd", Operation::Other(0x55), SseEncoding::XmmRm)
            .with_vex_mnemonic("vandnpd"),
    );

    // ORPD xmm, xmm/m128
    table[0x56] = Some(
        SseOpcodeEntry::new("orpd", Operation::Or, SseEncoding::XmmRm).with_vex_mnemonic("vorpd"),
    );

    // XORPD xmm, xmm/m128
    table[0x57] = Some(
        SseOpcodeEntry::new("xorpd", Operation::Xor, SseEncoding::XmmRm)
            .with_vex_mnemonic("vxorpd"),
    );

    // ADDPD xmm, xmm/m128
    table[0x58] = Some(
        SseOpcodeEntry::new("addpd", Operation::Add, SseEncoding::XmmRm)
            .with_vex_mnemonic("vaddpd"),
    );

    // MULPD xmm, xmm/m128
    table[0x59] = Some(
        SseOpcodeEntry::new("mulpd", Operation::Mul, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmulpd"),
    );

    // CVTPD2PS xmm, xmm/m128
    table[0x5A] = Some(
        SseOpcodeEntry::new("cvtpd2ps", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vcvtpd2ps"),
    );

    // CVTPS2DQ xmm, xmm/m128
    table[0x5B] = Some(
        SseOpcodeEntry::new("cvtps2dq", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vcvtps2dq"),
    );

    // SUBPD xmm, xmm/m128
    table[0x5C] = Some(
        SseOpcodeEntry::new("subpd", Operation::Sub, SseEncoding::XmmRm)
            .with_vex_mnemonic("vsubpd"),
    );

    // MINPD xmm, xmm/m128
    table[0x5D] = Some(
        SseOpcodeEntry::new("minpd", Operation::Other(0x5D), SseEncoding::XmmRm)
            .with_vex_mnemonic("vminpd"),
    );

    // DIVPD xmm, xmm/m128
    table[0x5E] = Some(
        SseOpcodeEntry::new("divpd", Operation::Div, SseEncoding::XmmRm)
            .with_vex_mnemonic("vdivpd"),
    );

    // MAXPD xmm, xmm/m128
    table[0x5F] = Some(
        SseOpcodeEntry::new("maxpd", Operation::Other(0x5F), SseEncoding::XmmRm)
            .with_vex_mnemonic("vmaxpd"),
    );

    // SHUFPD xmm, xmm/m128, imm8
    table[0xC6] = Some(
        SseOpcodeEntry::new("shufpd", Operation::Other(0xC6), SseEncoding::XmmRmImm8)
            .with_vex_mnemonic("vshufpd"),
    );

    table
};

/// SSE scalar single (F3 prefix) opcode variants.
pub static SSE_OPCODE_TABLE_F3: [Option<SseOpcodeEntry>; 256] = {
    let mut table: [Option<SseOpcodeEntry>; 256] = [NONE_SSE_ENTRY; 256];

    // MOVSS xmm, xmm/m32
    table[0x10] = Some(
        SseOpcodeEntry::new("movss", Operation::Move, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vmovss"),
    );

    // MOVSS xmm/m32, xmm
    table[0x11] = Some(
        SseOpcodeEntry::new("movss", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovss"),
    );

    // MOVSLDUP xmm, xmm/m128
    table[0x12] = Some(
        SseOpcodeEntry::new("movsldup", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovsldup"),
    );

    // MOVSHDUP xmm, xmm/m128
    table[0x16] = Some(
        SseOpcodeEntry::new("movshdup", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovshdup"),
    );

    // CVTSI2SS xmm, r/m32/64
    table[0x2A] = Some(
        SseOpcodeEntry::new("cvtsi2ss", Operation::Move, SseEncoding::XmmGpr)
            .with_vex_mnemonic("vcvtsi2ss"),
    );

    // CVTTSS2SI r32/64, xmm/m32
    table[0x2C] = Some(
        SseOpcodeEntry::new("cvttss2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvttss2si"),
    );

    // CVTSS2SI r32/64, xmm/m32
    table[0x2D] = Some(
        SseOpcodeEntry::new("cvtss2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvtss2si"),
    );

    // SQRTSS xmm, xmm/m32
    table[0x51] = Some(
        SseOpcodeEntry::new("sqrtss", Operation::Other(0x51), SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vsqrtss"),
    );

    // RSQRTSS xmm, xmm/m32
    table[0x52] = Some(
        SseOpcodeEntry::new(
            "rsqrtss",
            Operation::Other(0x52),
            SseEncoding::XmmRmScalar32,
        )
        .with_vex_mnemonic("vrsqrtss"),
    );

    // RCPSS xmm, xmm/m32
    table[0x53] = Some(
        SseOpcodeEntry::new("rcpss", Operation::Other(0x53), SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vrcpss"),
    );

    // ADDSS xmm, xmm/m32
    table[0x58] = Some(
        SseOpcodeEntry::new("addss", Operation::Add, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vaddss"),
    );

    // MULSS xmm, xmm/m32
    table[0x59] = Some(
        SseOpcodeEntry::new("mulss", Operation::Mul, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vmulss"),
    );

    // CVTSS2SD xmm, xmm/m32
    table[0x5A] = Some(
        SseOpcodeEntry::new("cvtss2sd", Operation::Move, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vcvtss2sd"),
    );

    // CVTTPS2DQ xmm, xmm/m128
    table[0x5B] = Some(
        SseOpcodeEntry::new("cvttps2dq", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vcvttps2dq"),
    );

    // SUBSS xmm, xmm/m32
    table[0x5C] = Some(
        SseOpcodeEntry::new("subss", Operation::Sub, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vsubss"),
    );

    // MINSS xmm, xmm/m32
    table[0x5D] = Some(
        SseOpcodeEntry::new("minss", Operation::Other(0x5D), SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vminss"),
    );

    // DIVSS xmm, xmm/m32
    table[0x5E] = Some(
        SseOpcodeEntry::new("divss", Operation::Div, SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vdivss"),
    );

    // MAXSS xmm, xmm/m32
    table[0x5F] = Some(
        SseOpcodeEntry::new("maxss", Operation::Other(0x5F), SseEncoding::XmmRmScalar32)
            .with_vex_mnemonic("vmaxss"),
    );

    // MOVDQU xmm, xmm/m128
    table[0x6F] = Some(
        SseOpcodeEntry::new("movdqu", Operation::Move, SseEncoding::XmmRm)
            .with_vex_mnemonic("vmovdqu"),
    );

    // PSHUFHW xmm, xmm/m128, imm8
    table[0x70] = Some(
        SseOpcodeEntry::new("pshufhw", Operation::Other(0x70), SseEncoding::XmmRmImm8)
            .with_vex_mnemonic("vpshufhw"),
    );

    // MOVQ xmm, xmm/m64
    table[0x7E] = Some(
        SseOpcodeEntry::new("movq", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovq"),
    );

    // MOVDQU xmm/m128, xmm
    table[0x7F] = Some(
        SseOpcodeEntry::new("movdqu", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovdqu"),
    );

    // POPCNT r, r/m (F3 0F B8)
    table[0xB8] = Some(SseOpcodeEntry::new(
        "popcnt",
        Operation::Popcnt,
        SseEncoding::GprGprRm,
    ));

    // TZCNT r, r/m (F3 0F BC)
    table[0xBC] = Some(SseOpcodeEntry::new(
        "tzcnt",
        Operation::Tzcnt,
        SseEncoding::GprGprRm,
    ));

    // LZCNT r, r/m (F3 0F BD)
    table[0xBD] = Some(SseOpcodeEntry::new(
        "lzcnt",
        Operation::Lzcnt,
        SseEncoding::GprGprRm,
    ));

    table
};

/// SSE scalar double (F2 prefix) opcode variants.
pub static SSE_OPCODE_TABLE_F2: [Option<SseOpcodeEntry>; 256] = {
    let mut table: [Option<SseOpcodeEntry>; 256] = [NONE_SSE_ENTRY; 256];

    // MOVSD xmm, xmm/m64
    table[0x10] = Some(
        SseOpcodeEntry::new("movsd", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovsd"),
    );

    // MOVSD xmm/m64, xmm
    table[0x11] = Some(
        SseOpcodeEntry::new("movsd", Operation::Store, SseEncoding::RmXmm)
            .with_vex_mnemonic("vmovsd"),
    );

    // MOVDDUP xmm, xmm/m64
    table[0x12] = Some(
        SseOpcodeEntry::new("movddup", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmovddup"),
    );

    // CVTSI2SD xmm, r/m32/64
    table[0x2A] = Some(
        SseOpcodeEntry::new("cvtsi2sd", Operation::Move, SseEncoding::XmmGpr)
            .with_vex_mnemonic("vcvtsi2sd"),
    );

    // CVTTSD2SI r32/64, xmm/m64
    table[0x2C] = Some(
        SseOpcodeEntry::new("cvttsd2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvttsd2si"),
    );

    // CVTSD2SI r32/64, xmm/m64
    table[0x2D] = Some(
        SseOpcodeEntry::new("cvtsd2si", Operation::Move, SseEncoding::GprXmm)
            .with_vex_mnemonic("vcvtsd2si"),
    );

    // SQRTSD xmm, xmm/m64
    table[0x51] = Some(
        SseOpcodeEntry::new("sqrtsd", Operation::Other(0x51), SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vsqrtsd"),
    );

    // ADDSD xmm, xmm/m64
    table[0x58] = Some(
        SseOpcodeEntry::new("addsd", Operation::Add, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vaddsd"),
    );

    // MULSD xmm, xmm/m64
    table[0x59] = Some(
        SseOpcodeEntry::new("mulsd", Operation::Mul, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmulsd"),
    );

    // CVTSD2SS xmm, xmm/m64
    table[0x5A] = Some(
        SseOpcodeEntry::new("cvtsd2ss", Operation::Move, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vcvtsd2ss"),
    );

    // SUBSD xmm, xmm/m64
    table[0x5C] = Some(
        SseOpcodeEntry::new("subsd", Operation::Sub, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vsubsd"),
    );

    // MINSD xmm, xmm/m64
    table[0x5D] = Some(
        SseOpcodeEntry::new("minsd", Operation::Other(0x5D), SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vminsd"),
    );

    // DIVSD xmm, xmm/m64
    table[0x5E] = Some(
        SseOpcodeEntry::new("divsd", Operation::Div, SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vdivsd"),
    );

    // MAXSD xmm, xmm/m64
    table[0x5F] = Some(
        SseOpcodeEntry::new("maxsd", Operation::Other(0x5F), SseEncoding::XmmRmScalar64)
            .with_vex_mnemonic("vmaxsd"),
    );

    // PSHUFLW xmm, xmm/m128, imm8
    table[0x70] = Some(
        SseOpcodeEntry::new("pshuflw", Operation::Other(0x70), SseEncoding::XmmRmImm8)
            .with_vex_mnemonic("vpshuflw"),
    );

    table
};

/// Looks up an SSE opcode based on the opcode byte and prefix.
pub fn lookup_sse_opcode(
    opcode: u8,
    prefix_66: bool,
    prefix_f2: bool,
    prefix_f3: bool,
) -> Option<&'static SseOpcodeEntry> {
    // Priority: F2 > F3 > 66 > none
    if prefix_f2 {
        SSE_OPCODE_TABLE_F2[opcode as usize].as_ref()
    } else if prefix_f3 {
        SSE_OPCODE_TABLE_F3[opcode as usize].as_ref()
    } else if prefix_66 {
        SSE2_OPCODE_TABLE_66[opcode as usize].as_ref()
    } else {
        SSE_OPCODE_TABLE[opcode as usize].as_ref()
    }
}
