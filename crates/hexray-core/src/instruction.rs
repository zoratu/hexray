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

    // Comparison
    Compare,
    Test,

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
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::Shl => "shl",
            Self::Shr => "shr",
            Self::Sar => "sar",
            Self::Rol => "rol",
            Self::Ror => "ror",
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
    Above,         // CF=0 and ZF=0
    AboveOrEqual,  // CF=0
    Below,         // CF=1
    BelowOrEqual,  // CF=1 or ZF=1

    // Signed comparisons
    Greater,       // ZF=0 and SF=OF
    GreaterOrEqual,// SF=OF
    Less,          // SF!=OF
    LessOrEqual,   // ZF=1 or SF!=OF

    // Flag-based
    Sign,          // SF=1
    NotSign,       // SF=0
    Overflow,      // OF=1
    NotOverflow,   // OF=0
    Parity,        // PF=1
    NotParity,     // PF=0

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
    UnconditionalBranch {
        target: u64,
    },

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
    Call {
        target: u64,
        return_addr: u64,
    },

    /// Indirect call.
    IndirectCall {
        return_addr: u64,
    },

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
