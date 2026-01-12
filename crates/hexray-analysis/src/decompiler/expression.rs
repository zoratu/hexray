//! Expression representation for decompiled code.
//!
//! Converts low-level instructions into high-level expressions.

use hexray_core::{Instruction, Operand, Operation, Register, MemoryRef};
use std::fmt;

/// A high-level expression.
#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
}

/// The kind of expression.
#[derive(Debug, Clone)]
pub enum ExprKind {
    /// A variable (register or stack slot).
    Var(Variable),

    /// An integer literal.
    IntLit(i128),

    /// Binary operation: left op right.
    BinOp {
        op: BinOpKind,
        left: Box<Expr>,
        right: Box<Expr>,
    },

    /// Unary operation: op expr.
    UnaryOp {
        op: UnaryOpKind,
        operand: Box<Expr>,
    },

    /// Memory dereference: *expr or expr[index].
    Deref {
        addr: Box<Expr>,
        size: u8,
    },

    /// GOT/data reference: RIP-relative memory access with computed absolute address.
    /// Used for resolving `mov reg, [rip + offset]` patterns to symbol names.
    GotRef {
        /// The computed absolute address (rip + inst_size + displacement).
        address: u64,
        /// The address of the instruction that created this reference (for relocation lookup).
        instruction_address: u64,
        /// Size of the dereference in bytes (0 for address-of/LEA).
        size: u8,
        /// The original expression for display if resolution fails.
        display_expr: Box<Expr>,
        /// True if this is a dereference (MOV), false if address-of (LEA).
        is_deref: bool,
    },

    /// Address-of: &expr.
    AddressOf(Box<Expr>),

    /// Function call: func(args...).
    Call {
        target: CallTarget,
        args: Vec<Expr>,
    },

    /// Assignment: lhs = rhs.
    Assign {
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },

    /// Compound assignment: lhs op= rhs.
    CompoundAssign {
        op: BinOpKind,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },

    /// Conditional expression: cond ? then : else.
    Conditional {
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
    },

    /// Cast expression: (type)expr.
    Cast {
        expr: Box<Expr>,
        to_size: u8,
        signed: bool,
    },

    /// Phi node (for SSA - shows multiple possible values).
    Phi(Vec<Expr>),

    /// Unknown/unanalyzed expression.
    Unknown(String),
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar, // Arithmetic shift right

    // Comparison
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    ULt, // Unsigned less than
    ULe,
    UGt,
    UGe,

    // Logical
    LogicalAnd,
    LogicalOr,
}

impl BinOpKind {
    /// Returns the operator string for display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Sar => ">>", // Same visual, but semantically different
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::ULt => "<",  // Could use <u for clarity
            Self::ULe => "<=",
            Self::UGt => ">",
            Self::UGe => ">=",
            Self::LogicalAnd => "&&",
            Self::LogicalOr => "||",
        }
    }

    /// Returns the operator string for compound assignment (e.g., "+=" for Add).
    /// Returns None for comparison operators which don't support compound assignment.
    pub fn compound_op_str(&self) -> Option<&'static str> {
        match self {
            Self::Add => Some("+"),
            Self::Sub => Some("-"),
            Self::Mul => Some("*"),
            Self::Div => Some("/"),
            Self::Mod => Some("%"),
            Self::And => Some("&"),
            Self::Or => Some("|"),
            Self::Xor => Some("^"),
            Self::Shl => Some("<<"),
            Self::Shr => Some(">>"),
            Self::Sar => Some(">>"),
            // Comparison and logical operators don't have compound forms
            _ => None,
        }
    }

    /// Returns precedence (higher = binds tighter).
    pub fn precedence(&self) -> u8 {
        match self {
            Self::LogicalOr => 1,
            Self::LogicalAnd => 2,
            Self::Or => 3,
            Self::Xor => 4,
            Self::And => 5,
            Self::Eq | Self::Ne => 6,
            Self::Lt | Self::Le | Self::Gt | Self::Ge |
            Self::ULt | Self::ULe | Self::UGt | Self::UGe => 7,
            Self::Shl | Self::Shr | Self::Sar => 8,
            Self::Add | Self::Sub => 9,
            Self::Mul | Self::Div | Self::Mod => 10,
        }
    }

    /// Returns the negated comparison operator, if this is a comparison.
    pub fn negate(&self) -> Option<Self> {
        match self {
            Self::Eq => Some(Self::Ne),
            Self::Ne => Some(Self::Eq),
            Self::Lt => Some(Self::Ge),
            Self::Le => Some(Self::Gt),
            Self::Gt => Some(Self::Le),
            Self::Ge => Some(Self::Lt),
            Self::ULt => Some(Self::UGe),
            Self::ULe => Some(Self::UGt),
            Self::UGt => Some(Self::ULe),
            Self::UGe => Some(Self::ULt),
            _ => None,
        }
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOpKind {
    Neg,        // -x
    Not,        // ~x (bitwise)
    LogicalNot, // !x
    Inc,        // ++x
    Dec,        // --x
}

impl UnaryOpKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Neg => "-",
            Self::Not => "~",
            Self::LogicalNot => "!",
            Self::Inc => "++",
            Self::Dec => "--",
        }
    }
}

/// Call target.
#[derive(Debug, Clone)]
pub enum CallTarget {
    /// Direct call to address.
    /// `target` is the computed call target address.
    /// `call_site` is the address of the call instruction itself (for relocation lookup).
    Direct { target: u64, call_site: u64 },
    /// Direct call to named function.
    Named(String),
    /// Indirect call through expression.
    Indirect(Box<Expr>),
    /// Indirect call through GOT/PLT entry.
    /// `got_address` is the computed address of the GOT entry being dereferenced.
    /// `expr` is the expression for display if symbol resolution fails.
    IndirectGot { got_address: u64, expr: Box<Expr> },
}

/// A variable (abstraction over registers, stack slots, globals).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Variable {
    pub kind: VarKind,
    pub name: String,
    pub size: u8,
}

/// Variable kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VarKind {
    /// Register variable.
    Register(u16),
    /// Stack variable at offset from frame pointer.
    Stack(i64),
    /// Global variable at address.
    Global(u64),
    /// Function argument.
    Arg(u8),
    /// Temporary variable.
    Temp(u32),
}

impl Variable {
    /// Creates a register variable.
    pub fn from_register(reg: &Register) -> Self {
        Self {
            kind: VarKind::Register(reg.id),
            name: reg.name().to_string(),
            size: (reg.size / 8) as u8,
        }
    }

    /// Creates a stack variable.
    pub fn stack(offset: i64, size: u8) -> Self {
        let name = if offset < 0 {
            format!("var_{:x}", -offset)
        } else {
            format!("arg_{:x}", offset)
        };
        Self {
            kind: VarKind::Stack(offset),
            name,
            size,
        }
    }

    /// Creates a global variable.
    pub fn global(addr: u64, size: u8) -> Self {
        Self {
            kind: VarKind::Global(addr),
            name: format!("g_{:x}", addr),
            size,
        }
    }
}

impl Expr {
    /// Creates a variable expression.
    pub fn var(v: Variable) -> Self {
        Self { kind: ExprKind::Var(v) }
    }

    /// Creates an integer literal.
    pub fn int(value: i128) -> Self {
        Self { kind: ExprKind::IntLit(value) }
    }

    /// Creates a binary operation.
    pub fn binop(op: BinOpKind, left: Expr, right: Expr) -> Self {
        Self {
            kind: ExprKind::BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
    }

    /// Creates a unary operation.
    pub fn unary(op: UnaryOpKind, operand: Expr) -> Self {
        Self {
            kind: ExprKind::UnaryOp {
                op,
                operand: Box::new(operand),
            }
        }
    }

    /// Creates an assignment.
    pub fn assign(lhs: Expr, rhs: Expr) -> Self {
        Self {
            kind: ExprKind::Assign {
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            }
        }
    }

    /// Creates a memory dereference.
    pub fn deref(addr: Expr, size: u8) -> Self {
        Self {
            kind: ExprKind::Deref {
                addr: Box::new(addr),
                size,
            }
        }
    }

    /// Creates a GOT/data reference with a computed absolute address (for MOV from memory).
    /// `address` is the computed target address (rip + inst_size + displacement).
    /// `instruction_address` is the address of the instruction for relocation lookup.
    pub fn got_ref(address: u64, instruction_address: u64, size: u8, display_expr: Expr) -> Self {
        Self {
            kind: ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr: Box::new(display_expr),
                is_deref: true,
            }
        }
    }

    /// Creates a GOT/data address reference (for LEA - address-of, not dereference).
    /// `address` is the computed target address (rip + inst_size + displacement).
    /// `instruction_address` is the address of the instruction for relocation lookup.
    pub fn got_addr(address: u64, instruction_address: u64, display_expr: Expr) -> Self {
        Self {
            kind: ExprKind::GotRef {
                address,
                instruction_address,
                size: 0,
                display_expr: Box::new(display_expr),
                is_deref: false,
            }
        }
    }

    /// Creates a call expression.
    pub fn call(target: CallTarget, args: Vec<Expr>) -> Self {
        Self {
            kind: ExprKind::Call { target, args }
        }
    }

    /// Creates an unknown expression.
    pub fn unknown(desc: impl Into<String>) -> Self {
        Self { kind: ExprKind::Unknown(desc.into()) }
    }

    /// Negates a boolean expression (for conditions).
    /// For comparisons, inverts the operator (== becomes !=, < becomes >=, etc.)
    /// For other expressions, wraps with logical not.
    pub fn negate(self) -> Self {
        match self.kind {
            ExprKind::BinOp { op, left, right } => {
                if let Some(negated_op) = op.negate() {
                    Self::binop(negated_op, *left, *right)
                } else {
                    // Not a comparison, wrap with logical not
                    Self::unary(UnaryOpKind::LogicalNot, Self { kind: ExprKind::BinOp { op, left, right } })
                }
            }
            ExprKind::UnaryOp { op: UnaryOpKind::LogicalNot, operand } => {
                // Double negation: !!x -> x
                *operand
            }
            _ => Self::unary(UnaryOpKind::LogicalNot, self),
        }
    }

    /// Simplifies an expression by performing constant folding and algebraic simplifications.
    ///
    /// This includes:
    /// - Constant folding: `5 + 3` → `8`
    /// - Identity elimination: `x + 0` → `x`, `x * 1` → `x`
    /// - Zero multiplication: `x * 0` → `0`
    /// - Bitwise identity: `x | 0` → `x`, `x & 0xFFFFFFFF` → `x`
    /// - Double negation: `--x` → `x`, `~~x` → `x`
    pub fn simplify(self) -> Self {
        match self.kind {
            ExprKind::BinOp { op, left, right } => {
                // Recursively simplify operands first
                let left = left.simplify();
                let right = right.simplify();

                // Try constant folding
                if let (ExprKind::IntLit(l), ExprKind::IntLit(r)) = (&left.kind, &right.kind) {
                    if let Some(result) = fold_binary_constants(op, *l, *r) {
                        return Self::int(result);
                    }
                }

                // Algebraic simplifications
                match op {
                    // x + 0 = x, 0 + x = x
                    BinOpKind::Add => {
                        if matches!(right.kind, ExprKind::IntLit(0)) {
                            return left;
                        }
                        if matches!(left.kind, ExprKind::IntLit(0)) {
                            return right;
                        }
                    }
                    // x - 0 = x
                    BinOpKind::Sub => {
                        if matches!(right.kind, ExprKind::IntLit(0)) {
                            return left;
                        }
                        // x - x = 0 (when expressions are structurally equal)
                        if exprs_structurally_equal(&left, &right) {
                            return Self::int(0);
                        }
                    }
                    // x * 0 = 0, 0 * x = 0
                    // x * 1 = x, 1 * x = x
                    BinOpKind::Mul => {
                        if matches!(right.kind, ExprKind::IntLit(0)) || matches!(left.kind, ExprKind::IntLit(0)) {
                            return Self::int(0);
                        }
                        if matches!(right.kind, ExprKind::IntLit(1)) {
                            return left;
                        }
                        if matches!(left.kind, ExprKind::IntLit(1)) {
                            return right;
                        }
                    }
                    // x / 1 = x
                    BinOpKind::Div => {
                        if matches!(right.kind, ExprKind::IntLit(1)) {
                            return left;
                        }
                    }
                    // x | 0 = x, 0 | x = x
                    BinOpKind::Or => {
                        if matches!(right.kind, ExprKind::IntLit(0)) {
                            return left;
                        }
                        if matches!(left.kind, ExprKind::IntLit(0)) {
                            return right;
                        }
                        // x | x = x
                        if exprs_structurally_equal(&left, &right) {
                            return left;
                        }
                    }
                    // x & 0 = 0, 0 & x = 0
                    BinOpKind::And => {
                        if matches!(right.kind, ExprKind::IntLit(0)) || matches!(left.kind, ExprKind::IntLit(0)) {
                            return Self::int(0);
                        }
                        // x & x = x
                        if exprs_structurally_equal(&left, &right) {
                            return left;
                        }
                    }
                    // x ^ 0 = x, 0 ^ x = x
                    BinOpKind::Xor => {
                        if matches!(right.kind, ExprKind::IntLit(0)) {
                            return left;
                        }
                        if matches!(left.kind, ExprKind::IntLit(0)) {
                            return right;
                        }
                        // x ^ x = 0
                        if exprs_structurally_equal(&left, &right) {
                            return Self::int(0);
                        }
                    }
                    // x << 0 = x, x >> 0 = x
                    BinOpKind::Shl | BinOpKind::Shr | BinOpKind::Sar => {
                        if matches!(right.kind, ExprKind::IntLit(0)) {
                            return left;
                        }
                    }
                    _ => {}
                }

                Self::binop(op, left, right)
            }
            ExprKind::UnaryOp { op, operand } => {
                let operand = operand.simplify();

                // Constant folding for unary ops
                if let ExprKind::IntLit(n) = operand.kind {
                    match op {
                        UnaryOpKind::Neg => return Self::int(-n),
                        UnaryOpKind::Not => return Self::int(!n),
                        UnaryOpKind::LogicalNot => return Self::int(if n == 0 { 1 } else { 0 }),
                        _ => {}
                    }
                }

                // Double negation elimination
                if let ExprKind::UnaryOp { op: inner_op, operand: inner_operand } = &operand.kind {
                    match (op, inner_op) {
                        (UnaryOpKind::Neg, UnaryOpKind::Neg) => return *inner_operand.clone(),
                        (UnaryOpKind::Not, UnaryOpKind::Not) => return *inner_operand.clone(),
                        (UnaryOpKind::LogicalNot, UnaryOpKind::LogicalNot) => return *inner_operand.clone(),
                        _ => {}
                    }
                }

                Self::unary(op, operand)
            }
            ExprKind::Assign { lhs, rhs } => {
                Self::assign(lhs.simplify(), rhs.simplify())
            }
            ExprKind::Deref { addr, size } => {
                Self::deref(addr.simplify(), size)
            }
            ExprKind::Call { target, args } => {
                let args = args.into_iter().map(|a| a.simplify()).collect();
                Self::call(target, args)
            }
            // Other expression kinds pass through unchanged
            _ => self,
        }
    }

    /// Converts an operand to an expression.
    pub fn from_operand(op: &Operand) -> Self {
        match op {
            Operand::Register(reg) => Self::var(Variable::from_register(reg)),
            Operand::Immediate(imm) => Self::int(imm.value),
            Operand::Memory(mem) => Self::from_memory_ref(mem),
            Operand::PcRelative { target, .. } => Self::int(*target as i128),
        }
    }

    /// Converts a memory reference to an expression.
    fn from_memory_ref(mem: &MemoryRef) -> Self {
        let mut addr_expr: Option<Expr> = None;

        // Build address expression: base + index*scale + disp
        if let Some(ref base) = mem.base {
            addr_expr = Some(Self::var(Variable::from_register(base)));
        }

        if let Some(ref index) = mem.index {
            let index_expr = Self::var(Variable::from_register(index));
            let scaled = if mem.scale > 1 {
                Self::binop(BinOpKind::Mul, index_expr, Self::int(mem.scale as i128))
            } else {
                index_expr
            };

            addr_expr = Some(match addr_expr {
                Some(base) => Self::binop(BinOpKind::Add, base, scaled),
                None => scaled,
            });
        }

        if mem.displacement != 0 {
            let disp_expr = Self::int(mem.displacement as i128);
            addr_expr = Some(match addr_expr {
                Some(base) => Self::binop(BinOpKind::Add, base, disp_expr),
                None => disp_expr,
            });
        }

        let addr = addr_expr.unwrap_or_else(|| Self::int(0));
        Self::deref(addr, mem.size)
    }

    /// Converts an instruction to an expression/statement.
    pub fn from_instruction(inst: &Instruction) -> Self {
        let ops = &inst.operands;

        match inst.operation {
            Operation::Move => {
                if ops.len() >= 2 {
                    // Check for RIP-relative memory load (e.g., mov rdi, [rip + offset])
                    let rhs = if let Operand::Memory(mem) = &ops[1] {
                        let base_name = mem.base.as_ref().map(|r| r.name()).unwrap_or("");
                        if base_name == "rip" && mem.index.is_none() {
                            // Compute absolute address: inst.address + inst.size + displacement
                            let abs_addr = (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
                            let display_expr = Self::from_memory_ref(mem);
                            Self::got_ref(abs_addr, inst.address, mem.size, display_expr)
                        } else {
                            Self::from_operand(&ops[1])
                        }
                    } else {
                        Self::from_operand(&ops[1])
                    };
                    Self::assign(Self::from_operand(&ops[0]), rhs)
                } else if ops.len() == 1 {
                    Self::from_operand(&ops[0])
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Load => {
                if ops.len() == 3 {
                    // ARM64 ldp: load pair [reg1, reg2, mem]
                    // Just load into first register (second is typically x30/link register)
                    // This is used in epilogue (ldp x29, x30, [sp + X])
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::from_operand(&ops[2]),
                    )
                } else if ops.len() >= 2 {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::from_operand(&ops[1]),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Store => {
                if ops.len() >= 2 {
                    Self::assign(
                        Self::from_operand(&ops[1]),
                        Self::from_operand(&ops[0]),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Add => Self::make_binop(ops, BinOpKind::Add, &inst.mnemonic),
            Operation::Sub => {
                // Special case: sub reg, reg is a zeroing idiom
                if ops.len() >= 2 && ops[0] == ops[1] {
                    Self::assign(Self::from_operand(&ops[0]), Self::int(0))
                } else {
                    Self::make_binop(ops, BinOpKind::Sub, &inst.mnemonic)
                }
            }
            Operation::Mul => Self::make_binop(ops, BinOpKind::Mul, &inst.mnemonic),
            Operation::Div => Self::make_binop(ops, BinOpKind::Div, &inst.mnemonic),
            Operation::And => Self::make_binop(ops, BinOpKind::And, &inst.mnemonic),
            Operation::Or => Self::make_binop(ops, BinOpKind::Or, &inst.mnemonic),
            Operation::Xor => {
                // Special case: xor reg, reg is a zeroing idiom
                if ops.len() >= 2 && ops[0] == ops[1] {
                    Self::assign(Self::from_operand(&ops[0]), Self::int(0))
                } else {
                    Self::make_binop(ops, BinOpKind::Xor, &inst.mnemonic)
                }
            }
            Operation::Shl => Self::make_binop(ops, BinOpKind::Shl, &inst.mnemonic),
            Operation::Shr => Self::make_binop(ops, BinOpKind::Shr, &inst.mnemonic),
            Operation::Sar => Self::make_binop(ops, BinOpKind::Sar, &inst.mnemonic),
            Operation::Rol | Operation::Ror => {
                // Rotate operations - emit as function-style for now
                // Could be expanded to proper rotate expressions later
                if ops.len() >= 2 {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(
                            CallTarget::Named(inst.mnemonic.clone()),
                            vec![Self::from_operand(&ops[0]), Self::from_operand(&ops[1])],
                        ),
                    )
                } else if ops.len() == 1 {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(
                            CallTarget::Named(inst.mnemonic.clone()),
                            vec![Self::from_operand(&ops[0]), Self::int(1)],
                        ),
                    )
                } else {
                    Self::unknown("/* nop */")
                }
            }
            Operation::Compare | Operation::Test => {
                // Compare and test set flags but don't produce a visible result.
                // They're consumed by subsequent conditional branches.
                // Emit as a no-op comment to avoid cluttering output.
                Self::unknown("/* nop */")
            }
            Operation::Neg => {
                if !ops.is_empty() {
                    let operand = Self::from_operand(&ops[0]);
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::unary(UnaryOpKind::Neg, operand),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Not => {
                if !ops.is_empty() {
                    let operand = Self::from_operand(&ops[0]);
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::unary(UnaryOpKind::Not, operand),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Inc => {
                if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::binop(BinOpKind::Add, Self::from_operand(&ops[0]), Self::int(1)),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Dec => {
                if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::binop(BinOpKind::Sub, Self::from_operand(&ops[0]), Self::int(1)),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Call => {
                let call_site = inst.address;
                let target = if !ops.is_empty() {
                    match &ops[0] {
                        Operand::PcRelative { target, .. } => CallTarget::Direct { target: *target, call_site },
                        Operand::Immediate(imm) => CallTarget::Direct { target: imm.as_u64(), call_site },
                        Operand::Memory(mem) => {
                            // Check for RIP-relative addressing (GOT/PLT pattern)
                            // e.g., call [rip + 0x1234] = call through GOT entry
                            if mem.base.as_ref().map(|r| r.name()).unwrap_or("") == "rip" && mem.index.is_none() {
                                // Compute GOT address: inst.address + inst.size + displacement
                                // inst.size is stored in inst.size field
                                let got_address = (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
                                CallTarget::IndirectGot {
                                    got_address,
                                    expr: Box::new(Self::from_operand(&ops[0])),
                                }
                            } else {
                                CallTarget::Indirect(Box::new(Self::from_operand(&ops[0])))
                            }
                        }
                        _ => CallTarget::Indirect(Box::new(Self::from_operand(&ops[0]))),
                    }
                } else {
                    CallTarget::Named("unknown".to_string())
                };
                Self::call(target, vec![])
            }
            Operation::Push => {
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named("push".to_string()),
                        vec![Self::from_operand(&ops[0])],
                    )
                } else {
                    Self::unknown("push")
                }
            }
            Operation::Pop => {
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named("pop".to_string()),
                        vec![Self::from_operand(&ops[0])],
                    )
                } else {
                    Self::unknown("pop")
                }
            }
            Operation::Return => Self::unknown("return"),
            Operation::Nop => Self::unknown("/* nop */"),
            Operation::Syscall => Self::call(CallTarget::Named("syscall".to_string()), vec![]),
            Operation::Interrupt => {
                if !ops.is_empty() {
                    Self::call(CallTarget::Named("int".to_string()), vec![Self::from_operand(&ops[0])])
                } else {
                    Self::call(CallTarget::Named("int".to_string()), vec![])
                }
            }
            Operation::Halt => Self::call(CallTarget::Named("halt".to_string()), vec![]),
            Operation::Exchange => {
                // XCHG swaps two operands - emit as a swap pseudo-function
                if ops.len() >= 2 {
                    Self::call(
                        CallTarget::Named("swap".to_string()),
                        vec![Self::from_operand(&ops[0]), Self::from_operand(&ops[1])],
                    )
                } else {
                    Self::unknown("/* nop */")
                }
            }
            Operation::Jump | Operation::ConditionalJump => {
                // Jumps are handled by control flow structuring, not as expressions
                Self::unknown("/* nop */")
            }
            Operation::Other(_) => {
                // Unknown operation - emit the mnemonic as a function call if it has operands
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named(inst.mnemonic.clone()),
                        ops.iter().map(Self::from_operand).collect(),
                    )
                } else {
                    Self::unknown("/* nop */")
                }
            }
            Operation::LoadEffectiveAddress => {
                // ADRP/ADR/LEA - load effective address
                if ops.len() >= 2 {
                    // operands[0] = destination register
                    // operands[1] = PcRelative or Memory address
                    let addr_val = match &ops[1] {
                        Operand::PcRelative { target, .. } => Self::int(*target as i128),
                        Operand::Memory(mem) => {
                            // Check for RIP-relative addressing (e.g., lea rdi, [rip + offset])
                            if mem.base.as_ref().map(|r| r.name()).unwrap_or("") == "rip" && mem.index.is_none() {
                                // Compute absolute address: inst.address + inst.size + displacement
                                let abs_addr = (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
                                // Use GotAddr for LEA (address-of, not dereference)
                                let display_expr = Self::int(abs_addr as i128);
                                Self::got_addr(abs_addr, inst.address, display_expr)
                            } else {
                                Self::from_memory_ref(mem)
                            }
                        }
                        Operand::Immediate(imm) => Self::int(imm.value),
                        _ => Self::from_operand(&ops[1]),
                    };
                    Self::assign(Self::from_operand(&ops[0]), addr_val)
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
        }
    }

    fn make_binop(ops: &[Operand], op: BinOpKind, mnemonic: &str) -> Self {
        if ops.len() >= 3 {
            // dest = src1 op src2
            Self::assign(
                Self::from_operand(&ops[0]),
                Self::binop(op, Self::from_operand(&ops[1]), Self::from_operand(&ops[2])),
            )
        } else if ops.len() == 2 {
            // dest op= src (common x86 pattern)
            Self::assign(
                Self::from_operand(&ops[0]),
                Self::binop(op, Self::from_operand(&ops[0]), Self::from_operand(&ops[1])),
            )
        } else {
            Self::unknown(mnemonic)
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ExprKind::Var(v) => write!(f, "{}", v.name),
            ExprKind::IntLit(n) => {
                if *n >= 0 && *n < 10 {
                    write!(f, "{}", n)
                } else if *n < 0 {
                    write!(f, "-{:#x}", -n)
                } else {
                    write!(f, "{:#x}", n)
                }
            }
            ExprKind::BinOp { op, left, right } => {
                write!(f, "{} {} {}", left, op.as_str(), right)
            }
            ExprKind::UnaryOp { op, operand } => {
                write!(f, "{}{}", op.as_str(), operand)
            }
            ExprKind::Deref { addr, size } => {
                let prefix = match size {
                    1 => "*(uint8_t*)",
                    2 => "*(uint16_t*)",
                    4 => "*(uint32_t*)",
                    8 => "*(uint64_t*)",
                    _ => "*",
                };
                write!(f, "{}({})", prefix, addr)
            }
            ExprKind::GotRef { display_expr, size, is_deref, .. } => {
                // Default display falls back to showing the original expression
                if *is_deref {
                    let prefix = match size {
                        1 => "*(uint8_t*)",
                        2 => "*(uint16_t*)",
                        4 => "*(uint32_t*)",
                        8 => "*(uint64_t*)",
                        _ => "*",
                    };
                    write!(f, "{}({})", prefix, display_expr)
                } else {
                    // Address-of (LEA) - just show the address
                    write!(f, "{}", display_expr)
                }
            }
            ExprKind::AddressOf(e) => write!(f, "&{}", e),
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Direct { target, .. } => write!(f, "sub_{:x}", target)?,
                    CallTarget::Named(name) => write!(f, "{}", name)?,
                    CallTarget::Indirect(e) => write!(f, "({})", e)?,
                    CallTarget::IndirectGot { expr, .. } => write!(f, "({})", expr)?,
                }
                write!(f, "(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ")")
            }
            ExprKind::Assign { lhs, rhs } => write!(f, "{} = {}", lhs, rhs),
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                write!(f, "{} {}= {}", lhs, op.as_str(), rhs)
            }
            ExprKind::Conditional { cond, then_expr, else_expr } => {
                write!(f, "{} ? {} : {}", cond, then_expr, else_expr)
            }
            ExprKind::Cast { expr, to_size, signed } => {
                let type_name = match (to_size, signed) {
                    (1, true) => "int8_t",
                    (1, false) => "uint8_t",
                    (2, true) => "int16_t",
                    (2, false) => "uint16_t",
                    (4, true) => "int32_t",
                    (4, false) => "uint32_t",
                    (8, true) => "int64_t",
                    (8, false) => "uint64_t",
                    _ => "unknown",
                };
                write!(f, "({}){}", type_name, expr)
            }
            ExprKind::Phi(exprs) => {
                write!(f, "φ(")?;
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", e)?;
                }
                write!(f, ")")
            }
            ExprKind::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// Resolves ARM64 ADRP + ADD patterns in a list of expressions.
///
/// When ARM64 loads a PC-relative address, it uses two instructions:
/// ```text
/// adrp x0, 0x100000000    ; Load page address (4KB aligned)
/// add x0, x0, 0x58a       ; Add offset within page
/// ```
///
/// This function combines these patterns into a single address expression.
pub fn resolve_adrp_patterns(exprs: Vec<Expr>) -> Vec<Expr> {
    let mut result = Vec::with_capacity(exprs.len());
    let mut i = 0;

    while i < exprs.len() {
        // Look for ADRP pattern: reg = page_address (from adrp mnemonic tracking)
        if let Some(combined) = try_combine_adrp_add(&exprs, i) {
            result.push(combined);
            i += 2; // Skip both adrp and add
        } else {
            result.push(exprs[i].clone());
            i += 1;
        }
    }

    result
}

/// Tries to combine an ADRP + ADD pattern at position i.
fn try_combine_adrp_add(exprs: &[Expr], i: usize) -> Option<Expr> {
    if i + 1 >= exprs.len() {
        return None;
    }

    // First expression should be: reg = page_address (ADRP result)
    let (adrp_reg, page_addr) = match_adrp_assignment(&exprs[i])?;

    // Second expression should be: reg = reg + offset (ADD)
    let (add_dst, add_src, offset) = match_add_assignment(&exprs[i + 1])?;

    // Check that the registers match
    if adrp_reg != add_dst || adrp_reg != add_src {
        return None;
    }

    // Combine the addresses
    let combined_addr = page_addr.wrapping_add(offset as u64);

    // Create combined assignment: reg = combined_addr
    Some(Expr::assign(
        Expr::var(Variable {
            name: adrp_reg,
            kind: VarKind::Register(0), // Register ID not needed for display
            size: 8, // 64-bit register
        }),
        Expr::int(combined_addr as i128),
    ))
}

/// Matches an ADRP assignment: reg = page_address
fn match_adrp_assignment(expr: &Expr) -> Option<(String, u64)> {
    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        // LHS should be a register variable
        let reg_name = if let ExprKind::Var(v) = &lhs.kind {
            v.name.clone()
        } else {
            return None;
        };

        // RHS should be an integer literal (the page address from ADRP)
        if let ExprKind::IntLit(addr) = &rhs.kind {
            // ADRP addresses are page-aligned (multiple of 4KB)
            let addr = *addr as u64;
            if addr & 0xFFF == 0 || addr > 0x1000 {
                // Looks like a page address
                return Some((reg_name, addr));
            }
        }
    }
    None
}

/// Matches an ADD assignment: dst = src + offset
fn match_add_assignment(expr: &Expr) -> Option<(String, String, i128)> {
    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        // LHS should be a register variable
        let dst_reg = if let ExprKind::Var(v) = &lhs.kind {
            v.name.clone()
        } else {
            return None;
        };

        // RHS should be a binary add operation
        if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &rhs.kind {
            // Left operand should be a register
            let src_reg = if let ExprKind::Var(v) = &left.kind {
                v.name.clone()
            } else {
                return None;
            };

            // Right operand should be an integer literal (offset)
            if let ExprKind::IntLit(offset) = &right.kind {
                return Some((dst_reg, src_reg, *offset));
            }
        }
    }
    None
}

/// Performs constant folding for binary operations.
/// Returns Some(result) if both operands are constants, None otherwise.
fn fold_binary_constants(op: BinOpKind, left: i128, right: i128) -> Option<i128> {
    match op {
        BinOpKind::Add => Some(left.wrapping_add(right)),
        BinOpKind::Sub => Some(left.wrapping_sub(right)),
        BinOpKind::Mul => Some(left.wrapping_mul(right)),
        BinOpKind::Div => {
            if right != 0 {
                Some(left / right)
            } else {
                None // Avoid division by zero
            }
        }
        BinOpKind::Mod => {
            if right != 0 {
                Some(left % right)
            } else {
                None
            }
        }
        BinOpKind::And => Some(left & right),
        BinOpKind::Or => Some(left | right),
        BinOpKind::Xor => Some(left ^ right),
        BinOpKind::Shl => {
            if right >= 0 && right < 128 {
                Some(left << (right as u32))
            } else {
                None
            }
        }
        BinOpKind::Shr | BinOpKind::Sar => {
            if right >= 0 && right < 128 {
                Some(left >> (right as u32))
            } else {
                None
            }
        }
        // Comparison operators return 0 or 1
        BinOpKind::Eq => Some(if left == right { 1 } else { 0 }),
        BinOpKind::Ne => Some(if left != right { 1 } else { 0 }),
        BinOpKind::Lt | BinOpKind::ULt => Some(if left < right { 1 } else { 0 }),
        BinOpKind::Le | BinOpKind::ULe => Some(if left <= right { 1 } else { 0 }),
        BinOpKind::Gt | BinOpKind::UGt => Some(if left > right { 1 } else { 0 }),
        BinOpKind::Ge | BinOpKind::UGe => Some(if left >= right { 1 } else { 0 }),
        BinOpKind::LogicalAnd => Some(if left != 0 && right != 0 { 1 } else { 0 }),
        BinOpKind::LogicalOr => Some(if left != 0 || right != 0 { 1 } else { 0 }),
    }
}

/// Checks if two expressions are structurally equal.
/// Used for simplifications like `x - x = 0` and `x ^ x = 0`.
fn exprs_structurally_equal(left: &Expr, right: &Expr) -> bool {
    match (&left.kind, &right.kind) {
        (ExprKind::Var(v1), ExprKind::Var(v2)) => v1 == v2,
        (ExprKind::IntLit(n1), ExprKind::IntLit(n2)) => n1 == n2,
        (
            ExprKind::BinOp { op: op1, left: l1, right: r1 },
            ExprKind::BinOp { op: op2, left: l2, right: r2 }
        ) => {
            op1 == op2 && exprs_structurally_equal(l1, l2) && exprs_structurally_equal(r1, r2)
        }
        (
            ExprKind::UnaryOp { op: op1, operand: o1 },
            ExprKind::UnaryOp { op: op2, operand: o2 }
        ) => {
            op1 == op2 && exprs_structurally_equal(o1, o2)
        }
        (
            ExprKind::Deref { addr: a1, size: s1 },
            ExprKind::Deref { addr: a2, size: s2 }
        ) => {
            s1 == s2 && exprs_structurally_equal(a1, a2)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_folding_arithmetic() {
        // 5 + 3 = 8
        let expr = Expr::binop(BinOpKind::Add, Expr::int(5), Expr::int(3));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(8)));

        // 10 - 4 = 6
        let expr = Expr::binop(BinOpKind::Sub, Expr::int(10), Expr::int(4));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(6)));

        // 6 * 7 = 42
        let expr = Expr::binop(BinOpKind::Mul, Expr::int(6), Expr::int(7));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(42)));

        // 20 / 4 = 5
        let expr = Expr::binop(BinOpKind::Div, Expr::int(20), Expr::int(4));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(5)));
    }

    #[test]
    fn test_identity_elimination() {
        let x = Expr::unknown("x");

        // x + 0 = x
        let expr = Expr::binop(BinOpKind::Add, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // 0 + x = x
        let expr = Expr::binop(BinOpKind::Add, Expr::int(0), x.clone());
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // x - 0 = x
        let expr = Expr::binop(BinOpKind::Sub, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // x * 1 = x
        let expr = Expr::binop(BinOpKind::Mul, x.clone(), Expr::int(1));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // 1 * x = x
        let expr = Expr::binop(BinOpKind::Mul, Expr::int(1), x.clone());
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // x / 1 = x
        let expr = Expr::binop(BinOpKind::Div, x.clone(), Expr::int(1));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));
    }

    #[test]
    fn test_zero_multiplication() {
        let x = Expr::unknown("x");

        // x * 0 = 0
        let expr = Expr::binop(BinOpKind::Mul, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(0)));

        // 0 * x = 0
        let expr = Expr::binop(BinOpKind::Mul, Expr::int(0), x.clone());
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(0)));
    }

    #[test]
    fn test_bitwise_simplifications() {
        let x = Expr::unknown("x");

        // x | 0 = x
        let expr = Expr::binop(BinOpKind::Or, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // x & 0 = 0
        let expr = Expr::binop(BinOpKind::And, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(0)));

        // x ^ 0 = x
        let expr = Expr::binop(BinOpKind::Xor, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // Constant bitwise
        let expr = Expr::binop(BinOpKind::And, Expr::int(0xFF), Expr::int(0x0F));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(0x0F)));
    }

    #[test]
    fn test_unary_constant_folding() {
        // -5 = -5
        let expr = Expr::unary(UnaryOpKind::Neg, Expr::int(5));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(-5)));

        // !0 = 1
        let expr = Expr::unary(UnaryOpKind::LogicalNot, Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(1)));

        // !5 = 0
        let expr = Expr::unary(UnaryOpKind::LogicalNot, Expr::int(5));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(0)));
    }

    #[test]
    fn test_double_negation_elimination() {
        let x = Expr::unknown("x");

        // --x = x
        let expr = Expr::unary(UnaryOpKind::Neg, Expr::unary(UnaryOpKind::Neg, x.clone()));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // ~~x = x
        let expr = Expr::unary(UnaryOpKind::Not, Expr::unary(UnaryOpKind::Not, x.clone()));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // !!x = x
        let expr = Expr::unary(UnaryOpKind::LogicalNot, Expr::unary(UnaryOpKind::LogicalNot, x.clone()));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));
    }

    #[test]
    fn test_shift_simplifications() {
        let x = Expr::unknown("x");

        // x << 0 = x
        let expr = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // x >> 0 = x
        let expr = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(0));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // 8 << 2 = 32
        let expr = Expr::binop(BinOpKind::Shl, Expr::int(8), Expr::int(2));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(32)));
    }

    #[test]
    fn test_nested_simplification() {
        // (5 + 3) * 2 = 16
        let inner = Expr::binop(BinOpKind::Add, Expr::int(5), Expr::int(3));
        let expr = Expr::binop(BinOpKind::Mul, inner, Expr::int(2));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::IntLit(16)));

        // (x + 0) * 1 = x
        let x = Expr::unknown("x");
        let inner = Expr::binop(BinOpKind::Add, x.clone(), Expr::int(0));
        let expr = Expr::binop(BinOpKind::Mul, inner, Expr::int(1));
        let simplified = expr.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));
    }
}
