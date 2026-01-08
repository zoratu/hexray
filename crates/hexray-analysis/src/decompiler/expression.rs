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
    Direct(u64),
    /// Direct call to named function.
    Named(String),
    /// Indirect call through expression.
    Indirect(Box<Expr>),
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
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::from_operand(&ops[1]),
                    )
                } else if ops.len() == 1 {
                    Self::from_operand(&ops[0])
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Load => {
                if ops.len() >= 2 {
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
            Operation::Sub => Self::make_binop(ops, BinOpKind::Sub, &inst.mnemonic),
            Operation::Mul => Self::make_binop(ops, BinOpKind::Mul, &inst.mnemonic),
            Operation::Div => Self::make_binop(ops, BinOpKind::Div, &inst.mnemonic),
            Operation::And => Self::make_binop(ops, BinOpKind::And, &inst.mnemonic),
            Operation::Or => Self::make_binop(ops, BinOpKind::Or, &inst.mnemonic),
            Operation::Xor => Self::make_binop(ops, BinOpKind::Xor, &inst.mnemonic),
            Operation::Shl => Self::make_binop(ops, BinOpKind::Shl, &inst.mnemonic),
            Operation::Shr => Self::make_binop(ops, BinOpKind::Shr, &inst.mnemonic),
            Operation::Sar => Self::make_binop(ops, BinOpKind::Sar, &inst.mnemonic),
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
                let target = if !ops.is_empty() {
                    match &ops[0] {
                        Operand::PcRelative { target, .. } => CallTarget::Direct(*target),
                        Operand::Immediate(imm) => CallTarget::Direct(imm.as_u64()),
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
            Operation::LoadEffectiveAddress => {
                // ADRP/ADR/LEA - load effective address
                if ops.len() >= 2 {
                    // operands[0] = destination register
                    // operands[1] = PcRelative or Memory address
                    let addr_val = match &ops[1] {
                        Operand::PcRelative { target, .. } => Self::int(*target as i128),
                        Operand::Memory(mem) => Self::from_memory_ref(mem),
                        Operand::Immediate(imm) => Self::int(imm.value),
                        _ => Self::from_operand(&ops[1]),
                    };
                    Self::assign(Self::from_operand(&ops[0]), addr_val)
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            _ => Self::unknown(&inst.mnemonic),
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
            ExprKind::AddressOf(e) => write!(f, "&{}", e),
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Direct(addr) => write!(f, "sub_{:x}", addr)?,
                    CallTarget::Named(name) => write!(f, "{}", name)?,
                    CallTarget::Indirect(e) => write!(f, "({})", e)?,
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
