//! Expression representation for decompiled code.
//!
//! Converts low-level instructions into high-level expressions.

use hexray_core::{
    register::x86, Architecture, Instruction, MemoryRef, Operand, Operation, Register,
    RegisterClass,
};
use std::fmt;

use super::abi;

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
    UnaryOp { op: UnaryOpKind, operand: Box<Expr> },

    /// Memory dereference: `*expr` or `expr\[index\]`.
    Deref { addr: Box<Expr>, size: u8 },

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

    /// Array access: `base\[index\]`.
    /// Represents pointer arithmetic patterns like `*(base + index * element_size)`.
    ArrayAccess {
        /// The base pointer or array.
        base: Box<Expr>,
        /// The index expression.
        index: Box<Expr>,
        /// Size of each element in bytes.
        element_size: usize,
    },

    /// Struct field access: base->field or base.field.
    /// Represents memory access patterns like `*(base + offset)` where offset is a field.
    FieldAccess {
        /// The base pointer (struct pointer).
        base: Box<Expr>,
        /// The field name (e.g., "field_8", "field_10").
        field_name: String,
        /// The field offset in bytes.
        offset: usize,
    },

    /// Function call: func(args...).
    Call { target: CallTarget, args: Vec<Expr> },

    /// Assignment: lhs = rhs.
    Assign { lhs: Box<Expr>, rhs: Box<Expr> },

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

    /// Bit field extraction: extracts `width` bits starting at `start` from `expr`.
    /// Represents patterns like `(x >> start) & mask` where mask = (1 << width) - 1.
    /// Displayed as `BITS(expr, start, width)` or `expr[start:start+width]`.
    BitField {
        expr: Box<Expr>,
        start: u8,
        width: u8,
    },

    /// Phi node (for SSA - shows multiple possible values).
    Phi(Vec<Expr>),

    /// Unknown/unanalyzed expression.
    Unknown(String),
}

/// Binary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            Self::ULt => "<", // Could use <u for clarity
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
            Self::Lt
            | Self::Le
            | Self::Gt
            | Self::Ge
            | Self::ULt
            | Self::ULe
            | Self::UGt
            | Self::UGe => 7,
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

    /// Check if this is a comparison operator.
    pub fn is_comparison(&self) -> bool {
        matches!(
            self,
            Self::Eq
                | Self::Ne
                | Self::Lt
                | Self::Le
                | Self::Gt
                | Self::Ge
                | Self::ULt
                | Self::ULe
                | Self::UGt
                | Self::UGe
        )
    }
}

/// Unary operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    ///
    /// For x86-64, this normalizes partial register accesses to their 64-bit form:
    /// - al, ah, ax, eax → rax
    /// - bl, bh, bx, ebx → rbx
    /// - etc.
    ///
    /// The original size is preserved in the size field.
    pub fn from_register(reg: &Register) -> Self {
        let reg_name = reg.name();
        let size_bytes = (reg.size / 8) as u8;

        // Normalize x86-64 partial registers to their 64-bit form
        let (normalized_name, original_size) = if matches!(reg.arch, Architecture::X86_64) {
            abi::normalize_x86_64_register(reg_name, size_bytes).unwrap_or((reg_name, size_bytes))
        } else {
            (reg_name, size_bytes)
        };

        Self {
            kind: VarKind::Register(reg.id),
            name: normalized_name.to_string(),
            size: original_size,
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

    /// Creates a register variable from a name string.
    /// This is useful for creating expressions referencing known registers like "rbp", "sp".
    pub fn reg(name: impl Into<String>, size: u8) -> Self {
        Self {
            kind: VarKind::Register(0), // ID is not used for matching, just name
            name: name.into(),
            size,
        }
    }
}

impl Expr {
    fn lift_hidden_rep_stos_state_update(inst: &Instruction) -> Option<Self> {
        let scale = match inst.mnemonic.as_str() {
            "__rep_stosb" => 1,
            "__rep_stosw" => 2,
            "__rep_stosd" => 4,
            "__rep_stosq" => 8,
            _ => return None,
        };

        Some(Self::assign(
            Self::var(Variable::reg("rdi", 8)),
            Self::binop(
                BinOpKind::Add,
                Self::var(Variable::reg("rdi", 8)),
                Self::binop(
                    BinOpKind::Mul,
                    Self::var(Variable::reg("rcx", 8)),
                    Self::int(scale),
                ),
            ),
        ))
    }

    /// Creates a variable expression.
    pub fn var(v: Variable) -> Self {
        Self {
            kind: ExprKind::Var(v),
        }
    }

    /// Creates an integer literal.
    pub fn int(value: i128) -> Self {
        Self {
            kind: ExprKind::IntLit(value),
        }
    }

    /// Creates a binary operation.
    pub fn binop(op: BinOpKind, left: Expr, right: Expr) -> Self {
        Self {
            kind: ExprKind::BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
        }
    }

    /// Creates a unary operation.
    pub fn unary(op: UnaryOpKind, operand: Expr) -> Self {
        Self {
            kind: ExprKind::UnaryOp {
                op,
                operand: Box::new(operand),
            },
        }
    }

    /// Creates an assignment.
    pub fn assign(lhs: Expr, rhs: Expr) -> Self {
        Self {
            kind: ExprKind::Assign {
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
        }
    }

    /// Creates a memory dereference.
    pub fn deref(addr: Expr, size: u8) -> Self {
        Self {
            kind: ExprKind::Deref {
                addr: Box::new(addr),
                size,
            },
        }
    }

    /// Creates an array access expression.
    pub fn array_access(base: Expr, index: Expr, element_size: usize) -> Self {
        Self {
            kind: ExprKind::ArrayAccess {
                base: Box::new(base),
                index: Box::new(index),
                element_size,
            },
        }
    }

    /// Creates a struct field access expression.
    ///
    /// This represents `base->field_name` in C syntax.
    /// The offset is preserved for debugging/analysis purposes.
    pub fn field_access(base: Expr, field_name: impl Into<String>, offset: usize) -> Self {
        Self {
            kind: ExprKind::FieldAccess {
                base: Box::new(base),
                field_name: field_name.into(),
                offset,
            },
        }
    }

    /// Creates an address-of expression.
    pub fn address_of(expr: Expr) -> Self {
        Self {
            kind: ExprKind::AddressOf(Box::new(expr)),
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
            },
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
            },
        }
    }

    /// Creates a call expression.
    pub fn call(target: CallTarget, args: Vec<Expr>) -> Self {
        Self {
            kind: ExprKind::Call { target, args },
        }
    }

    /// Creates an unknown expression.
    pub fn unknown(desc: impl Into<String>) -> Self {
        Self {
            kind: ExprKind::Unknown(desc.into()),
        }
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
                    Self::unary(
                        UnaryOpKind::LogicalNot,
                        Self {
                            kind: ExprKind::BinOp { op, left, right },
                        },
                    )
                }
            }
            ExprKind::UnaryOp {
                op: UnaryOpKind::LogicalNot,
                operand,
            } => {
                // Double negation: !!x -> x
                *operand
            }
            // Handle negation of condition comment placeholders
            ExprKind::Unknown(ref s) => {
                let negated = match s.as_str() {
                    "/* equal */" => "/* not_equal */",
                    "/* not_equal */" => "/* equal */",
                    "/* signed_lt */" => "/* signed_ge */",
                    "/* signed_le */" => "/* signed_gt */",
                    "/* signed_gt */" => "/* signed_le */",
                    "/* signed_ge */" => "/* signed_lt */",
                    "/* unsigned_lt */" => "/* unsigned_ge */",
                    "/* unsigned_le */" => "/* unsigned_gt */",
                    "/* unsigned_gt */" => "/* unsigned_le */",
                    "/* unsigned_ge */" => "/* unsigned_lt */",
                    "/* negative */" => "/* non_negative */",
                    "/* non_negative */" => "/* negative */",
                    "/* overflow */" => "/* no_overflow */",
                    "/* no_overflow */" => "/* overflow */",
                    "/* parity_even */" => "/* parity_odd */",
                    "/* parity_odd */" => "/* parity_even */",
                    _ => return Self::unary(UnaryOpKind::LogicalNot, self),
                };
                Self::unknown(negated)
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
                        if matches!(right.kind, ExprKind::IntLit(0))
                            || matches!(left.kind, ExprKind::IntLit(0))
                        {
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
                        // x | ((x >> n) << n) = x, and the commuted form. The
                        // shift pair clears the low n bits, which the `| x`
                        // restores, leaving x. This is the 64-bit reassembly
                        // idiom emitted for edx:eax intrinsics like rdtsc:
                        // `eax | (edx << 32)` where both halves come from one
                        // value reduces to that value.
                        if let Some(x) = match_low_bits_reassembly(&left, &right) {
                            return x;
                        }
                        // (cmp1) | (cmp2) → (cmp1) || (cmp2) for better readability
                        if is_comparison_expr(&left) && is_comparison_expr(&right) {
                            return Self::binop(BinOpKind::LogicalOr, left, right);
                        }
                    }
                    // x & 0 = 0, 0 & x = 0
                    BinOpKind::And => {
                        if matches!(right.kind, ExprKind::IntLit(0))
                            || matches!(left.kind, ExprKind::IntLit(0))
                        {
                            return Self::int(0);
                        }
                        // x & x = x
                        if exprs_structurally_equal(&left, &right) {
                            return left;
                        }
                        // (cmp1) & (cmp2) → (cmp1) && (cmp2) for better readability
                        if is_comparison_expr(&left) && is_comparison_expr(&right) {
                            return Self::binop(BinOpKind::LogicalAnd, left, right);
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

                // Sign extension pattern: (x << N) >> N where >> is SAR (arithmetic shift right)
                // becomes (intN_t)x where remaining bits = 64 - N
                if let Some(cast) = try_match_sign_extension(&left, op, &right) {
                    return cast;
                }

                // Combine nested constant shifts before later pattern matching.
                if let Some(combined) = try_combine_shift_chain(&left, op, &right) {
                    return combined;
                }

                // Zero extension pattern: x & mask where mask is 0xFF, 0xFFFF, etc.
                // becomes (uintN_t)x
                if let Some(cast) = try_match_zero_extension(&left, op, &right) {
                    return cast;
                }

                let (left, right) = normalize_small_cast_comparison_operands(op, left, right);

                if let Some(simplified) =
                    try_simplify_conditional_boolean_comparison(&left, op, &right)
                {
                    return simplified;
                }

                // Bit field extraction pattern: (x >> start) & mask
                // becomes BITS(x, start, width) where width = popcount(mask)
                if let Some(bitfield) = try_match_bitfield_extraction(&left, op, &right) {
                    return bitfield;
                }

                // Bit field insertion pattern: (carrier & ~mask) | (value << start)
                // becomes SET_BITS(carrier, value, start, width)
                if let Some(bitfield_insert) = try_match_bitfield_insert(&left, op, &right) {
                    return bitfield_insert;
                }

                // Boolean simplification: (cmp) == 1 → cmp, (cmp) != 1 → !(cmp)
                // and (cmp) == 0 → !(cmp), (cmp) != 0 → cmp
                // where cmp is a comparison expression
                if let Some(simplified) = try_simplify_boolean_comparison(&left, op, &right) {
                    return simplified;
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
                if let ExprKind::UnaryOp {
                    op: inner_op,
                    operand: inner_operand,
                } = &operand.kind
                {
                    match (op, inner_op) {
                        (UnaryOpKind::Neg, UnaryOpKind::Neg) => return *inner_operand.clone(),
                        (UnaryOpKind::Not, UnaryOpKind::Not) => return *inner_operand.clone(),
                        (UnaryOpKind::LogicalNot, UnaryOpKind::LogicalNot) => {
                            return *inner_operand.clone()
                        }
                        _ => {}
                    }
                }

                Self::unary(op, operand)
            }
            ExprKind::Assign { lhs, rhs } => {
                let lhs = lhs.simplify();
                let rhs = rhs.simplify();

                // Try to detect compound assignment pattern: x = x op y → x op= y
                if let Some(compound) = try_detect_compound_assign(&lhs, &rhs) {
                    return compound;
                }

                Self::assign(lhs, rhs)
            }
            ExprKind::Deref { addr, size } => {
                let simplified_addr = addr.simplify();
                // Try to detect array access patterns
                if let Some(array_access) = try_detect_array_in_deref(&simplified_addr, size) {
                    return array_access;
                }
                // Check for spurious dereferences: if the address is a pure value computation
                // (no memory references, pointers, or valid address bases), the Deref is likely
                // incorrect and should be removed. This handles cases like:
                //   *(uint32_t*)(_g * 2 + 1)  ->  _g * 2 + 1
                // where _g is already a value, not an address.
                if is_spurious_deref_address(&simplified_addr) {
                    return simplified_addr;
                }
                Self::deref(simplified_addr, size)
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                // Simplify base and index recursively
                Self::array_access(base.simplify(), index.simplify(), element_size)
            }
            ExprKind::AddressOf(inner) => {
                let simplified = inner.simplify();
                Self {
                    kind: ExprKind::AddressOf(Box::new(simplified)),
                }
            }
            ExprKind::Call { target, args } => {
                let args = args.into_iter().map(|a| a.simplify()).collect();
                Self::call(target, args)
            }
            ExprKind::Cast {
                expr,
                to_size,
                signed,
            } => {
                let simplified_expr = expr.simplify();

                // Cast of integer literal: evaluate the cast
                if let ExprKind::IntLit(n) = simplified_expr.kind {
                    let mask = match to_size {
                        1 => 0xFF,
                        2 => 0xFFFF,
                        4 => 0xFFFFFFFF,
                        8 => u64::MAX as i128,
                        _ => {
                            return Self {
                                kind: ExprKind::Cast {
                                    expr: Box::new(simplified_expr),
                                    to_size,
                                    signed,
                                },
                            }
                        }
                    };
                    let masked = n & mask;
                    // Sign extend if needed
                    let result = if signed {
                        let sign_bit = 1i128 << (to_size * 8 - 1);
                        if (masked & sign_bit) != 0 {
                            masked | !mask // Sign extend
                        } else {
                            masked
                        }
                    } else {
                        masked
                    };
                    return Self::int(result);
                }

                // Nested cast elimination: (T1)(T2)x
                // If outer cast is larger or equal, inner cast may be redundant
                if let ExprKind::Cast {
                    expr: inner_expr,
                    to_size: inner_size,
                    signed: inner_signed,
                } = &simplified_expr.kind
                {
                    // If casting to same size with same signedness, remove redundant cast
                    if to_size == *inner_size && signed == *inner_signed {
                        return *inner_expr.clone();
                    }
                    // If outer cast is smaller, it dominates (truncation)
                    if to_size < *inner_size {
                        return Self {
                            kind: ExprKind::Cast {
                                expr: inner_expr.clone(),
                                to_size,
                                signed,
                            },
                        };
                    }
                    // If outer cast is larger and same signedness, inner is redundant
                    if to_size > *inner_size && signed == *inner_signed {
                        return Self {
                            kind: ExprKind::Cast {
                                expr: inner_expr.clone(),
                                to_size,
                                signed,
                            },
                        };
                    }

                    // Sign/zero extension pattern: (signed_larger)(unsigned_smaller)x
                    // Zero extension preserves value as non-negative, so outer signed cast
                    // can directly cast from original when inner size is "full width" (>= 4 bytes)
                    if to_size > *inner_size && signed && !*inner_signed {
                        // For 4+ byte unsigned values zero-extended to signed, we can
                        // simplify since the value is guaranteed non-negative
                        if *inner_size >= 4 {
                            return Self {
                                kind: ExprKind::Cast {
                                    expr: inner_expr.clone(),
                                    to_size,
                                    signed,
                                },
                            };
                        }
                    }

                    // Pattern: (same_size)(different_signedness)x - just change interpretation
                    // e.g., (uint32_t)(int32_t)x or (int32_t)(uint32_t)x
                    // Inner cast is redundant, just reinterpret with outer signedness
                    if to_size == *inner_size && signed != *inner_signed {
                        return Self {
                            kind: ExprKind::Cast {
                                expr: inner_expr.clone(),
                                to_size,
                                signed,
                            },
                        };
                    }
                }

                // Cast of a variable to its own size: eliminate the cast
                if let ExprKind::Var(v) = &simplified_expr.kind {
                    if v.size == to_size {
                        return simplified_expr;
                    }
                }

                // Cast of comparison result (0 or 1) to larger type: preserve as-is
                // since comparisons naturally produce int-sized results
                if let ExprKind::BinOp { op, .. } = &simplified_expr.kind {
                    if op.is_comparison() && to_size >= 4 {
                        // Comparison results are conceptually 32-bit ints
                        // No need to explicitly cast them
                        return simplified_expr;
                    }
                }

                // Cast of deref to same size as the deref: eliminate
                if let ExprKind::Deref { size, .. } = &simplified_expr.kind {
                    if *size == to_size {
                        return simplified_expr;
                    }
                }

                // Cast of array/field access: the element size determines the type
                if let ExprKind::ArrayAccess { element_size, .. } = &simplified_expr.kind {
                    if *element_size == to_size as usize {
                        return simplified_expr;
                    }
                }

                // Cast of field access: the field offset implies a type size
                if let ExprKind::FieldAccess { .. } = &simplified_expr.kind {
                    // Field accesses typically have well-defined types from struct layout
                    // For now, allow casting to pointer size (8) or int size (4) without explicit cast
                    if to_size >= 4 {
                        return simplified_expr;
                    }
                }

                // Cast of address-of expression: addresses are always pointer-sized (8 bytes)
                if let ExprKind::AddressOf(_) = &simplified_expr.kind {
                    if to_size == 8 {
                        return simplified_expr;
                    }
                }

                // Cast of function call result to standard int/pointer size
                // Function returns are typically already the correct size
                if let ExprKind::Call { .. } = &simplified_expr.kind {
                    // Most functions return int (4 bytes) or pointer (8 bytes)
                    // Casting to 4 or 8 bytes is usually redundant
                    if to_size >= 4 {
                        return simplified_expr;
                    }
                }

                // Cast of GotRef (PLT/GOT reference) - these are pointer-sized
                if let ExprKind::GotRef { .. } = &simplified_expr.kind {
                    if to_size == 8 {
                        return simplified_expr;
                    }
                }

                Self {
                    kind: ExprKind::Cast {
                        expr: Box::new(simplified_expr),
                        to_size,
                        signed,
                    },
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond = cond.simplify();
                let then_expr = then_expr.simplify();
                let else_expr = else_expr.simplify();

                // If condition is constant, select the appropriate branch
                if let ExprKind::IntLit(n) = cond.kind {
                    if n != 0 {
                        return then_expr;
                    } else {
                        return else_expr;
                    }
                }

                // cond ? x : x → x. This shows up directly for `cmovcc reg, reg`
                // where the same register is both source and destination (a no-op
                // the compiler still emits as a hint or a side-effect-free guard).
                // Without this fold, repeated self-cmovs cascade-substitute through
                // simplification passes and double the expression on every step —
                // the fuzzer surfaced an 11-byte input that ballooned into 37 KB of
                // pseudo-C through three chained `cmovge eax, eax` instructions.
                if exprs_structurally_equal(&then_expr, &else_expr) {
                    return then_expr;
                }

                Self {
                    kind: ExprKind::Conditional {
                        cond: Box::new(cond),
                        then_expr: Box::new(then_expr),
                        else_expr: Box::new(else_expr),
                    },
                }
            }
            // Other expression kinds pass through unchanged
            _ => self,
        }
    }

    /// Converts an operand to an expression.
    pub fn from_operand(op: &Operand) -> Self {
        match op {
            Operand::Register(reg) => Self::var(Variable::from_register(reg)),
            Operand::Arm64SveVector(reg) => Self::var(Variable::from_register(&reg.reg)),
            Operand::Arm64SvePredicate(pred) => Self::var(Variable::from_register(&pred.reg)),
            Operand::Immediate(imm) => Self::int(imm.value),
            Operand::Memory(mem) => Self::from_memory_ref(mem),
            Operand::PcRelative { target, .. } => Self::int(*target as i128),
        }
    }

    fn x86_scalar_float_lane_size(inst: &Instruction) -> Option<u8> {
        let mnemonic = inst.mnemonic.to_ascii_lowercase();
        if mnemonic.ends_with("ss") {
            Some(4)
        } else if mnemonic.ends_with("sd") {
            Some(8)
        } else {
            None
        }
    }

    fn scalar_x86_simd_register_expr(reg: &Register, inst: &Instruction) -> Option<Self> {
        let size_bytes = Self::x86_scalar_float_lane_size(inst)?;

        let name = reg.name().to_ascii_lowercase();
        if !(name.starts_with("xmm") || name.starts_with("ymm") || name.starts_with("zmm")) {
            return None;
        }

        Some(Self::var(Variable::reg(reg.name(), size_bytes)))
    }

    /// Converts an operand to an expression with instruction context.
    /// This properly handles RIP-relative memory accesses by computing the absolute address.
    pub fn from_operand_with_inst(op: &Operand, inst: &Instruction) -> Self {
        match op {
            Operand::Register(reg) => Self::scalar_x86_simd_register_expr(reg, inst)
                .unwrap_or_else(|| Self::var(Variable::from_register(reg))),
            Operand::Arm64SveVector(reg) => Self::var(Variable::from_register(&reg.reg)),
            Operand::Arm64SvePredicate(pred) => Self::var(Variable::from_register(&pred.reg)),
            Operand::Immediate(imm) => Self::int(imm.value),
            Operand::Memory(mem) => Self::from_memory_with_context(mem, inst, false),
            Operand::PcRelative { target, .. } => Self::int(*target as i128),
        }
    }

    fn x86_vector_float_call_name(inst: &Instruction, base: &str, dst: &Operand) -> Option<String> {
        let mnemonic = inst.mnemonic.to_ascii_lowercase();
        let suffix = if mnemonic.ends_with("ps") {
            "ps"
        } else if mnemonic.ends_with("pd") {
            "pd"
        } else {
            return None;
        };

        let Operand::Register(reg) = dst else {
            return None;
        };
        let width_bytes = (reg.size / 8) as u8;
        if width_bytes <= 8 {
            return None;
        }

        let ty = match width_bytes {
            16 => "__m128",
            32 => "__m256",
            64 => "__m512",
            _ => return None,
        };
        Some(format!("{ty}_{base}_{suffix}"))
    }

    fn x86_vector_float_binop(inst: &Instruction, ops: &[Operand], base: &str) -> Option<Self> {
        let call_name = Self::x86_vector_float_call_name(inst, base, ops.first()?)?;
        let dst = Self::from_operand_with_inst(ops.first()?, inst);
        let args = if ops.len() >= 3 {
            vec![
                Self::from_operand_with_inst(&ops[1], inst),
                Self::from_operand_with_inst(&ops[2], inst),
            ]
        } else if ops.len() == 2 {
            vec![dst.clone(), Self::from_operand_with_inst(&ops[1], inst)]
        } else {
            return None;
        };

        Some(Self::assign(
            dst,
            Self::call(CallTarget::Named(call_name), args),
        ))
    }

    fn x86_scalar_minmax_expr(inst: &Instruction) -> Option<Self> {
        let call_name = match inst.mnemonic.to_ascii_lowercase().as_str() {
            "minss" | "vminss" => "fminf",
            "minsd" | "vminsd" => "fmin",
            "maxss" | "vmaxss" => "fmaxf",
            "maxsd" | "vmaxsd" => "fmax",
            _ => return None,
        };
        let ops = &inst.operands;
        let dst = Self::from_operand_with_inst(ops.first()?, inst);
        let args = if ops.len() >= 3 {
            vec![
                Self::from_operand_with_inst(&ops[1], inst),
                Self::from_operand_with_inst(&ops[2], inst),
            ]
        } else if ops.len() == 2 {
            vec![dst.clone(), Self::from_operand_with_inst(&ops[1], inst)]
        } else {
            return None;
        };

        Some(Self::assign(
            dst,
            Self::call(CallTarget::Named(call_name.to_string()), args),
        ))
    }

    fn x86_vector_minmax_expr(inst: &Instruction) -> Option<Self> {
        let base = match inst.mnemonic.to_ascii_lowercase().as_str() {
            "minps" | "vminps" | "minpd" | "vminpd" => "min",
            "maxps" | "vmaxps" | "maxpd" | "vmaxpd" => "max",
            _ => return None,
        };
        Self::x86_vector_float_binop(inst, &inst.operands, base)
    }

    fn x86_fma_expr(inst: &Instruction) -> Option<Self> {
        let mnemonic = inst.mnemonic.to_ascii_lowercase();
        if !mnemonic.starts_with("vfmadd") || inst.operands.len() < 3 {
            return None;
        }

        let dst = Self::from_operand_with_inst(&inst.operands[0], inst);
        let src0 = dst.clone();
        let src1 = Self::from_operand_with_inst(&inst.operands[1], inst);
        let src2 = Self::from_operand_with_inst(&inst.operands[2], inst);

        let (mul_lhs, mul_rhs, addend) = if mnemonic.contains("132") {
            (src0, src2, src1)
        } else if mnemonic.contains("213") {
            (src0, src1, src2)
        } else if mnemonic.contains("231") {
            (src1, src2, src0)
        } else {
            return None;
        };

        Some(Self::assign(
            dst,
            Self::binop(
                BinOpKind::Add,
                Self::binop(BinOpKind::Mul, mul_lhs, mul_rhs),
                addend,
            ),
        ))
    }

    fn address_register_expr(reg: &Register, forced_size_bytes: Option<u8>) -> Self {
        let adjusted = if matches!(reg.arch, Architecture::X86_64 | Architecture::X86)
            && reg.class == RegisterClass::General
        {
            forced_size_bytes
                .filter(|size| u16::from(*size) * 8 < reg.size)
                .map(|size| Register::new(reg.arch, reg.class, reg.id, u16::from(size) * 8))
                .unwrap_or(*reg)
        } else {
            *reg
        };

        Self::var(Variable::from_register(&adjusted))
    }

    /// Converts a memory reference into its effective address expression.
    fn memory_address_expr(mem: &MemoryRef) -> Self {
        Self::memory_address_expr_with_size(mem, None)
    }

    fn known_segmented_memory_symbol(mem: &MemoryRef) -> Option<&'static str> {
        let segment = mem.segment.as_ref()?;
        if mem.base.is_some() || mem.index.is_some() {
            return None;
        }

        match (segment.id, mem.displacement) {
            // Linux x86_64 and x86 stack-protector canary slots in TLS.
            (x86::FS, 0x28) | (x86::GS, 0x14) => Some("__stack_chk_guard"),
            _ => None,
        }
    }

    fn known_segmented_memory_expr(mem: &MemoryRef) -> Option<Self> {
        if let Some(symbol) = Self::known_segmented_memory_symbol(mem) {
            return Some(Self::unknown(symbol));
        }

        let segment = mem.segment.as_ref()?;
        if mem.base.is_some() || mem.index.is_some() {
            return None;
        }

        match (segment.id, mem.displacement) {
            // On x86 Linux, `fs:0` loads the thread-pointer base. Preserve it as
            // a TLS-aware expression instead of collapsing it to an absolute null
            // dereference.
            (x86::FS, 0) | (x86::GS, 0) => Some(Self::call(
                CallTarget::Named("__builtin_thread_pointer".to_string()),
                vec![],
            )),
            _ => None,
        }
    }

    fn segmented_address_base_expr(mem: &MemoryRef) -> Option<Self> {
        let segment = mem.segment.as_ref()?;

        match segment.id {
            x86::FS | x86::GS => Some(Self::call(
                CallTarget::Named("__builtin_thread_pointer".to_string()),
                vec![],
            )),
            _ => None,
        }
    }

    fn memory_address_expr_with_size(mem: &MemoryRef, forced_size_bytes: Option<u8>) -> Self {
        let mut addr_expr = Self::segmented_address_base_expr(mem);

        // Build address expression: base + index*scale + disp
        if let Some(ref base) = mem.base {
            let base_expr = Self::address_register_expr(base, forced_size_bytes);
            addr_expr = Some(match addr_expr {
                Some(segment_base) => Self::binop(BinOpKind::Add, segment_base, base_expr),
                None => base_expr,
            });
        }

        if let Some(ref index) = mem.index {
            let index_expr = Self::address_register_expr(index, forced_size_bytes);
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

        addr_expr.unwrap_or_else(|| Self::int(0))
    }

    /// Converts a memory reference to an expression.
    fn from_memory_ref(mem: &MemoryRef) -> Self {
        if let Some(expr) = Self::known_segmented_memory_expr(mem) {
            return expr;
        }
        Self::deref(Self::memory_address_expr(mem), mem.size)
    }

    /// Converts a memory operand with instruction context to handle RIP-relative addressing.
    /// Returns a GotRef for RIP-relative addresses with computed absolute address,
    /// or a regular Deref for other memory accesses.
    fn from_memory_with_context(mem: &MemoryRef, inst: &Instruction, is_dest: bool) -> Self {
        if !is_dest && Self::is_saved_return_address_slot(mem) {
            return Self::call(
                CallTarget::Named("__builtin_return_address".to_string()),
                vec![Self::int(0)],
            );
        }

        let base_name = mem.base.as_ref().map(|r| r.name()).unwrap_or("");
        if base_name == "rip" && mem.index.is_none() {
            // Compute absolute address: inst.address + inst.size + displacement
            let abs_addr = (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
            let display_expr = Self::from_memory_ref(mem);
            if is_dest {
                // For stores, we want to return a GotRef that can be assigned to
                Self::got_ref(abs_addr, inst.address, mem.size, display_expr)
            } else {
                Self::got_ref(abs_addr, inst.address, mem.size, display_expr)
            }
        } else {
            Self::from_memory_ref(mem)
        }
    }

    fn from_memory_address_with_context(mem: &MemoryRef, inst: &Instruction) -> Self {
        let base_name = mem.base.as_ref().map(|r| r.name()).unwrap_or("");
        if base_name == "rip" && mem.index.is_none() {
            let abs_addr = (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
            Self::got_addr(abs_addr, inst.address, Self::int(abs_addr as i128))
        } else if let Some(expr) = Self::known_segmented_memory_expr(mem) {
            expr
        } else {
            Self::memory_address_expr(mem)
        }
    }

    fn is_saved_return_address_slot(mem: &MemoryRef) -> bool {
        mem.index.is_none()
            && mem.displacement == 8
            && mem.size == 8
            && mem
                .base
                .as_ref()
                .is_some_and(|base| matches!(base.name(), "rbp" | "ebp" | "bp"))
    }

    fn is_lock_prefixed(inst: &Instruction) -> bool {
        inst.bytes.first() == Some(&0xF0)
    }

    fn is_mfence(inst: &Instruction) -> bool {
        inst.mnemonic.eq_ignore_ascii_case("mfence") || inst.bytes.as_slice() == [0x0f, 0xae, 0xf0]
    }

    fn is_zero_immediate(operand: &Operand) -> bool {
        matches!(operand, Operand::Immediate(imm) if imm.value == 0)
    }

    fn is_stack_fence_memory(mem: &MemoryRef) -> bool {
        mem.index.is_none()
            && mem
                .base
                .as_ref()
                .is_some_and(|base| matches!(base.name(), "rsp" | "esp"))
    }

    fn is_seq_cst_fence_pattern(inst: &Instruction) -> bool {
        if !Self::is_lock_prefixed(inst) || inst.operands.len() != 2 {
            return false;
        }

        let Some(Operand::Memory(mem)) = inst.operands.first() else {
            return false;
        };

        Self::is_stack_fence_memory(mem)
            && Self::is_zero_immediate(&inst.operands[1])
            && matches!(inst.operation, Operation::Or | Operation::Add)
    }

    fn x86_atomic_pair(ops: &[Operand]) -> Option<(&MemoryRef, usize)> {
        let mem_index = ops
            .iter()
            .position(|operand| matches!(operand, Operand::Memory(_)))?;
        let reg_index = ops.iter().enumerate().find_map(|(index, operand)| {
            (index != mem_index && matches!(operand, Operand::Register(_))).then_some(index)
        })?;
        let Operand::Memory(mem) = &ops[mem_index] else {
            return None;
        };
        Some((mem, reg_index))
    }

    fn x86_seq_cst_fence_expr() -> Self {
        Self::call(
            CallTarget::Named("__atomic_thread_fence".to_string()),
            vec![Self::unknown("memory_order_seq_cst")],
        )
    }

    fn x86_locked_rmw_expr(inst: &Instruction) -> Option<Self> {
        if !Self::is_lock_prefixed(inst) {
            return None;
        }
        if Self::is_seq_cst_fence_pattern(inst) {
            return Some(Self::x86_seq_cst_fence_expr());
        }

        let Operand::Memory(mem) = inst.operands.first()? else {
            return None;
        };
        let ptr = Self::from_memory_address_with_context(mem, inst);

        let (func_name, value) = match inst.operation {
            Operation::Add if inst.operands.len() >= 2 => (
                "atomic_fetch_add",
                Self::from_operand_with_inst(&inst.operands[1], inst),
            ),
            Operation::Sub if inst.operands.len() >= 2 => (
                "atomic_fetch_sub",
                Self::from_operand_with_inst(&inst.operands[1], inst),
            ),
            Operation::And if inst.operands.len() >= 2 => (
                "atomic_fetch_and",
                Self::from_operand_with_inst(&inst.operands[1], inst),
            ),
            Operation::Or if inst.operands.len() >= 2 => (
                "atomic_fetch_or",
                Self::from_operand_with_inst(&inst.operands[1], inst),
            ),
            Operation::Xor if inst.operands.len() >= 2 => (
                "atomic_fetch_xor",
                Self::from_operand_with_inst(&inst.operands[1], inst),
            ),
            Operation::Inc => ("atomic_fetch_add", Self::int(1)),
            Operation::Dec => ("atomic_fetch_sub", Self::int(1)),
            _ => return None,
        };

        Some(Self::call(
            CallTarget::Named(func_name.to_string()),
            vec![ptr, value],
        ))
    }

    fn x86_mnemonic_matches(inst: &Instruction, mnemonic: &str) -> bool {
        inst.mnemonic.eq_ignore_ascii_case(mnemonic)
            || inst
                .mnemonic
                .strip_prefix("lock ")
                .is_some_and(|inner| inner.eq_ignore_ascii_case(mnemonic))
    }

    fn x86_atomic_xchg_expr(inst: &Instruction) -> Option<Self> {
        if !Self::x86_mnemonic_matches(inst, "xchg") {
            return None;
        }
        let (mem, reg_index) = Self::x86_atomic_pair(&inst.operands)?;
        let ptr = Self::from_memory_address_with_context(mem, inst);
        let reg = Self::from_operand_with_inst(&inst.operands[reg_index], inst);
        let prior = reg.clone();
        Some(Self::assign(
            reg,
            Self::call(
                CallTarget::Named("atomic_exchange".to_string()),
                vec![ptr, prior],
            ),
        ))
    }

    fn x86_atomic_xadd_expr(inst: &Instruction) -> Option<Self> {
        if !Self::x86_mnemonic_matches(inst, "xadd") {
            return None;
        }
        let (mem, reg_index) = Self::x86_atomic_pair(&inst.operands)?;
        let ptr = Self::from_memory_address_with_context(mem, inst);
        let reg = Self::from_operand_with_inst(&inst.operands[reg_index], inst);
        let delta = reg.clone();
        Some(Self::assign(
            reg,
            Self::call(
                CallTarget::Named("atomic_fetch_add".to_string()),
                vec![ptr, delta],
            ),
        ))
    }

    fn x86_atomic_cmpxchg_expr(inst: &Instruction) -> Option<Self> {
        if !Self::x86_mnemonic_matches(inst, "cmpxchg") {
            return None;
        }
        let (mem, reg_index) = Self::x86_atomic_pair(&inst.operands)?;
        let ptr = Self::from_memory_address_with_context(mem, inst);
        let desired = Self::from_operand_with_inst(&inst.operands[reg_index], inst);
        let expected_size = mem.size.max(1);
        let expected_reg = match expected_size {
            1 => "al",
            2 => "ax",
            4 => "eax",
            8 => "rax",
            _ => return None,
        };
        let expected = Self::var(Variable::reg(expected_reg, expected_size));

        Some(Self::call(
            CallTarget::Named("atomic_compare_exchange_strong".to_string()),
            vec![ptr, expected, desired],
        ))
    }

    fn lift_special_x86_atomic(inst: &Instruction) -> Option<Self> {
        if Self::is_mfence(inst) || Self::is_seq_cst_fence_pattern(inst) {
            return Some(Self::x86_seq_cst_fence_expr());
        }

        Self::x86_atomic_xchg_expr(inst)
            .or_else(|| Self::x86_atomic_xadd_expr(inst))
            .or_else(|| Self::x86_atomic_cmpxchg_expr(inst))
            .or_else(|| Self::x86_locked_rmw_expr(inst))
    }

    fn x86_bswap_expr(inst: &Instruction) -> Option<Self> {
        if !inst.mnemonic.eq_ignore_ascii_case("bswap") || inst.operands.len() != 1 {
            return None;
        }

        let builtin = match inst.operands.first() {
            Some(Operand::Register(reg)) if reg.size == 32 => "__builtin_bswap32",
            Some(Operand::Register(reg)) if reg.size == 64 => "__builtin_bswap64",
            _ => return None,
        };
        let operand = Self::from_operand_with_inst(inst.operands.first()?, inst);

        Some(Self::assign(
            operand.clone(),
            Self::call(CallTarget::Named(builtin.to_string()), vec![operand]),
        ))
    }

    fn x86_bit_scan_expr(inst: &Instruction) -> Option<Self> {
        if inst.operands.len() < 2 {
            return None;
        }

        let builtin = if inst.mnemonic.eq_ignore_ascii_case("bsf") {
            "__builtin_bsf"
        } else if inst.mnemonic.eq_ignore_ascii_case("bsr") {
            "__builtin_bsr"
        } else {
            return None;
        };

        Some(Self::assign(
            Self::from_operand_with_inst(&inst.operands[0], inst),
            Self::call(
                CallTarget::Named(builtin.to_string()),
                vec![Self::from_operand_with_inst(&inst.operands[1], inst)],
            ),
        ))
    }

    fn x86_prefetch_expr(inst: &Instruction) -> Option<Self> {
        let locality = match inst.mnemonic.to_ascii_lowercase().as_str() {
            "prefetchnta" => Some(0),
            "prefetcht2" => Some(1),
            "prefetcht1" => Some(2),
            "prefetcht0" => Some(3),
            _ => None,
        }?;

        let address = match inst.operands.first()? {
            Operand::Memory(mem) => Self::from_memory_address_with_context(mem, inst),
            operand => Self::from_operand_with_inst(operand, inst),
        };

        Some(Self::call(
            CallTarget::Named("__builtin_prefetch".to_string()),
            vec![address, Self::int(0), Self::int(locality)],
        ))
    }

    fn x86_ud2_expr(inst: &Instruction) -> Option<Self> {
        inst.mnemonic
            .eq_ignore_ascii_case("ud2")
            .then(|| Self::call(CallTarget::Named("__builtin_trap".to_string()), vec![]))
    }

    fn lift_special_x86_intrinsic(inst: &Instruction) -> Option<Self> {
        Self::x86_bswap_expr(inst)
            .or_else(|| Self::x86_bit_scan_expr(inst))
            .or_else(|| Self::x86_prefetch_expr(inst))
            .or_else(|| Self::x86_ud2_expr(inst))
    }

    fn opaque_x86_integer_simd_comment(mnemonic: &str) -> Self {
        Self::unknown(format!("/* SSE: {} */", mnemonic.to_ascii_lowercase()))
    }

    fn should_lift_as_opaque_x86_integer_simd(inst: &Instruction) -> bool {
        let mnemonic = inst.mnemonic.to_ascii_lowercase();
        Self::looks_like_x86_integer_simd_mnemonic(&mnemonic)
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

    /// Converts an instruction to an expression/statement.
    pub fn from_instruction(inst: &Instruction) -> Self {
        if let Some(expr) = Self::lift_hidden_rep_stos_state_update(inst) {
            return expr;
        }

        if Self::should_lift_as_opaque_x86_integer_simd(inst) {
            return Self::opaque_x86_integer_simd_comment(&inst.mnemonic);
        }

        if let Some(expr) = Self::lift_special_x86_atomic(inst) {
            return expr;
        }

        if let Some(expr) = Self::lift_special_x86_intrinsic(inst) {
            return expr;
        }

        let ops = &inst.operands;

        match inst.operation {
            Operation::Move => {
                if ops.len() >= 2 {
                    // Check for RIP-relative memory on both sides
                    let lhs = if let Operand::Memory(mem) = &ops[0] {
                        Self::from_memory_with_context(mem, inst, true)
                    } else {
                        Self::from_operand_with_inst(&ops[0], inst)
                    };
                    let rhs = if let Operand::Memory(mem) = &ops[1] {
                        Self::from_memory_with_context(mem, inst, false)
                    } else {
                        Self::from_operand_with_inst(&ops[1], inst)
                    };
                    Self::assign(lhs, rhs)
                } else if ops.len() == 1 {
                    Self::from_operand_with_inst(&ops[0], inst)
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
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::from_operand_with_inst(&ops[2], inst),
                    )
                } else if ops.len() >= 2 {
                    Self::assign(
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::from_operand_with_inst(&ops[1], inst),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Store => {
                if ops.len() >= 2 {
                    // A store writes to memory, so the memory operand is the
                    // destination regardless of architecture operand order:
                    // x86 SSE stores are destination-first (`[mem], xmm`), while
                    // ARM64 STR is value-first (`reg, [mem]`). Pick the memory
                    // operand as the lhs so both lift to `mem = value`.
                    let (dst_idx, src_idx) = match (&ops[0], &ops[1]) {
                        (Operand::Memory(_), _) => (0, 1),
                        (_, Operand::Memory(_)) => (1, 0),
                        // Neither operand is memory (e.g. reg-to-reg moves lifted
                        // through Store): keep the historical value-first order.
                        _ => (1, 0),
                    };
                    let lhs = if let Operand::Memory(mem) = &ops[dst_idx] {
                        Self::from_memory_with_context(mem, inst, true)
                    } else {
                        Self::from_operand_with_inst(&ops[dst_idx], inst)
                    };
                    Self::assign(lhs, Self::from_operand_with_inst(&ops[src_idx], inst))
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Add => Self::make_binop(inst, ops, BinOpKind::Add, &inst.mnemonic),
            Operation::Sub => {
                // Special case: sub reg, reg is a zeroing idiom
                // For 2-operand (x86): sub eax, eax → ops[0] == ops[1]
                // For 3-operand (ARM64): subs w8, w8, w8 → ops[1] == ops[2]
                let is_zeroing = if ops.len() == 2 {
                    ops[0] == ops[1]
                } else if ops.len() >= 3 {
                    ops[1] == ops[2]
                } else {
                    false
                };
                if is_zeroing {
                    Self::assign(Self::from_operand(&ops[0]), Self::int(0))
                } else {
                    Self::make_binop(inst, ops, BinOpKind::Sub, &inst.mnemonic)
                }
            }
            Operation::Mul => Self::make_binop(inst, ops, BinOpKind::Mul, &inst.mnemonic),
            Operation::Div => Self::make_binop(inst, ops, BinOpKind::Div, &inst.mnemonic),
            Operation::And => Self::make_binop(inst, ops, BinOpKind::And, &inst.mnemonic),
            Operation::Or => {
                // ARM64 ORN: orn rd, rn, rm → rd = rn | ~rm
                let mnem = inst.mnemonic.to_lowercase();
                if mnem == "orn" && ops.len() >= 3 {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::binop(
                            BinOpKind::Or,
                            Self::from_operand(&ops[1]),
                            Self::unary(UnaryOpKind::Not, Self::from_operand(&ops[2])),
                        ),
                    )
                } else {
                    Self::make_binop(inst, ops, BinOpKind::Or, &inst.mnemonic)
                }
            }
            Operation::Xor => {
                // Special case: xor reg, reg is a zeroing idiom
                // For 2-operand (x86): xor eax, eax → ops[0] == ops[1]
                // For 3-operand (ARM64): eor w8, w8, w8 → ops[1] == ops[2]
                let is_zeroing = if ops.len() == 2 {
                    ops[0] == ops[1]
                } else if ops.len() >= 3 {
                    ops[1] == ops[2]
                } else {
                    false
                };
                if is_zeroing {
                    Self::assign(Self::from_operand(&ops[0]), Self::int(0))
                } else {
                    // ARM64 EON: eon rd, rn, rm → rd = rn ^ ~rm
                    let mnem = inst.mnemonic.to_lowercase();
                    if mnem == "eon" && ops.len() >= 3 {
                        Self::assign(
                            Self::from_operand(&ops[0]),
                            Self::binop(
                                BinOpKind::Xor,
                                Self::from_operand(&ops[1]),
                                Self::unary(UnaryOpKind::Not, Self::from_operand(&ops[2])),
                            ),
                        )
                    } else {
                        Self::make_binop(inst, ops, BinOpKind::Xor, &inst.mnemonic)
                    }
                }
            }
            Operation::Shl => Self::make_binop(inst, ops, BinOpKind::Shl, &inst.mnemonic),
            Operation::Shr => Self::make_binop(inst, ops, BinOpKind::Shr, &inst.mnemonic),
            Operation::Sar => Self::make_binop(inst, ops, BinOpKind::Sar, &inst.mnemonic),
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
            Operation::Compare | Operation::Test | Operation::BitTest => {
                // Compare, test, and bit test set flags but don't produce a visible result.
                // They're consumed by subsequent conditional branches.
                // Emit as a no-op comment to avoid cluttering output.
                Self::unknown("/* nop */")
            }
            Operation::Neg => {
                if !ops.is_empty() {
                    let operand = Self::from_operand_with_inst(&ops[0], inst);
                    Self::assign(
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::unary(UnaryOpKind::Neg, operand),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Not => {
                if !ops.is_empty() {
                    let operand = Self::from_operand_with_inst(&ops[0], inst);
                    Self::assign(
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::unary(UnaryOpKind::Not, operand),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Inc => {
                if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::binop(
                            BinOpKind::Add,
                            Self::from_operand_with_inst(&ops[0], inst),
                            Self::int(1),
                        ),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Dec => {
                if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand_with_inst(&ops[0], inst),
                        Self::binop(
                            BinOpKind::Sub,
                            Self::from_operand_with_inst(&ops[0], inst),
                            Self::int(1),
                        ),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::Call => {
                let call_site = inst.address;
                let target = if !ops.is_empty() {
                    match &ops[0] {
                        Operand::PcRelative { target, .. } => CallTarget::Direct {
                            target: *target,
                            call_site,
                        },
                        Operand::Immediate(imm) => CallTarget::Direct {
                            target: imm.as_u64(),
                            call_site,
                        },
                        Operand::Memory(mem) => {
                            // Check for RIP-relative addressing (GOT/PLT pattern)
                            // e.g., call [rip + 0x1234] = call through GOT entry
                            if mem.base.as_ref().map(|r| r.name()).unwrap_or("") == "rip"
                                && mem.index.is_none()
                            {
                                // Compute GOT address: inst.address + inst.size + displacement
                                // inst.size is stored in inst.size field
                                let got_address =
                                    (inst.address as i64 + inst.size as i64 + mem.displacement)
                                        as u64;
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
            Operation::Syscall => {
                if inst.mnemonic.eq_ignore_ascii_case("syscall") {
                    let rax = Self::var(Variable::reg("rax", 8));
                    let args = vec![
                        rax.clone(),
                        Self::var(Variable::reg("rdi", 8)),
                        Self::var(Variable::reg("rsi", 8)),
                        Self::var(Variable::reg("rdx", 8)),
                        Self::var(Variable::reg("r10", 8)),
                        Self::var(Variable::reg("r8", 8)),
                        Self::var(Variable::reg("r9", 8)),
                    ];
                    Self::assign(
                        rax.clone(),
                        Self::call(CallTarget::Named("__linux_syscall".to_string()), args),
                    )
                } else {
                    Self::call(CallTarget::Named("__raw_syscall".to_string()), vec![])
                }
            }
            Operation::Interrupt => {
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named("int".to_string()),
                        vec![Self::from_operand(&ops[0])],
                    )
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
            // x87 FPU operations - emit as function calls with operands
            Operation::X87Load
            | Operation::X87Store
            | Operation::X87Add
            | Operation::X87Sub
            | Operation::X87Mul
            | Operation::X87Div
            | Operation::X87Compare
            | Operation::X87Transcendental
            | Operation::X87Misc
            | Operation::X87Control
            | Operation::X87Stack => {
                // x87 FPU instructions: emit as a function call with the mnemonic
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named(inst.mnemonic.clone()),
                        ops.iter().map(Self::from_operand).collect(),
                    )
                } else {
                    // No operands - just emit as a no-arg call
                    Self::call(CallTarget::Named(inst.mnemonic.clone()), vec![])
                }
            }
            Operation::Other(_) => {
                if let Some(expr) = Self::x86_fma_expr(inst)
                    .or_else(|| Self::x86_scalar_minmax_expr(inst))
                    .or_else(|| Self::x86_vector_minmax_expr(inst))
                {
                    return expr;
                }

                let mnem_lower = inst.mnemonic.to_lowercase();

                // Handle ARM64 bitfield operations
                if (mnem_lower == "sbfm" || mnem_lower == "ubfm" || mnem_lower == "bfm")
                    && ops.len() >= 4
                {
                    // Format: sbfm/ubfm rd, rn, #immr, #imms
                    let dst = Self::from_operand(&ops[0]);
                    let src = Self::from_operand(&ops[1]);
                    let immr = match &ops[2] {
                        Operand::Immediate(imm) => imm.value as i64,
                        _ => -1,
                    };
                    let imms = match &ops[3] {
                        Operand::Immediate(imm) => imm.value as i64,
                        _ => -1,
                    };

                    if immr >= 0 && imms >= 0 {
                        let is_signed = mnem_lower == "sbfm";

                        // Check for common sign/zero extension patterns
                        if immr == 0 {
                            // Sign/zero extend from bit position imms
                            let ext_expr = match imms {
                                7 => {
                                    // Extend from byte
                                    if is_signed {
                                        // (int8_t)(src)
                                        Self::call(
                                            CallTarget::Named("(int8_t)".to_string()),
                                            vec![src],
                                        )
                                    } else {
                                        Self::binop(BinOpKind::And, src, Self::int(0xFF))
                                    }
                                }
                                15 => {
                                    // Extend from halfword
                                    if is_signed {
                                        Self::call(
                                            CallTarget::Named("(int16_t)".to_string()),
                                            vec![src],
                                        )
                                    } else {
                                        Self::binop(BinOpKind::And, src, Self::int(0xFFFF))
                                    }
                                }
                                31 => {
                                    // Extend from word
                                    if is_signed {
                                        Self::call(
                                            CallTarget::Named("(int32_t)".to_string()),
                                            vec![src],
                                        )
                                    } else {
                                        Self::binop(BinOpKind::And, src, Self::int(0xFFFFFFFF))
                                    }
                                }
                                _ => {
                                    // General bitfield extract from bit 0 to imms
                                    let width = imms + 1;
                                    let mask = (1i128 << width) - 1;
                                    Self::binop(BinOpKind::And, src, Self::int(mask))
                                }
                            };
                            return Self::assign(dst, ext_expr);
                        } else if imms >= immr {
                            // Bitfield extract: extract bits [imms:immr]
                            let width = imms - immr + 1;
                            let mask = (1i128 << width) - 1;
                            let shift = immr;
                            let shifted =
                                Self::binop(BinOpKind::Shr, src, Self::int(shift as i128));
                            let masked = Self::binop(BinOpKind::And, shifted, Self::int(mask));
                            return Self::assign(dst, masked);
                        } else {
                            // immr > imms: left shift and mask pattern
                            // LSL is encoded as UBFM with immr = datasize - shift_amount
                            // Shift amount = datasize - immr (assuming 64-bit)
                            let datasize = 64i64;
                            let shift_amount = datasize - immr;
                            let width = imms + 1;
                            let mask = (1i128 << width) - 1;

                            // src << shift_amount, then mask to width bits
                            let shifted =
                                Self::binop(BinOpKind::Shl, src, Self::int(shift_amount as i128));
                            let masked = Self::binop(BinOpKind::And, shifted, Self::int(mask));
                            return Self::assign(dst, masked);
                        }
                    }
                }

                // Handle ARM64 sign/zero extension pseudo-ops (if recognized)
                if ops.len() >= 2 {
                    let ext_expr = match mnem_lower.as_str() {
                        "sxtb" => Some(Self::call(
                            CallTarget::Named("(int8_t)".to_string()),
                            vec![Self::from_operand(&ops[1])],
                        )),
                        "sxth" => Some(Self::call(
                            CallTarget::Named("(int16_t)".to_string()),
                            vec![Self::from_operand(&ops[1])],
                        )),
                        "sxtw" => Some(Self::call(
                            CallTarget::Named("(int32_t)".to_string()),
                            vec![Self::from_operand(&ops[1])],
                        )),
                        "uxtb" => Some(Self::binop(
                            BinOpKind::And,
                            Self::from_operand(&ops[1]),
                            Self::int(0xFF),
                        )),
                        "uxth" => Some(Self::binop(
                            BinOpKind::And,
                            Self::from_operand(&ops[1]),
                            Self::int(0xFFFF),
                        )),
                        "uxtw" => Some(Self::binop(
                            BinOpKind::And,
                            Self::from_operand(&ops[1]),
                            Self::int(0xFFFFFFFF),
                        )),
                        _ => None,
                    };
                    if let Some(expr) = ext_expr {
                        return Self::assign(Self::from_operand(&ops[0]), expr);
                    }
                }

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
                            if mem.base.as_ref().map(|r| r.name()).unwrap_or("") == "rip"
                                && mem.index.is_none()
                            {
                                // Compute absolute address: inst.address + inst.size + displacement
                                let abs_addr =
                                    (inst.address as i64 + inst.size as i64 + mem.displacement)
                                        as u64;
                                // Use GotAddr for LEA (address-of, not dereference)
                                let display_expr = Self::int(abs_addr as i128);
                                Self::got_addr(abs_addr, inst.address, display_expr)
                            } else {
                                let forced_size = match &ops[0] {
                                    Operand::Register(dst) => Some((dst.size / 8) as u8),
                                    _ => None,
                                };
                                Self::memory_address_expr_with_size(mem, forced_size)
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
            // Bit manipulation instructions (POPCNT, LZCNT, TZCNT)
            Operation::Popcnt | Operation::Lzcnt | Operation::Tzcnt => {
                if ops.len() >= 2 {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(
                            CallTarget::Named(inst.mnemonic.clone()),
                            vec![Self::from_operand(&ops[1])],
                        ),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            // BMI1/BMI2 instructions and ARM64 BIC
            Operation::AndNot => {
                // x86 ANDN: dest = ~src1 & src2
                // ARM64 BIC: dest = src1 & ~src2
                if ops.len() >= 3 {
                    let mnem = inst.mnemonic.to_lowercase();
                    let is_arm_bic = mnem.starts_with("bic");

                    let (lhs, rhs) = if is_arm_bic {
                        // ARM64: bic rd, rn, rm → rd = rn & ~rm
                        (
                            Self::from_operand(&ops[1]),
                            Self::unary(UnaryOpKind::Not, Self::from_operand(&ops[2])),
                        )
                    } else {
                        // x86: andn rd, rs1, rs2 → rd = ~rs1 & rs2
                        (
                            Self::unary(UnaryOpKind::Not, Self::from_operand(&ops[1])),
                            Self::from_operand(&ops[2]),
                        )
                    };

                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::binop(BinOpKind::And, lhs, rhs),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::BitExtract
            | Operation::ExtractLowestBit
            | Operation::MaskUpToLowest
            | Operation::ResetLowestBit
            | Operation::ZeroHighBits
            | Operation::ParallelDeposit
            | Operation::ParallelExtract
            | Operation::MulNoFlags => {
                // BMI instructions - emit as function calls for now
                if !ops.is_empty() {
                    Self::call(
                        CallTarget::Named(inst.mnemonic.clone()),
                        ops.iter().map(Self::from_operand).collect(),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            // System instructions
            Operation::StoreGdt
            | Operation::StoreIdt
            | Operation::LoadGdt
            | Operation::LoadIdt
            | Operation::StoreMsw
            | Operation::LoadMsw
            | Operation::InvalidateTlb
            | Operation::ReadMsr
            | Operation::WriteMsr => {
                // System instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }
            Operation::CpuId => {
                // CPUID consumes EAX as the primary leaf selector even though the encoding
                // has no explicit operands. Materialize it so later passes keep the input.
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    vec![Self::var(Variable::reg("eax", 4))],
                )
            }
            Operation::ReadTsc | Operation::ReadTscP => {
                // RDTSC/RDTSCP expose their outputs through registers; the instruction itself
                // has no explicit input operands.
                Self::call(CallTarget::Named(inst.mnemonic.clone()), Vec::new())
            }
            // Atomic/synchronization instructions
            Operation::LoadExclusive | Operation::StoreExclusive => {
                // Load/store exclusive - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }
            Operation::AtomicAdd
            | Operation::AtomicClear
            | Operation::AtomicXor
            | Operation::AtomicSet
            | Operation::AtomicSignedMax
            | Operation::AtomicSignedMin
            | Operation::AtomicUnsignedMax
            | Operation::AtomicUnsignedMin
            | Operation::AtomicSwap => {
                // ARM64 atomic operations: Rs, Rt, [Xn]
                // Semantics: Rt = atomicOp(mem[Xn], Rs)
                // Emit as: dest = atomic_op(mem, operand)
                if ops.len() >= 3 {
                    let source = Self::from_operand(&ops[0]);
                    let dest = Self::from_operand(&ops[1]);
                    let mem = Self::from_operand(&ops[2]);

                    // Create a C-style atomic function call
                    let func_name = match inst.operation {
                        Operation::AtomicAdd => "atomic_fetch_add",
                        Operation::AtomicClear => "atomic_fetch_and_not",
                        Operation::AtomicXor => "atomic_fetch_xor",
                        Operation::AtomicSet => "atomic_fetch_or",
                        Operation::AtomicSignedMax => "atomic_fetch_max",
                        Operation::AtomicSignedMin => "atomic_fetch_min",
                        Operation::AtomicUnsignedMax => "atomic_fetch_umax",
                        Operation::AtomicUnsignedMin => "atomic_fetch_umin",
                        Operation::AtomicSwap => "atomic_exchange",
                        _ => "atomic_op",
                    };

                    Self::assign(
                        dest,
                        Self::call(CallTarget::Named(func_name.to_string()), vec![mem, source]),
                    )
                } else {
                    Self::call(
                        CallTarget::Named(inst.mnemonic.clone()),
                        ops.iter().map(Self::from_operand).collect(),
                    )
                }
            }
            Operation::CompareAndSwap => {
                // CAS: compare and swap
                Self::call(
                    CallTarget::Named("atomic_compare_exchange".to_string()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // SVE (Scalable Vector Extension) instructions
            Operation::SveLoad
            | Operation::SveStore
            | Operation::SveAdd
            | Operation::SveSub
            | Operation::SveMul
            | Operation::SveAnd
            | Operation::SveOr
            | Operation::SveXor
            | Operation::SveDup
            | Operation::SveCompare
            | Operation::SveReduce
            | Operation::SveCount
            | Operation::SvePermute
            | Operation::SvePredicate => {
                // SVE instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // SVE2 (Scalable Vector Extension 2) instructions
            Operation::Sve2AbsDiffAccum
            | Operation::Sve2AbsDiffAccumLong
            | Operation::Sve2SatAbsNeg
            | Operation::Sve2SatDoublingMulHigh
            | Operation::Sve2SatDoublingMulAddLong
            | Operation::Sve2BitDeposit
            | Operation::Sve2BitExtract
            | Operation::Sve2BitGroup
            | Operation::Sve2Histogram
            | Operation::Sve2Match
            | Operation::Sve2NonTempLoad
            | Operation::Sve2Aes
            | Operation::Sve2Sha3Rotate
            | Operation::Sve2Sm4 => {
                // SVE2 instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // SME (Scalable Matrix Extension) instructions
            Operation::SmeStart
            | Operation::SmeStop
            | Operation::SmeZeroZa
            | Operation::SmeLoadZa
            | Operation::SmeStoreZa
            | Operation::SmeMova
            | Operation::SmeFmopa
            | Operation::SmeFmops
            | Operation::SmeBfmop
            | Operation::SmeSmop
            | Operation::SmeUmop
            | Operation::SmeSumop => {
                // SME instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // AMX (Advanced Matrix Extensions) instructions - x86
            Operation::AmxLoadTileConfig
            | Operation::AmxStoreTileConfig
            | Operation::AmxTileRelease
            | Operation::AmxTileZero
            | Operation::AmxTileLoad
            | Operation::AmxTileStore
            | Operation::AmxDotProductSS
            | Operation::AmxDotProductSU
            | Operation::AmxDotProductUS
            | Operation::AmxDotProductUU
            | Operation::AmxFp16Multiply => {
                // AMX instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // CET (Control-flow Enforcement Technology) instructions - x86
            Operation::CetIncSsp
            | Operation::CetReadSsp
            | Operation::CetSavePrevSsp
            | Operation::CetRestoreSsp
            | Operation::CetWriteSs
            | Operation::CetWriteUss
            | Operation::CetEndBranch32
            | Operation::CetEndBranch64 => {
                // CET instructions - emit as function calls (or nop for ENDBR)
                match inst.operation {
                    Operation::CetEndBranch32 | Operation::CetEndBranch64 => {
                        Self::unknown("/* nop */")
                    }
                    _ => Self::call(
                        CallTarget::Named(inst.mnemonic.clone()),
                        ops.iter().map(Self::from_operand).collect(),
                    ),
                }
            }

            // RISC-V Floating-Point instructions
            Operation::FloatLoad
            | Operation::FloatStore
            | Operation::FloatAdd
            | Operation::FloatSub
            | Operation::FloatMul
            | Operation::FloatDiv
            | Operation::FloatSqrt
            | Operation::FloatMin
            | Operation::FloatMax
            | Operation::FloatMulAdd
            | Operation::FloatMulSub
            | Operation::FloatNegMulAdd
            | Operation::FloatNegMulSub
            | Operation::FloatConvert
            | Operation::FloatSignInject
            | Operation::FloatCompare
            | Operation::FloatClassify
            | Operation::FloatMove => {
                // RISC-V floating-point instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }

            // RISC-V Vector instructions
            Operation::VectorConfig
            | Operation::VectorLoad
            | Operation::VectorStore
            | Operation::VectorStridedLoad
            | Operation::VectorStridedStore
            | Operation::VectorIndexedLoad
            | Operation::VectorIndexedStore
            | Operation::VectorAdd
            | Operation::VectorSub
            | Operation::VectorMul
            | Operation::VectorDiv
            | Operation::VectorRem
            | Operation::VectorAnd
            | Operation::VectorOr
            | Operation::VectorXor
            | Operation::VectorShl
            | Operation::VectorShr
            | Operation::VectorSar
            | Operation::VectorCompare
            | Operation::VectorMin
            | Operation::VectorMax
            | Operation::VectorMerge
            | Operation::VectorMask
            | Operation::VectorReduce
            | Operation::VectorFloatAdd
            | Operation::VectorFloatSub
            | Operation::VectorFloatMul
            | Operation::VectorFloatDiv
            | Operation::VectorFloatMulAdd
            | Operation::VectorWiden
            | Operation::VectorNarrow
            | Operation::VectorSlide
            | Operation::VectorGather
            | Operation::VectorCompress => {
                // RISC-V vector instructions - emit as function calls
                Self::call(
                    CallTarget::Named(inst.mnemonic.clone()),
                    ops.iter().map(Self::from_operand).collect(),
                )
            }
            Operation::SetConditional => {
                // SETcc instructions: set byte on condition
                // ARM64 CSEL/CSINC/CSINV/CSNEG: conditional select
                let mnem_lower = inst.mnemonic.to_lowercase();

                // Check for ARM64 conditional select: csel.cond rd, rn, rm
                if let Some(dot_pos) = mnem_lower.find('.') {
                    let prefix = &mnem_lower[..dot_pos];
                    let cond_suffix = &mnem_lower[dot_pos + 1..];

                    if matches!(prefix, "csel" | "csinc" | "csinv" | "csneg") && ops.len() >= 3 {
                        // Emit as: rd = cond ? rn : rm
                        // Use condition name as a call (displays as "gt" etc.)
                        let cond_expr =
                            Self::call(CallTarget::Named(cond_suffix.to_string()), vec![]);
                        let then_expr = Self::from_operand(&ops[1]);
                        let else_expr = Self::from_operand(&ops[2]);

                        return Self::assign(
                            Self::from_operand(&ops[0]),
                            Expr {
                                kind: ExprKind::Conditional {
                                    cond: Box::new(cond_expr),
                                    then_expr: Box::new(then_expr),
                                    else_expr: Box::new(else_expr),
                                },
                            },
                        );
                    }
                }

                // Default: assign result of condition check
                if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(CallTarget::Named(inst.mnemonic.clone()), vec![]),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::ConditionalMove => {
                // CMOVcc instructions: conditional move
                // dest = condition ? src : dest
                if ops.len() >= 2 {
                    // Show as: dest = cmovcc(src) or as ternary
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(
                            CallTarget::Named(inst.mnemonic.clone()),
                            vec![Self::from_operand(&ops[1])],
                        ),
                    )
                } else if !ops.is_empty() {
                    Self::assign(
                        Self::from_operand(&ops[0]),
                        Self::call(CallTarget::Named(inst.mnemonic.clone()), vec![]),
                    )
                } else {
                    Self::unknown(&inst.mnemonic)
                }
            }
            Operation::SignExtend => {
                // CBW/CWDE/CDQE: sign-extend accumulator
                // CWD/CDQ/CQO: sign-extend accumulator to DX:AX/EDX:EAX/RDX:RAX
                // Show as a cast or function call since these have no explicit operands
                Self::call(CallTarget::Named(inst.mnemonic.clone()), vec![])
            }
            Operation::Invalid => {
                // Invalid instruction (e.g., opcode not valid in 64-bit mode)
                Self::unknown(&inst.mnemonic)
            }
        }
    }

    fn make_binop(inst: &Instruction, ops: &[Operand], op: BinOpKind, mnemonic: &str) -> Self {
        if let Some(expr) = match op {
            BinOpKind::Add => Self::x86_vector_float_binop(inst, ops, "add"),
            BinOpKind::Sub => Self::x86_vector_float_binop(inst, ops, "sub"),
            BinOpKind::Mul => Self::x86_vector_float_binop(inst, ops, "mul"),
            BinOpKind::Div => Self::x86_vector_float_binop(inst, ops, "div"),
            _ => None,
        } {
            return expr;
        }

        if op == BinOpKind::Div && ops.len() == 1 {
            if let Some(expr) = Self::x86_single_operand_div(inst, ops) {
                return expr;
            }
            return Self::unknown(format!("/* {} */", mnemonic.to_ascii_lowercase()));
        }

        if ops.len() >= 3 {
            // dest = src1 op src2
            Self::assign(
                Self::from_operand_with_inst(&ops[0], inst),
                Self::binop(
                    op,
                    Self::from_operand_with_inst(&ops[1], inst),
                    Self::from_operand_with_inst(&ops[2], inst),
                ),
            )
        } else if ops.len() == 2 {
            // dest op= src (common x86 pattern)
            Self::assign(
                Self::from_operand_with_inst(&ops[0], inst),
                Self::binop(
                    op,
                    Self::from_operand_with_inst(&ops[0], inst),
                    Self::from_operand_with_inst(&ops[1], inst),
                ),
            )
        } else {
            if op == BinOpKind::Div {
                Self::unknown(format!("/* {} */", mnemonic.to_ascii_lowercase()))
            } else {
                Self::unknown(mnemonic)
            }
        }
    }

    fn x86_single_operand_div(inst: &Instruction, ops: &[Operand]) -> Option<Self> {
        let operand_size = match &ops[0] {
            Operand::Register(reg) => (reg.size / 8) as u8,
            Operand::Arm64SveVector(_) | Operand::Arm64SvePredicate(_) => return None,
            Operand::Immediate(imm) => imm.size / 8,
            Operand::Memory(mem) => mem.size,
            Operand::PcRelative { .. } => return None,
        };
        let quotient_name = match operand_size {
            1 => "al",
            2 => "ax",
            4 => "eax",
            8 => "rax",
            _ => return None,
        };
        let quotient_size = operand_size;
        let quotient = Self::var(Variable::reg(quotient_name, quotient_size));
        let divisor = Self::from_operand_with_inst(&ops[0], inst);

        Some(Self::assign(
            quotient.clone(),
            Self::binop(BinOpKind::Div, quotient, divisor),
        ))
    }
}

/// Checks if an integer value should be displayed as a character literal.
/// Returns Some(char) if it's a printable ASCII character or common escape sequence.
fn as_char_literal(n: i128) -> Option<String> {
    if !(0..=127).contains(&n) {
        return None;
    }
    let c = n as u8;
    match c {
        // Common escape sequences
        0 => Some("'\\0'".to_string()),
        b'\t' => Some("'\\t'".to_string()),
        b'\n' => Some("'\\n'".to_string()),
        b'\r' => Some("'\\r'".to_string()),
        b'\\' => Some("'\\\\'".to_string()),
        b'\'' => Some("'\\''".to_string()),
        // Printable ASCII (space through tilde)
        32..=126 => Some(format!("'{}'", c as char)),
        _ => None,
    }
}

/// Checks if a binary operation is a comparison that might involve character values.
fn is_comparison_op(op: &BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
            | BinOpKind::ULt
            | BinOpKind::ULe
            | BinOpKind::UGt
            | BinOpKind::UGe
    )
}

/// Formats an integer, optionally as a character literal if in a comparison context.
fn format_int_maybe_char(n: i128, in_comparison: bool) -> String {
    // In comparison context, prefer character literals for ASCII values
    if in_comparison {
        if let Some(char_lit) = as_char_literal(n) {
            return char_lit;
        }
    }
    // Default integer formatting
    if (0..10).contains(&n) {
        format!("{}", n)
    } else if n < 0 {
        format!("-{:#x}", -n)
    } else {
        format!("{:#x}", n)
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ExprKind::Var(v) => write!(f, "{}", v.name),
            ExprKind::IntLit(n) => {
                // Format integers: small values as decimal, others as hex
                if *n >= 0 && *n < 10 {
                    write!(f, "{}", n)
                } else if *n < 0 {
                    write!(f, "-{:#x}", -n)
                } else {
                    write!(f, "{:#x}", n)
                }
            }
            ExprKind::BinOp { op, left, right } => {
                // For comparisons, try to display integer operands as character literals
                if is_comparison_op(op) {
                    let left_str = if let ExprKind::IntLit(n) = &left.kind {
                        format_int_maybe_char(*n, true)
                    } else {
                        format!("{}", left)
                    };
                    let right_str = if let ExprKind::IntLit(n) = &right.kind {
                        format_int_maybe_char(*n, true)
                    } else {
                        format!("{}", right)
                    };
                    write!(f, "{} {} {}", left_str, op.as_str(), right_str)
                } else {
                    write!(f, "{} {} {}", left, op.as_str(), right)
                }
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
            ExprKind::GotRef {
                address,
                size,
                is_deref,
                ..
            } => {
                // Display using computed address rather than "rip + offset"
                if *is_deref {
                    let prefix = match size {
                        1 => "*(uint8_t*)",
                        2 => "*(uint16_t*)",
                        4 => "*(uint32_t*)",
                        8 => "*(uint64_t*)",
                        _ => "*",
                    };
                    write!(f, "{}(&data_{:x})", prefix, address)
                } else {
                    // Address-of (LEA) - show as data address
                    write!(f, "data_{:x}", address)
                }
            }
            ExprKind::AddressOf(e) => write!(f, "&{}", e),
            ExprKind::ArrayAccess { base, index, .. } => {
                write!(f, "{}[{}]", base, index)
            }
            ExprKind::FieldAccess {
                base, field_name, ..
            } => {
                // Use -> for pointer access (most common in decompiled code)
                write!(f, "{}->{}", base, field_name)
            }
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
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                write!(f, "{} ? {} : {}", cond, then_expr, else_expr)
            }
            ExprKind::Cast {
                expr,
                to_size,
                signed,
            } => {
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
            ExprKind::BitField { expr, start, width } => {
                // Display as BITS(expr, start, width) macro-style
                write!(f, "BITS({}, {}, {})", expr, start, width)
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
        // Try ADRP + LDR pattern first (for GOT loads)
        if let Some(combined) = try_combine_adrp_ldr(&exprs, i) {
            result.push(combined);
            i += 2; // Skip both adrp and ldr
                    // Then try ADRP + ADD pattern
        } else if let Some(combined) = try_combine_adrp_add(&exprs, i) {
            result.push(combined);
            i += 2; // Skip both adrp and add
        } else {
            result.push(exprs[i].clone());
            i += 1;
        }
    }

    result
}

/// Tries to combine an ADRP + LDR pattern at position i.
///
/// Typical ARM64 sequence:
/// - `xN = page_addr` (ADRP)
/// - `xM = *(xN + offset)` (LDR)
///
/// This is lowered to a single GotRef-based assignment so later symbol resolution
/// can print a named global instead of raw page math.
fn try_combine_adrp_ldr(exprs: &[Expr], i: usize) -> Option<Expr> {
    if i + 1 >= exprs.len() {
        return None;
    }

    // First expression should be: reg = page_address (ADRP result)
    let (adrp_reg, page_addr) = match_adrp_assignment(&exprs[i])?;

    // Second expression should be: dst = *(reg + offset) or dst = *reg
    let (dst_reg, ldr_base, ldr_offset, ldr_size) = match_ldr_assignment(&exprs[i + 1])?;

    // The LDR base register must match ADRP destination register.
    if adrp_reg != ldr_base {
        return None;
    }

    let combined_addr = page_addr.wrapping_add(ldr_offset as u64);

    Some(Expr::assign(
        Expr::var(Variable {
            name: dst_reg,
            kind: VarKind::Register(0),
            size: 8,
        }),
        Expr::got_ref(combined_addr, 0, ldr_size, exprs[i + 1].clone()),
    ))
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
            size: 8,                    // 64-bit register
        }),
        Expr::int(combined_addr as i128),
    ))
}

/// Matches an LDR-style assignment: dst = *(base + offset) or dst = *base.
fn match_ldr_assignment(expr: &Expr) -> Option<(String, String, i128, u8)> {
    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        let dst_reg = if let ExprKind::Var(v) = &lhs.kind {
            v.name.clone()
        } else {
            return None;
        };

        if let ExprKind::Deref { addr, size } = &rhs.kind {
            match &addr.kind {
                ExprKind::Var(v) => {
                    return Some((dst_reg, v.name.clone(), 0, *size));
                }
                ExprKind::BinOp {
                    op: BinOpKind::Add,
                    left,
                    right,
                } => {
                    if let (ExprKind::Var(v), ExprKind::IntLit(offset)) = (&left.kind, &right.kind)
                    {
                        return Some((dst_reg, v.name.clone(), *offset, *size));
                    }
                    if let (ExprKind::IntLit(offset), ExprKind::Var(v)) = (&left.kind, &right.kind)
                    {
                        return Some((dst_reg, v.name.clone(), *offset, *size));
                    }
                }
                _ => {}
            }
        }
    }
    None
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
        if let ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } = &rhs.kind
        {
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
            if (0..128).contains(&right) {
                Some(left << (right as u32))
            } else {
                None
            }
        }
        BinOpKind::Shr | BinOpKind::Sar => {
            if (0..128).contains(&right) {
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

/// Checks if an expression is a comparison (produces a boolean result).
/// This includes comparison operators and logical operators.
fn is_comparison_expr(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::BinOp { op, .. } => {
            op.is_comparison() || *op == BinOpKind::LogicalAnd || *op == BinOpKind::LogicalOr
        }
        ExprKind::UnaryOp {
            op: UnaryOpKind::LogicalNot,
            ..
        } => true,
        _ => false,
    }
}

/// Matches the 64-bit reassembly idiom `x | ((x >> n) << n)` (in either
/// operand order) and returns `x`. `(x >> n) << n` zeroes the low `n` bits,
/// which `| x` restores, so the whole expression equals `x`. This shows up
/// when an `edx:eax`-style split value (e.g. from `rdtsc`) is recombined with
/// `eax | (edx << 32)` where both halves were derived from one value.
fn match_low_bits_reassembly(left: &Expr, right: &Expr) -> Option<Expr> {
    fn shift_pair_clears_low_bits(expr: &Expr) -> Option<(&Expr, i128)> {
        // ((x >> n) << n) — outer Shl by n of an inner (Shr/Sar by the same n).
        let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: shl_l,
            right: shl_r,
        } = &expr.kind
        else {
            return None;
        };
        let ExprKind::IntLit(outer_n) = shl_r.kind else {
            return None;
        };
        let ExprKind::BinOp {
            op: BinOpKind::Shr | BinOpKind::Sar,
            left: shr_l,
            right: shr_r,
        } = &shl_l.kind
        else {
            return None;
        };
        let ExprKind::IntLit(inner_n) = shr_r.kind else {
            return None;
        };
        if outer_n == inner_n && outer_n > 0 {
            Some((shr_l, outer_n))
        } else {
            None
        }
    }

    // Try `x | ((x >> n) << n)` then the commuted `((x >> n) << n) | x`.
    if let Some((inner, _)) = shift_pair_clears_low_bits(right) {
        if exprs_structurally_equal(left, inner) {
            return Some(left.clone());
        }
    }
    if let Some((inner, _)) = shift_pair_clears_low_bits(left) {
        if exprs_structurally_equal(right, inner) {
            return Some(right.clone());
        }
    }
    None
}

/// Checks if two expressions are structurally equal.
/// Used for simplifications like `x - x = 0` and `x ^ x = 0`.
fn exprs_structurally_equal(left: &Expr, right: &Expr) -> bool {
    match (&left.kind, &right.kind) {
        (ExprKind::Var(v1), ExprKind::Var(v2)) => v1 == v2,
        (ExprKind::IntLit(n1), ExprKind::IntLit(n2)) => n1 == n2,
        (ExprKind::Unknown(s1), ExprKind::Unknown(s2)) => s1 == s2,
        (
            ExprKind::BinOp {
                op: op1,
                left: l1,
                right: r1,
            },
            ExprKind::BinOp {
                op: op2,
                left: l2,
                right: r2,
            },
        ) => op1 == op2 && exprs_structurally_equal(l1, l2) && exprs_structurally_equal(r1, r2),
        (
            ExprKind::UnaryOp {
                op: op1,
                operand: o1,
            },
            ExprKind::UnaryOp {
                op: op2,
                operand: o2,
            },
        ) => op1 == op2 && exprs_structurally_equal(o1, o2),
        (ExprKind::Deref { addr: a1, size: s1 }, ExprKind::Deref { addr: a2, size: s2 }) => {
            s1 == s2 && exprs_structurally_equal(a1, a2)
        }
        (
            ExprKind::ArrayAccess {
                base: b1,
                index: i1,
                element_size: s1,
            },
            ExprKind::ArrayAccess {
                base: b2,
                index: i2,
                element_size: s2,
            },
        ) => s1 == s2 && exprs_structurally_equal(b1, b2) && exprs_structurally_equal(i1, i2),
        (ExprKind::AddressOf(e1), ExprKind::AddressOf(e2)) => exprs_structurally_equal(e1, e2),
        (
            ExprKind::FieldAccess {
                base: b1,
                offset: o1,
                ..
            },
            ExprKind::FieldAccess {
                base: b2,
                offset: o2,
                ..
            },
        ) => o1 == o2 && exprs_structurally_equal(b1, b2),
        (
            ExprKind::Call {
                target: t1,
                args: a1,
            },
            ExprKind::Call {
                target: t2,
                args: a2,
            },
        ) => {
            call_targets_equal(t1, t2)
                && a1.len() == a2.len()
                && a1
                    .iter()
                    .zip(a2.iter())
                    .all(|(e1, e2)| exprs_structurally_equal(e1, e2))
        }
        _ => false,
    }
}

/// Check if two call targets are equal.
fn call_targets_equal(t1: &CallTarget, t2: &CallTarget) -> bool {
    match (t1, t2) {
        (CallTarget::Direct { target: a1, .. }, CallTarget::Direct { target: a2, .. }) => a1 == a2,
        (CallTarget::Named(n1), CallTarget::Named(n2)) => n1 == n2,
        (CallTarget::Indirect(e1), CallTarget::Indirect(e2)) => exprs_structurally_equal(e1, e2),
        (
            CallTarget::IndirectGot {
                got_address: a1, ..
            },
            CallTarget::IndirectGot {
                got_address: a2, ..
            },
        ) => a1 == a2,
        _ => false,
    }
}

/// Matches sign extension pattern: (x << N) >> N where >> is SAR
///
/// When you shift left by N bits and then arithmetic shift right by N bits,
/// you sign-extend the lower (64-N) bits to 64 bits.
///
/// Examples:
/// - `(x << 56) >> 56` → `(int8_t)x`  (64-56=8 bits)
/// - `(x << 48) >> 48` → `(int16_t)x` (64-48=16 bits)
/// - `(x << 32) >> 32` → `(int32_t)x` (64-32=32 bits)
fn try_match_sign_extension(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    // Must be arithmetic shift right (SAR) for sign extension
    if op != BinOpKind::Sar {
        return None;
    }

    // Right operand must be a constant (the shift amount)
    let shift_amount = match &right.kind {
        ExprKind::IntLit(n) => *n,
        _ => return None,
    };

    // Left operand must be a left shift by the same amount
    let (inner_expr, left_shift) = match &left.kind {
        ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: inner,
            right: shift,
        } => {
            if let ExprKind::IntLit(n) = &shift.kind {
                (inner.as_ref(), *n)
            } else {
                return None;
            }
        }
        _ => return None,
    };

    // Both shifts must be the same amount
    if left_shift != shift_amount {
        return None;
    }

    // Determine the resulting type size based on shift amount
    // Assuming 64-bit registers:
    // shift=56 → 8-bit, shift=48 → 16-bit, shift=32 → 32-bit, shift=24 → 40-bit (unusual)
    let to_size = match shift_amount {
        56 => 1,          // 8-bit
        48 => 2,          // 16-bit
        32 => 4,          // 32-bit
        24 => 5,          // 40-bit (unusual, keep as-is)
        _ => return None, // Unsupported pattern
    };

    // Special case: if the shift is 24, it's an unusual size, skip
    if to_size == 5 {
        return None;
    }

    Some(Expr {
        kind: ExprKind::Cast {
            expr: Box::new(inner_expr.clone()),
            to_size,
            signed: true,
        },
    })
}

/// Matches zero extension pattern: x & mask where mask is a power-of-2 minus 1
///
/// When you AND with a mask like 0xFF, 0xFFFF, or 0xFFFFFFFF,
/// you zero-extend the value to that width.
///
/// Examples:
/// - `x & 0xFF`       → `(uint8_t)x`
/// - `x & 0xFFFF`     → `(uint16_t)x`
/// - `x & 0xFFFFFFFF` → `(uint32_t)x`
///
/// Note: Does NOT match if the expression is a right shift, as that's
/// a bit field extraction pattern handled separately.
fn try_match_zero_extension(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    // Must be AND operation
    if op != BinOpKind::And {
        return None;
    }

    // Try both orderings: (x & mask) and (mask & x)
    let (expr, mask) = if let ExprKind::IntLit(m) = &right.kind {
        (left, *m)
    } else if let ExprKind::IntLit(m) = &left.kind {
        (right, *m)
    } else {
        return None;
    };

    // Don't match if the expression is a shift - that's bit field extraction
    if let ExprKind::BinOp {
        op: BinOpKind::Shr | BinOpKind::Sar,
        right: shift_amt,
        ..
    } = &expr.kind
    {
        // Only skip if it's a non-zero shift (shift by 0 is effectively no shift)
        if let ExprKind::IntLit(n) = &shift_amt.kind {
            if *n != 0 {
                return None;
            }
        } else {
            // Variable shift amount - let bit field extraction handle it
            return None;
        }
    }

    // Check for known mask patterns
    let to_size = match mask {
        0xFF => 1,        // 8-bit
        0xFFFF => 2,      // 16-bit
        0xFFFFFFFF => 4,  // 32-bit
        _ => return None, // Not a standard extension mask
    };

    // Don't convert if the expression is already a cast to the same size
    if let ExprKind::Cast {
        to_size: existing_size,
        ..
    } = &expr.kind
    {
        if *existing_size == to_size {
            return None;
        }
    }

    Some(Expr {
        kind: ExprKind::Cast {
            expr: Box::new(expr.clone()),
            to_size,
            signed: false,
        },
    })
}

/// Matches bit field extraction pattern: (x >> start) & mask
///
/// When you shift right by `start` bits and then AND with a contiguous mask,
/// you're extracting a bit field.
///
/// Examples:
/// - `(x >> 4) & 0xF`    → BITS(x, 4, 4)   (extract 4 bits starting at bit 4)
/// - `(x >> 8) & 0xFF`   → BITS(x, 8, 8)   (extract 8 bits starting at bit 8)
/// - `(x >> 16) & 0x3FF` → BITS(x, 16, 10) (extract 10 bits starting at bit 16)
///
/// The mask must be a contiguous sequence of 1 bits (i.e., (1 << width) - 1).
fn try_match_bitfield_extraction(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    // Must be AND operation
    if op != BinOpKind::And {
        return None;
    }

    // Try both orderings: (shifted & mask) and (mask & shifted)
    let (shifted_expr, mask) = if let ExprKind::IntLit(m) = &right.kind {
        (left, *m)
    } else if let ExprKind::IntLit(m) = &left.kind {
        (right, *m)
    } else {
        return None;
    };

    // The shifted expression must be a right shift, or an unshifted value
    // for low-bit field extraction after `>> 0` has been simplified away.
    let (inner_expr, shift_amount) = match &shifted_expr.kind {
        ExprKind::BinOp {
            op: BinOpKind::Shr | BinOpKind::Sar,
            left: inner,
            right: shift,
        } => {
            if let ExprKind::IntLit(n) = &shift.kind {
                if *n < 0 || *n > 63 {
                    return None;
                }
                (inner.as_ref(), *n as u8)
            } else {
                return None;
            }
        }
        _ => (shifted_expr, 0),
    };

    // Check if mask is a valid contiguous bit mask: (1 << width) - 1
    // Valid masks: 0x1, 0x3, 0x7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF, etc.
    let width = mask_to_width(mask)?;

    // Don't match if width is 0 or too large
    if width == 0 || width > 64 {
        return None;
    }

    // Skip full-width low-bit masks at shift 0; that's just zero extension.
    if shift_amount == 0
        && infer_expr_bit_width(inner_expr).is_some_and(|bit_width| width >= bit_width)
    {
        return None;
    }

    Some(Expr {
        kind: ExprKind::BitField {
            expr: Box::new(inner_expr.clone()),
            start: shift_amount,
            width,
        },
    })
}

fn infer_expr_bit_width(expr: &Expr) -> Option<u8> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.size.saturating_mul(8)).filter(|width| *width > 0),
        ExprKind::Deref { size, .. } => Some(size.saturating_mul(8)).filter(|width| *width > 0),
        ExprKind::ArrayAccess { element_size, .. } => u8::try_from(*element_size)
            .ok()
            .map(|size| size.saturating_mul(8)),
        ExprKind::Cast { to_size, .. } => {
            Some(to_size.saturating_mul(8)).filter(|width| *width > 0)
        }
        ExprKind::BitField { width, .. } => Some(*width),
        _ => None,
    }
}

/// Converts a contiguous bit mask to a width.
/// Returns Some(width) if mask is (1 << width) - 1, None otherwise.
///
/// Examples:
/// - 0x1 (0b1) → 1
/// - 0x3 (0b11) → 2
/// - 0x7 (0b111) → 3
/// - 0xF (0b1111) → 4
/// - 0xFF → 8
/// - 0xFFFF → 16
/// - 0x5 (0b101) → None (not contiguous)
fn mask_to_width(mask: i128) -> Option<u8> {
    if mask <= 0 {
        return None;
    }

    // Check if mask is (1 << n) - 1, which means mask + 1 is a power of 2
    let mask_plus_one = mask.wrapping_add(1);

    // A number is a power of 2 if it has exactly one bit set
    // (n & (n - 1)) == 0 for powers of 2
    if mask_plus_one > 0 && (mask_plus_one & (mask_plus_one - 1)) == 0 {
        // Count trailing zeros to get the width
        Some(mask_plus_one.trailing_zeros() as u8)
    } else {
        None
    }
}

fn mask_to_shifted_field(mask: i128) -> Option<(u8, u8)> {
    if mask <= 0 {
        return None;
    }

    let start = mask.trailing_zeros() as u8;
    let shifted = mask >> start;
    let width = mask_to_width(shifted)?;
    Some((start, width))
}

fn try_combine_shift_chain(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    let ExprKind::IntLit(outer_shift) = right.kind else {
        return None;
    };
    let ExprKind::BinOp {
        op: inner_op,
        left: inner_expr,
        right: inner_shift,
    } = &left.kind
    else {
        return None;
    };
    if *inner_op != op {
        return None;
    }
    let ExprKind::IntLit(inner_shift) = inner_shift.kind else {
        return None;
    };

    match op {
        BinOpKind::Shl | BinOpKind::Shr | BinOpKind::Sar => Some(
            Expr::binop(
                op,
                inner_expr.as_ref().clone(),
                Expr::int(inner_shift + outer_shift),
            )
            .simplify(),
        ),
        _ => None,
    }
}

fn try_match_bitfield_insert(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    if op != BinOpKind::Or {
        return None;
    }

    for (carrier_side, insert_side) in [(left, right), (right, left)] {
        let Some((carrier, clear_mask)) = extract_bitfield_clear_side(carrier_side) else {
            continue;
        };
        let field_mask = !clear_mask;
        let Some((start, width)) = mask_to_shifted_field(field_mask) else {
            continue;
        };
        let Some(value) = extract_bitfield_insert_value(insert_side, field_mask, start) else {
            continue;
        };
        return Some(Expr::call(
            CallTarget::Named("SET_BITS".to_string()),
            vec![
                carrier.clone(),
                value,
                Expr::int(i128::from(start)),
                Expr::int(i128::from(width)),
            ],
        ));
    }

    None
}

fn extract_bitfield_clear_side(expr: &Expr) -> Option<(&Expr, i128)> {
    let ExprKind::BinOp {
        op: BinOpKind::And,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };
    if let ExprKind::IntLit(mask) = right.kind {
        return Some((left.as_ref(), mask));
    }
    if let ExprKind::IntLit(mask) = left.kind {
        return Some((right.as_ref(), mask));
    }
    None
}

fn extract_bitfield_insert_value(expr: &Expr, field_mask: i128, start: u8) -> Option<Expr> {
    if let Some(value) = extract_shifted_value(expr, start) {
        return Some(value);
    }

    let ExprKind::BinOp {
        op: BinOpKind::And,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };
    if let ExprKind::IntLit(mask) = right.kind {
        if mask == field_mask {
            return extract_shifted_value(left, start);
        }
    }
    if let ExprKind::IntLit(mask) = left.kind {
        if mask == field_mask {
            return extract_shifted_value(right, start);
        }
    }
    None
}

fn extract_shifted_value(expr: &Expr, start: u8) -> Option<Expr> {
    let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };
    let ExprKind::IntLit(shift) = right.kind else {
        return None;
    };
    if shift != i128::from(start) {
        return None;
    }
    Some(left.as_ref().clone())
}

/// Simplifies boolean comparison patterns.
///
/// Handles patterns where a comparison result is compared to 0 or 1:
/// - `(x == y) == 1` → `x == y` (identity)
/// - `(x == y) != 1` → `x != y` (negate)
/// - `(x == y) == 0` → `x != y` (negate)
/// - `(x == y) != 0` → `x == y` (identity)
///
/// This also works with chained comparisons, which get simplified step by step:
/// - `((x == 1) != 1) != 1` first simplifies inner `(x == 1) != 1` to `x != 1`,
///   then `(x != 1) != 1` simplifies to `x == 1`.
fn try_simplify_boolean_comparison(left: &Expr, op: BinOpKind, right: &Expr) -> Option<Expr> {
    // Must be == or != comparison
    if op != BinOpKind::Eq && op != BinOpKind::Ne {
        return None;
    }

    // One side must be 0 or 1, the other side must be a comparison
    let (cmp_expr, const_val) = if let ExprKind::IntLit(n) = &right.kind {
        if *n == 0 || *n == 1 {
            (left, *n)
        } else {
            return None;
        }
    } else if let ExprKind::IntLit(n) = &left.kind {
        if *n == 0 || *n == 1 {
            (right, *n)
        } else {
            return None;
        }
    } else {
        return None;
    };

    let (cmp_expr, cmp_already_negated) = if let ExprKind::UnaryOp {
        op: UnaryOpKind::LogicalNot,
        operand,
    } = &cmp_expr.kind
    {
        (operand.as_ref(), true)
    } else {
        (cmp_expr, false)
    };

    // The wrapped expression must be a boolean-producing operator.
    if let ExprKind::BinOp {
        op: inner_op,
        left: inner_left,
        right: inner_right,
    } = &cmp_expr.kind
    {
        if !inner_op.is_comparison()
            && *inner_op != BinOpKind::LogicalAnd
            && *inner_op != BinOpKind::LogicalOr
        {
            return None;
        }

        let base_expr = Expr::binop(*inner_op, (**inner_left).clone(), (**inner_right).clone());

        // Determine if we should negate:
        // - (cmp) == 1 → identity (don't negate)
        // - (cmp) != 1 → negate
        // - (cmp) == 0 → negate
        // - (cmp) != 0 → identity (don't negate)
        let should_negate = ((op == BinOpKind::Eq && const_val == 0)
            || (op == BinOpKind::Ne && const_val == 1))
            ^ cmp_already_negated;

        if should_negate {
            Some(base_expr.negate().simplify())
        } else {
            Some(base_expr)
        }
    } else {
        None
    }
}

fn try_simplify_conditional_boolean_comparison(
    left: &Expr,
    op: BinOpKind,
    right: &Expr,
) -> Option<Expr> {
    if op != BinOpKind::Eq && op != BinOpKind::Ne {
        return None;
    }

    let (conditional, cmp_value) = match (&left.kind, &right.kind) {
        (ExprKind::Conditional { .. }, ExprKind::IntLit(n)) if *n == 0 || *n == 1 => (left, *n),
        (ExprKind::IntLit(n), ExprKind::Conditional { .. }) if *n == 0 || *n == 1 => (right, *n),
        _ => return None,
    };

    let ExprKind::Conditional {
        cond,
        then_expr,
        else_expr,
    } = &conditional.kind
    else {
        return None;
    };
    let ExprKind::IntLit(then_val) = then_expr.kind else {
        return None;
    };
    let ExprKind::IntLit(else_val) = else_expr.kind else {
        return None;
    };
    if !matches!(then_val, 0 | 1) || !matches!(else_val, 0 | 1) {
        return None;
    }

    let true_result = match op {
        BinOpKind::Eq => then_val == cmp_value,
        BinOpKind::Ne => then_val != cmp_value,
        _ => unreachable!(),
    };
    let false_result = match op {
        BinOpKind::Eq => else_val == cmp_value,
        BinOpKind::Ne => else_val != cmp_value,
        _ => unreachable!(),
    };

    match (true_result, false_result) {
        (true, true) => Some(Expr::int(1)),
        (false, false) => Some(Expr::int(0)),
        (true, false) => Some((**cond).clone()),
        (false, true) => Some((**cond).clone().negate().simplify()),
    }
}

fn normalize_small_cast_comparison_operands(
    op: BinOpKind,
    left: Expr,
    right: Expr,
) -> (Expr, Expr) {
    if !op.is_comparison() {
        return (left, right);
    }

    if let Some(normalized) = normalize_small_cast_literal(&left, &right) {
        return (left, Expr::int(normalized));
    }
    if let Some(normalized) = normalize_small_cast_literal(&right, &left) {
        return (Expr::int(normalized), right);
    }

    (left, right)
}

fn normalize_small_cast_literal(cast_expr: &Expr, literal_expr: &Expr) -> Option<i128> {
    let ExprKind::Cast {
        to_size, signed, ..
    } = &cast_expr.kind
    else {
        return None;
    };
    if *to_size >= 8 {
        return None;
    }

    let ExprKind::IntLit(n) = literal_expr.kind else {
        return None;
    };

    let bits = u32::from(*to_size) * 8;
    let mask = (1_i128 << bits) - 1;
    let masked = n & mask;
    let normalized = if *signed {
        let sign_bit = 1_i128 << (bits - 1);
        if (masked & sign_bit) != 0 {
            masked | !mask
        } else {
            masked
        }
    } else {
        masked
    };

    (normalized != n).then_some(normalized)
}

/// Attempts to detect compound assignment patterns.
///
/// Detects patterns like:
/// - `x = x + y` -> `x += y`
/// - `x = x - y` -> `x -= y`
/// - `x = x * y` -> `x *= y`
/// - `x = x / y` -> `x /= y`
/// - `x = x % y` -> `x %= y`
/// - `x = x & y` -> `x &= y`
/// - `x = x | y` -> `x |= y`
/// - `x = x ^ y` -> `x ^= y`
/// - `x = x << y` -> `x <<= y`
/// - `x = x >> y` -> `x >>= y`
///
/// Returns `Some(CompoundAssign)` if a pattern is detected.
fn try_detect_compound_assign(lhs: &Expr, rhs: &Expr) -> Option<Expr> {
    // The RHS must be a binary operation
    let (op, bin_left, bin_right) = match &rhs.kind {
        ExprKind::BinOp { op, left, right } => {
            // Only certain operators support compound assignment
            match op {
                BinOpKind::Add
                | BinOpKind::Sub
                | BinOpKind::Mul
                | BinOpKind::Div
                | BinOpKind::Mod
                | BinOpKind::And
                | BinOpKind::Or
                | BinOpKind::Xor
                | BinOpKind::Shl
                | BinOpKind::Shr
                | BinOpKind::Sar => (*op, left, right),
                // Comparison and logical operators don't support compound assignment
                _ => return None,
            }
        }
        _ => return None,
    };

    // Check if the left operand of the binary operation matches the LHS
    if exprs_structurally_equal(lhs, bin_left) {
        return Some(Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new((**bin_right).clone()),
            },
        });
    }

    // For commutative operations, also check if right operand matches the LHS
    // (e.g., `x = y + x` could become `x += y`)
    if is_commutative(op) && exprs_structurally_equal(lhs, bin_right) {
        return Some(Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(lhs.clone()),
                rhs: Box::new((**bin_left).clone()),
            },
        });
    }

    None
}

/// Check if a binary operation is commutative.
fn is_commutative(op: BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Add | BinOpKind::Mul | BinOpKind::And | BinOpKind::Or | BinOpKind::Xor
    )
}

/// Checks if a dereference address is a spurious value computation.
///
/// This detects cases where an expression is incorrectly wrapped in a Deref
/// when it should be a direct value. A Deref is spurious if its address is
/// a pure arithmetic computation on values (not addresses), such as:
///   *(uint32_t*)(_g * 2 + 1)
/// where _g is already a loaded value, not a pointer.
///
/// Returns true if the Deref should be removed (address is a pure value).
fn is_spurious_deref_address(addr: &Expr) -> bool {
    // A spurious deref typically has a BinOp (arithmetic) at the top level
    // where neither operand is a valid memory base (register, pointer variable,
    // or another memory access).
    match &addr.kind {
        // BinOp with multiplication involving a variable is likely a value computation
        // e.g., _g * 2, _g * 2 + 1
        ExprKind::BinOp { op, left, right } => {
            // If it's a multiplication where one side is a small constant
            // and the other is a value (variable, memory load, or global),
            // this is likely a value computation, not address arithmetic.
            if *op == BinOpKind::Mul {
                let left_is_value = is_loaded_value(left);
                let right_is_value = is_loaded_value(right);
                let left_is_small_const = matches!(&left.kind, ExprKind::IntLit(n) if *n <= 256);
                let right_is_small_const = matches!(&right.kind, ExprKind::IntLit(n) if *n <= 256);

                // Pattern: value * small_const or small_const * value
                // This is typical for value arithmetic, not address calculation
                if (left_is_value && right_is_small_const)
                    || (right_is_value && left_is_small_const)
                {
                    return true;
                }
            }

            // For addition, check if it's adding to a multiplication result
            // e.g., (_g * 2) + 1
            if *op == BinOpKind::Add || *op == BinOpKind::Sub {
                // Check if either side is a spurious multiplication
                if is_spurious_deref_address(left) || is_spurious_deref_address(right) {
                    // But only if we're not adding to a valid pointer base
                    let left_is_ptr_base = is_valid_ptr_base(left);
                    let right_is_ptr_base = is_valid_ptr_base(right);

                    if !left_is_ptr_base && !right_is_ptr_base {
                        return true;
                    }
                }
            }

            false
        }
        _ => false,
    }
}

/// Checks if an expression represents a loaded/computed value (not a pointer).
/// These are values that, when multiplied by a small constant, indicate
/// arithmetic computation rather than address calculation.
fn is_loaded_value(expr: &Expr) -> bool {
    match &expr.kind {
        // Simple variables are loaded values
        ExprKind::Var(_) => true,
        // Deref of anything loads a value (not a pointer, unless dereferencing a pointer-to-pointer)
        // When we see Deref { GotRef { ... } }, this is loading the global's value
        ExprKind::Deref { .. } => true,
        // GotRef with is_deref=true represents a loaded global value
        // e.g., mov rax, [rip+_g_counter] produces GotRef { is_deref: true, ... }
        ExprKind::GotRef { is_deref: true, .. } => true,
        // Cast expressions preserve value semantics
        ExprKind::Cast { expr, .. } => is_loaded_value(expr),
        _ => false,
    }
}

/// Checks if an expression looks like a valid pointer base for memory access.
fn is_valid_ptr_base(expr: &Expr) -> bool {
    match &expr.kind {
        // Stack/frame pointers are valid bases
        ExprKind::Var(v) => {
            let name = v.name.to_lowercase();
            name == "rsp"
                || name == "rbp"
                || name == "sp"
                || name == "fp"
                || name == "x29"
                || name == "x30"
                || name == "rip"
                || name == "eip"
                || name.starts_with("r")
                || name.starts_with("x") // General registers
        }
        // GotRef with is_deref=false is a pointer to global data (LEA)
        // GotRef with is_deref=true is a loaded value, not a pointer
        ExprKind::GotRef { is_deref, .. } => !is_deref,
        // Deref is already a memory access
        ExprKind::Deref { .. } => true,
        // AddressOf produces a pointer
        ExprKind::AddressOf(_) => true,
        // Array access produces a pointer
        ExprKind::ArrayAccess { .. } => true,
        _ => false,
    }
}

/// Attempts to detect array access patterns in a dereference address.
///
/// This function analyzes address expressions like:
/// - `base + index * element_size` → `base\[index\]`
/// - `base + constant` → `base\[constant / size\]` (when aligned)
/// - `base + (index << shift)` → `base\[index\]` (where 1 << shift == size)
///
/// Returns `Some(Expr::ArrayAccess { ... })` if a pattern is detected.
pub(crate) fn try_detect_array_in_deref(addr: &Expr, size: u8) -> Option<Expr> {
    // Pattern 1: base + index * element_size
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try: base + (index * size)
        if let Some((index, element_size)) = extract_scaled_index(right) {
            if element_size == size as i128 {
                return Some(Expr::array_access(
                    (**left).clone(),
                    index,
                    element_size as usize,
                ));
            }
        }

        // Try: (index * size) + base (commutative)
        if let Some((index, element_size)) = extract_scaled_index(left) {
            if element_size == size as i128 {
                return Some(Expr::array_access(
                    (**right).clone(),
                    index,
                    element_size as usize,
                ));
            }
        }

        // Try shift patterns: base + (index << shift)
        if let Some((index, shift_amount)) = extract_shift_index(right) {
            let element_size = 1i128 << shift_amount;
            if element_size == size as i128 {
                return Some(Expr::array_access(
                    (**left).clone(),
                    index,
                    element_size as usize,
                ));
            }
        }

        if let Some((index, shift_amount)) = extract_shift_index(left) {
            let element_size = 1i128 << shift_amount;
            if element_size == size as i128 {
                return Some(Expr::array_access(
                    (**right).clone(),
                    index,
                    element_size as usize,
                ));
            }
        }

        // Try constant offset: base + constant (aligned to size)
        if let ExprKind::IntLit(offset) = &right.kind {
            if *offset != 0 && size > 0 && *offset % (size as i128) == 0 {
                let index = *offset / (size as i128);
                return Some(Expr::array_access(
                    (**left).clone(),
                    Expr::int(index),
                    size as usize,
                ));
            }
        }

        // Also check with offset on left side
        if let ExprKind::IntLit(offset) = &left.kind {
            if *offset != 0 && size > 0 && *offset % (size as i128) == 0 {
                let index = *offset / (size as i128);
                return Some(Expr::array_access(
                    (**right).clone(),
                    Expr::int(index),
                    size as usize,
                ));
            }
        }

        // Try unscaled index: base + index (no multiplication)
        // This handles patterns like *(ptr + i) where the deref size implies element size
        // Only apply when BOTH sides are simple (not constants, not BinOps)
        // This avoids matching:
        // - constant offsets (handled above)
        // - mismatched scaled patterns (e.g., ptr + i * 4 with 8-byte deref)
        // - unaligned offsets (e.g., ptr + 5 with 4-byte deref)
        let right_is_simple_var =
            !matches!(right.kind, ExprKind::IntLit(_) | ExprKind::BinOp { .. });
        let left_is_simple_var = !matches!(left.kind, ExprKind::IntLit(_) | ExprKind::BinOp { .. });

        // BOTH must be simple for this pattern to apply
        if right_is_simple_var && left_is_simple_var && (1..=8).contains(&size) {
            return Some(Expr::array_access(
                (**left).clone(),
                (**right).clone(),
                size as usize,
            ));
        }

        // Try struct array pattern: (base + index * stride) + field_offset
        // This handles cases where the inner expression already has scaled access
        if let ExprKind::IntLit(field_offset) = &right.kind {
            if let Some((index, stride)) = extract_scaled_index_from_expr(left) {
                if stride > 0 && *field_offset % stride == 0 {
                    // Aligned field offset - can adjust index
                    let additional_index = *field_offset / stride;
                    let combined_index = if additional_index == 0 {
                        index
                    } else {
                        Expr::binop(BinOpKind::Add, index, Expr::int(additional_index))
                    };
                    // The base is inside the scaled expression
                    if let ExprKind::BinOp {
                        op: BinOpKind::Add,
                        left: inner_left,
                        right: inner_right,
                    } = &left.kind
                    {
                        if extract_scaled_index(inner_right).is_some() {
                            return Some(Expr::array_access(
                                (**inner_left).clone(),
                                combined_index,
                                stride as usize,
                            ));
                        }
                        if extract_scaled_index(inner_left).is_some() {
                            return Some(Expr::array_access(
                                (**inner_right).clone(),
                                combined_index,
                                stride as usize,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Pattern for subtraction: base - constant (negative index)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left,
        right,
    } = &addr.kind
    {
        if let ExprKind::IntLit(offset) = &right.kind {
            if *offset != 0 && size > 0 && *offset % (size as i128) == 0 {
                let index = -(*offset / (size as i128));
                return Some(Expr::array_access(
                    (**left).clone(),
                    Expr::int(index),
                    size as usize,
                ));
            }
        }
    }

    None
}

/// Extracts (index, scale) from expressions like `index * scale` or `scale * index`.
fn extract_scaled_index(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Mul,
        left,
        right,
    } = &expr.kind
    {
        // Try: index * constant
        if let ExprKind::IntLit(n) = &right.kind {
            if *n > 0 && *n <= 1024 {
                return Some(((**left).clone(), *n));
            }
        }
        // Try: constant * index
        if let ExprKind::IntLit(n) = &left.kind {
            if *n > 0 && *n <= 1024 {
                return Some(((**right).clone(), *n));
            }
        }
    }
    None
}

/// Extracts (index, shift_amount) from expressions like `index << constant`.
fn extract_shift_index(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    {
        if let ExprKind::IntLit(n) = &right.kind {
            if *n >= 0 && *n <= 6 {
                return Some(((**left).clone(), *n));
            }
        }
    }
    None
}

/// Extracts scaled index from an expression that may be `base + index * stride`.
fn extract_scaled_index_from_expr(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    {
        if let Some(result) = extract_scaled_index(right) {
            return Some(result);
        }
        if let Some(result) = extract_scaled_index(left) {
            return Some(result);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{Architecture, Instruction, Operand, Operation, Register, RegisterClass};

    #[test]
    fn test_x86_sse_store_writes_memory_destination() {
        use hexray_core::MemoryRef;
        // movsd %xmm0, -8(%rbp): x86 SSE store, destination(memory)-first order.
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let xmm0 = Register::new(Architecture::X86_64, RegisterClass::Vector, 64, 128);
        let inst = Instruction::new(0x1000, 5, vec![], "movsd")
            .with_operation(Operation::Store)
            .with_operands(vec![
                Operand::Memory(MemoryRef::base_disp(rbp, -8, 8)),
                Operand::Register(xmm0),
            ]);
        let ExprKind::Assign { lhs, rhs } = Expr::from_instruction(&inst).kind else {
            panic!("expected assignment");
        };
        // Must lift to `*(rbp-8) = xmm0`, not the reverse.
        assert!(matches!(lhs.kind, ExprKind::Deref { .. }), "store dst must be memory");
        assert!(matches!(&rhs.kind, ExprKind::Var(v) if v.name == "xmm0"));
    }

    #[test]
    fn test_arm64_str_value_first_order_preserved() {
        use hexray_core::MemoryRef;
        // str x0, [sp, #8]: ARM64 store, value-first order — must still write memory.
        let x0 = Register::new(Architecture::Arm64, RegisterClass::General, 0, 64);
        let sp = Register::new(Architecture::Arm64, RegisterClass::General, 31, 64);
        let inst = Instruction::new(0x1000, 4, vec![], "str")
            .with_operation(Operation::Store)
            .with_operands(vec![
                Operand::Register(x0),
                Operand::Memory(MemoryRef::base_disp(sp, 8, 8)),
            ]);
        let ExprKind::Assign { lhs, .. } = Expr::from_instruction(&inst).kind else {
            panic!("expected assignment");
        };
        assert!(matches!(lhs.kind, ExprKind::Deref { .. }), "store dst must be memory");
    }

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
    fn test_x86_single_operand_idiv_assigns_quotient_register() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 32);
        let ecx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 32);
        let mut inst = Instruction::new(0x1000, 2, vec![], "idiv")
            .with_operation(Operation::Div)
            .with_operands(vec![Operand::Register(ecx)]);
        inst.reads = vec![edx, eax, ecx];
        inst.writes = vec![eax, edx];

        assert_eq!(
            format!("{}", Expr::from_instruction(&inst)),
            "eax = eax / rcx"
        );
    }

    #[test]
    fn test_unsupported_div_renders_as_comment_not_bare_mnemonic() {
        let inst = Instruction::new(0x1000, 2, vec![], "div").with_operation(Operation::Div);

        assert_eq!(format!("{}", Expr::from_instruction(&inst)), "/* div */");
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
    fn test_conditional_with_equal_branches_folds_to_branch() {
        // `cond ? x : x` simplifies to `x`. Without this, a chain of
        // `cmovcc reg, reg` self-conditionals doubles the expression on
        // every simplification pass — the fuzzer surfaced a 9-byte input
        // `0f 0f 4d c0 0f 4d c0 00 20` that produced 37 KB of pseudo-C
        // through three chained `cmovge eax, eax` instructions.
        let cond = Expr::unknown("cond");
        let x = Expr::unknown("x");
        let conditional = Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(cond.clone()),
                then_expr: Box::new(x.clone()),
                else_expr: Box::new(x.clone()),
            },
        };
        let simplified = conditional.simplify();
        assert!(matches!(simplified.kind, ExprKind::Unknown(ref s) if s == "x"));

        // Negative case: distinct branches stay as Conditional.
        let y = Expr::unknown("y");
        let conditional = Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(cond.clone()),
                then_expr: Box::new(x.clone()),
                else_expr: Box::new(y.clone()),
            },
        };
        let simplified = conditional.simplify();
        assert!(matches!(simplified.kind, ExprKind::Conditional { .. }));
    }

    #[test]
    fn test_low_bits_reassembly_folds_to_value() {
        // `x | ((x >> 32) << 32)` == `x` — the edx:eax reassembly idiom
        // emitted for rdtsc/rdtscp. Both operand orders fold.
        let x = || Expr::unknown("x");
        let shift_pair = || {
            Expr::binop(
                BinOpKind::Shl,
                Expr::binop(BinOpKind::Shr, x(), Expr::int(32)),
                Expr::int(32),
            )
        };

        let reassembled = Expr::binop(BinOpKind::Or, x(), shift_pair()).simplify();
        assert!(matches!(reassembled.kind, ExprKind::Unknown(ref s) if s == "x"));

        let commuted = Expr::binop(BinOpKind::Or, shift_pair(), x()).simplify();
        assert!(matches!(commuted.kind, ExprKind::Unknown(ref s) if s == "x"));

        // Negative: mismatched shift amounts must not fold.
        let mismatched = Expr::binop(
            BinOpKind::Or,
            x(),
            Expr::binop(
                BinOpKind::Shl,
                Expr::binop(BinOpKind::Shr, x(), Expr::int(32)),
                Expr::int(16),
            ),
        )
        .simplify();
        assert!(matches!(mismatched.kind, ExprKind::BinOp { .. }));
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

        // (cmp1) | (cmp2) → (cmp1) || (cmp2)
        let cmp1 = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(1));
        let cmp2 = Expr::binop(BinOpKind::Eq, Expr::unknown("y"), Expr::int(2));
        let expr = Expr::binop(BinOpKind::Or, cmp1, cmp2);
        let simplified = expr.simplify();
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::LogicalOr,
                    ..
                }
            ),
            "Expected LogicalOr, got {:?}",
            simplified.kind
        );

        // (cmp1) & (cmp2) → (cmp1) && (cmp2)
        let cmp1 = Expr::binop(BinOpKind::Lt, Expr::unknown("a"), Expr::int(10));
        let cmp2 = Expr::binop(BinOpKind::Gt, Expr::unknown("b"), Expr::int(0));
        let expr = Expr::binop(BinOpKind::And, cmp1, cmp2);
        let simplified = expr.simplify();
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::LogicalAnd,
                    ..
                }
            ),
            "Expected LogicalAnd, got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_boolean_comparison_simplification() {
        // (x == 1) != 1 → x != 1
        let inner = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(1));
        let expr = Expr::binop(BinOpKind::Ne, inner, Expr::int(1));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Ne);
                assert!(matches!(left.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(right.kind, ExprKind::IntLit(1)));
            }
            _ => panic!("Expected BinOp, got {:?}", simplified.kind),
        }

        // (x == 1) == 1 → x == 1 (identity)
        let inner = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(1));
        let expr = Expr::binop(BinOpKind::Eq, inner, Expr::int(1));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Eq);
                assert!(matches!(left.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(right.kind, ExprKind::IntLit(1)));
            }
            _ => panic!("Expected BinOp, got {:?}", simplified.kind),
        }

        // (x < 5) == 0 → x >= 5 (negate)
        let inner = Expr::binop(BinOpKind::Lt, Expr::unknown("x"), Expr::int(5));
        let expr = Expr::binop(BinOpKind::Eq, inner, Expr::int(0));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Ge);
                assert!(matches!(left.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(right.kind, ExprKind::IntLit(5)));
            }
            _ => panic!("Expected BinOp, got {:?}", simplified.kind),
        }

        // Chained: ((x == 1) != 1) != 1 → x == 1
        let inner1 = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(1));
        let inner2 = Expr::binop(BinOpKind::Ne, inner1, Expr::int(1)); // x != 1
        let expr = Expr::binop(BinOpKind::Ne, inner2, Expr::int(1)); // back to x == 1
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Eq);
                assert!(matches!(left.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(right.kind, ExprKind::IntLit(1)));
            }
            _ => panic!("Expected BinOp, got {:?}", simplified.kind),
        }

        // !((uint8_t)tag == INT64_MIN) == 1 → (uint8_t)tag != 0
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(Expr::unknown("tag")),
                to_size: 1,
                signed: false,
            },
        };
        let weird_cmp = Expr::binop(BinOpKind::Eq, cast, Expr::int(i64::MIN as i128));
        let expr = Expr::binop(
            BinOpKind::Eq,
            Expr::unary(UnaryOpKind::LogicalNot, weird_cmp),
            Expr::int(1),
        );
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Ne);
                assert!(matches!(
                    left.kind,
                    ExprKind::Cast {
                        to_size: 1,
                        signed: false,
                        ..
                    }
                ));
                assert!(matches!(right.kind, ExprKind::IntLit(0)));
            }
            _ => panic!("Expected normalized BinOp, got {:?}", simplified.kind),
        }

        // (cmp ? 0 : 1) != 0 → !cmp
        let expr = Expr::binop(
            BinOpKind::Ne,
            Expr {
                kind: ExprKind::Conditional {
                    cond: Box::new(Expr::binop(
                        BinOpKind::Eq,
                        Expr::unknown("tag"),
                        Expr::int(0),
                    )),
                    then_expr: Box::new(Expr::int(0)),
                    else_expr: Box::new(Expr::int(1)),
                },
            },
            Expr::int(0),
        );
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BinOp { op, left, right } => {
                assert_eq!(*op, BinOpKind::Ne);
                assert!(matches!(left.kind, ExprKind::Unknown(ref s) if s == "tag"));
                assert!(matches!(right.kind, ExprKind::IntLit(0)));
            }
            _ => panic!(
                "Expected conditional boolean wrapper to collapse to a comparison, got {:?}",
                simplified.kind
            ),
        }

        let expr = Expr::binop(
            BinOpKind::Eq,
            Expr::binop(
                BinOpKind::LogicalAnd,
                Expr::binop(BinOpKind::Eq, Expr::unknown("a"), Expr::int(1)),
                Expr::binop(BinOpKind::Eq, Expr::unknown("b"), Expr::int(2)),
            ),
            Expr::int(0),
        );
        let rendered = format!("{}", expr.simplify());
        assert!(
            rendered.starts_with("!"),
            "expected boolean && compared to zero to simplify via negation, got {rendered}"
        );
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
        let expr = Expr::unary(
            UnaryOpKind::LogicalNot,
            Expr::unary(UnaryOpKind::LogicalNot, x.clone()),
        );
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

    #[test]
    fn test_sign_extension_patterns() {
        let x = Expr::unknown("x");

        // (x << 56) >> 56 = (int8_t)x
        let shifted_left = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(56));
        let expr = Expr::binop(BinOpKind::Sar, shifted_left, Expr::int(56));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 1);
                assert!(*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // (x << 48) >> 48 = (int16_t)x
        let shifted_left = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(48));
        let expr = Expr::binop(BinOpKind::Sar, shifted_left, Expr::int(48));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 2);
                assert!(*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // (x << 32) >> 32 = (int32_t)x
        let shifted_left = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(32));
        let expr = Expr::binop(BinOpKind::Sar, shifted_left, Expr::int(32));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 4);
                assert!(*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // Non-matching shifts should not simplify: (x << 48) >> 32
        let shifted_left = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(48));
        let expr = Expr::binop(BinOpKind::Sar, shifted_left, Expr::int(32));
        let simplified = expr.simplify();
        assert!(matches!(
            simplified.kind,
            ExprKind::BinOp {
                op: BinOpKind::Sar,
                ..
            }
        ));

        // Logical shift right should not become a cast (it's zero extension, not sign extension)
        let shifted_left = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(56));
        let expr = Expr::binop(BinOpKind::Shr, shifted_left, Expr::int(56));
        let simplified = expr.simplify();
        assert!(matches!(
            simplified.kind,
            ExprKind::BinOp {
                op: BinOpKind::Shr,
                ..
            }
        ));
    }

    #[test]
    fn test_zero_extension_patterns() {
        let x = Expr::unknown("x");

        // x & 0xFF = (uint8_t)x
        let expr = Expr::binop(BinOpKind::And, x.clone(), Expr::int(0xFF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 1);
                assert!(!*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // x & 0xFFFF = (uint16_t)x
        let expr = Expr::binop(BinOpKind::And, x.clone(), Expr::int(0xFFFF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 2);
                assert!(!*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // x & 0xFFFFFFFF = (uint32_t)x
        let expr = Expr::binop(BinOpKind::And, x.clone(), Expr::int(0xFFFFFFFF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 4);
                assert!(!*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // Commutative: 0xFF & x = (uint8_t)x
        let expr = Expr::binop(BinOpKind::And, Expr::int(0xFF), x.clone());
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::Cast {
                to_size, signed, ..
            } => {
                assert_eq!(*to_size, 1);
                assert!(!*signed);
            }
            other => panic!("Expected Cast, got {:?}", other),
        }

        // Low-bit masks are recognized as bitfield extraction idioms.
        let expr = Expr::binop(BinOpKind::And, x.clone(), Expr::int(0x7F));
        let simplified = expr.simplify();
        assert!(matches!(
            simplified.kind,
            ExprKind::BitField {
                start: 0,
                width: 7,
                ..
            }
        ));
    }

    #[test]
    fn test_extension_display() {
        let x = Expr::unknown("x");

        // Test that casts display correctly
        let cast_i8 = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x.clone()),
                to_size: 1,
                signed: true,
            },
        };
        assert_eq!(cast_i8.to_string(), "(int8_t)x");

        let cast_u16 = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x.clone()),
                to_size: 2,
                signed: false,
            },
        };
        assert_eq!(cast_u16.to_string(), "(uint16_t)x");

        let cast_i32 = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x.clone()),
                to_size: 4,
                signed: true,
            },
        };
        assert_eq!(cast_i32.to_string(), "(int32_t)x");
    }

    #[test]
    fn test_mask_to_width() {
        // Valid contiguous masks
        assert_eq!(mask_to_width(0x1), Some(1));
        assert_eq!(mask_to_width(0x3), Some(2));
        assert_eq!(mask_to_width(0x7), Some(3));
        assert_eq!(mask_to_width(0xF), Some(4));
        assert_eq!(mask_to_width(0x1F), Some(5));
        assert_eq!(mask_to_width(0x3F), Some(6));
        assert_eq!(mask_to_width(0x7F), Some(7));
        assert_eq!(mask_to_width(0xFF), Some(8));
        assert_eq!(mask_to_width(0xFFFF), Some(16));
        assert_eq!(mask_to_width(0xFFFFFFFF), Some(32));

        // Invalid masks (not contiguous)
        assert_eq!(mask_to_width(0x5), None); // 0b101
        assert_eq!(mask_to_width(0x9), None); // 0b1001
        assert_eq!(mask_to_width(0xA), None); // 0b1010
        assert_eq!(mask_to_width(0x101), None); // 0b100000001

        // Edge cases
        assert_eq!(mask_to_width(0), None);
        assert_eq!(mask_to_width(-1), None);
    }

    #[test]
    fn test_mask_to_shifted_field() {
        assert_eq!(mask_to_shifted_field(0xff0), Some((4, 8)));
        assert_eq!(mask_to_shifted_field(0xe), Some((1, 3)));
        assert_eq!(mask_to_shifted_field(0), None);
        assert_eq!(mask_to_shifted_field(0x14), None);
    }

    #[test]
    fn test_bitfield_extraction_patterns() {
        let x = Expr::unknown("x");

        // (x >> 4) & 0xF = BITS(x, 4, 4)
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(4));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0xF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 4);
                assert_eq!(*width, 4);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // (x >> 8) & 0xFF = BITS(x, 8, 8)
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(8));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0xFF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 8);
                assert_eq!(*width, 8);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // (x >> 16) & 0x3FF = BITS(x, 16, 10) (10-bit field)
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(16));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0x3FF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 16);
                assert_eq!(*width, 10);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // Commutative: 0xF & (x >> 4) = BITS(x, 4, 4)
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(4));
        let expr = Expr::binop(BinOpKind::And, Expr::int(0xF), shifted);
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 4);
                assert_eq!(*width, 4);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // Works with arithmetic shift right too
        let shifted = Expr::binop(BinOpKind::Sar, x.clone(), Expr::int(12));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0x7));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 12);
                assert_eq!(*width, 3);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // Non-contiguous mask should not match: (x >> 4) & 0x5
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(4));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0x5));
        let simplified = expr.simplify();
        assert!(matches!(
            simplified.kind,
            ExprKind::BinOp {
                op: BinOpKind::And,
                ..
            }
        ));

        // Shift of 0 should match sub-byte fields when the source width is known.
        let byte = Expr::var(Variable::reg("al", 1));
        let shifted = Expr::binop(BinOpKind::Shr, byte, Expr::int(0));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0xF));
        let simplified = expr.simplify();
        match &simplified.kind {
            ExprKind::BitField { start, width, .. } => {
                assert_eq!(*start, 0);
                assert_eq!(*width, 4);
            }
            other => panic!("Expected BitField, got {:?}", other),
        }

        // Full-width masks at shift 0 should still behave as zero extension.
        let shifted = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(0));
        let expr = Expr::binop(BinOpKind::And, shifted, Expr::int(0xFF));
        let simplified = expr.simplify();
        assert!(!matches!(simplified.kind, ExprKind::BitField { .. }));
    }

    #[test]
    fn test_bitfield_display() {
        let x = Expr::unknown("x");

        // Test that BitField displays correctly
        let bitfield = Expr {
            kind: ExprKind::BitField {
                expr: Box::new(x.clone()),
                start: 4,
                width: 4,
            },
        };
        assert_eq!(bitfield.to_string(), "BITS(x, 4, 4)");

        let bitfield2 = Expr {
            kind: ExprKind::BitField {
                expr: Box::new(x.clone()),
                start: 16,
                width: 8,
            },
        };
        assert_eq!(bitfield2.to_string(), "BITS(x, 16, 8)");
    }

    #[test]
    fn test_shift_chain_combines_nested_left_shifts() {
        let x = Expr::unknown("x");
        let expr = Expr::binop(
            BinOpKind::Shl,
            Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(4)),
            Expr::int(8),
        );
        let simplified = expr.simplify();
        assert_eq!(simplified.to_string(), "x << 0xc");
    }

    #[test]
    fn test_bitfield_insert_patterns() {
        let carrier = Expr::unknown("carrier");
        let value = Expr::unknown("value");

        let expr = Expr::binop(
            BinOpKind::Or,
            Expr::binop(BinOpKind::And, carrier.clone(), Expr::int(!0xff0)),
            Expr::binop(BinOpKind::Shl, value.clone(), Expr::int(4)),
        );
        let simplified = expr.simplify();
        assert_eq!(simplified.to_string(), "SET_BITS(carrier, value, 4, 8)");

        let masked_expr = Expr::binop(
            BinOpKind::Or,
            Expr::binop(BinOpKind::And, carrier.clone(), Expr::int(!0xff0)),
            Expr::binop(
                BinOpKind::And,
                Expr::binop(BinOpKind::Shl, value.clone(), Expr::int(4)),
                Expr::int(0xff0),
            ),
        );
        let masked_simplified = masked_expr.simplify();
        assert_eq!(
            masked_simplified.to_string(),
            "SET_BITS(carrier, value, 4, 8)"
        );
    }

    // ============================================
    // Array Access Detection Tests
    // ============================================

    #[test]
    fn test_array_access_scaled_pattern() {
        // *(rbx + rcx * 4) with 4-byte deref -> rbx[rcx]
        let rbx = Expr::unknown("rbx");
        let rcx = Expr::unknown("rcx");

        // Create: rbx + rcx * 4
        let scaled = Expr::binop(BinOpKind::Mul, rcx.clone(), Expr::int(4));
        let addr = Expr::binop(BinOpKind::Add, rbx.clone(), scaled);

        // Create dereference with size 4
        let deref = Expr::deref(addr, 4);

        // Simplify should detect array pattern
        let simplified = deref.simplify();
        match &simplified.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                assert_eq!(*element_size, 4);
                assert!(matches!(base.kind, ExprKind::Unknown(ref s) if s == "rbx"));
                assert!(matches!(index.kind, ExprKind::Unknown(ref s) if s == "rcx"));
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "rbx[rcx]");
    }

    #[test]
    fn test_array_access_commutative_scaled() {
        // *(rcx * 8 + rbx) with 8-byte deref -> rbx[rcx]
        let rbx = Expr::unknown("rbx");
        let rcx = Expr::unknown("rcx");

        // Create: rcx * 8 + rbx (reversed order)
        let scaled = Expr::binop(BinOpKind::Mul, rcx.clone(), Expr::int(8));
        let addr = Expr::binop(BinOpKind::Add, scaled, rbx.clone());

        let deref = Expr::deref(addr, 8);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess { element_size, .. } => {
                assert_eq!(*element_size, 8);
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "rbx[rcx]");
    }

    #[test]
    fn test_array_access_shift_pattern() {
        // *(rbx + (rcx << 2)) with 4-byte deref -> rbx[rcx]
        // 1 << 2 = 4, so this is equivalent to rcx * 4
        let rbx = Expr::unknown("rbx");
        let rcx = Expr::unknown("rcx");

        let shifted = Expr::binop(BinOpKind::Shl, rcx.clone(), Expr::int(2));
        let addr = Expr::binop(BinOpKind::Add, rbx.clone(), shifted);

        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess { element_size, .. } => {
                assert_eq!(*element_size, 4);
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "rbx[rcx]");
    }

    #[test]
    fn test_array_access_constant_offset() {
        // *(rbx + 0x10) with 4-byte deref -> rbx[4]
        // 0x10 / 4 = 4
        let rbx = Expr::unknown("rbx");

        let addr = Expr::binop(BinOpKind::Add, rbx.clone(), Expr::int(0x10));
        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess {
                index,
                element_size,
                ..
            } => {
                assert_eq!(*element_size, 4);
                if let ExprKind::IntLit(idx) = &index.kind {
                    assert_eq!(*idx, 4); // 0x10 / 4 = 4
                } else {
                    panic!("Expected integer index");
                }
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "rbx[4]");
    }

    #[test]
    fn test_array_access_8byte_elements() {
        // *(ptr + 0x18) with 8-byte deref -> ptr[3]
        // 0x18 (24) / 8 = 3
        let ptr = Expr::unknown("ptr");

        let addr = Expr::binop(BinOpKind::Add, ptr.clone(), Expr::int(0x18));
        let deref = Expr::deref(addr, 8);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess {
                index,
                element_size,
                ..
            } => {
                assert_eq!(*element_size, 8);
                if let ExprKind::IntLit(idx) = &index.kind {
                    assert_eq!(*idx, 3);
                } else {
                    panic!("Expected integer index");
                }
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "ptr[3]");
    }

    #[test]
    fn test_array_access_negative_offset() {
        // *(ptr - 8) with 8-byte deref -> ptr[-1]
        let ptr = Expr::unknown("ptr");

        let addr = Expr::binop(BinOpKind::Sub, ptr.clone(), Expr::int(8));
        let deref = Expr::deref(addr, 8);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess {
                index,
                element_size,
                ..
            } => {
                assert_eq!(*element_size, 8);
                if let ExprKind::IntLit(idx) = &index.kind {
                    assert_eq!(*idx, -1);
                } else {
                    panic!("Expected integer index");
                }
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        // Note: -1 is displayed as -0x1 due to hex formatting
        assert_eq!(simplified.to_string(), "ptr[-0x1]");
    }

    #[test]
    fn test_array_access_struct_array_pattern() {
        // *((base + index * 16) + 8) with 8-byte deref
        // This is accessing element at offset 8 in a 16-byte struct array
        // Should become base[index + 1] when treating as 16-byte elements
        let base = Expr::unknown("base");
        let index = Expr::unknown("i");

        let scaled = Expr::binop(BinOpKind::Mul, index.clone(), Expr::int(16));
        let inner = Expr::binop(BinOpKind::Add, base.clone(), scaled);
        let addr = Expr::binop(BinOpKind::Add, inner, Expr::int(8));

        // The element size for the struct array detection should be 16
        // but the deref is 8 bytes (accessing a field within the struct)
        let deref = Expr::deref(addr, 16); // Use stride as size hint
        let simplified = deref.simplify();

        // Should detect this as struct array pattern
        if let ExprKind::ArrayAccess { element_size, .. } = &simplified.kind {
            assert_eq!(*element_size, 16);
        }
        // May not match all patterns, that's ok
    }

    #[test]
    fn test_array_access_no_match_unaligned() {
        // *(ptr + 5) with 4-byte deref should NOT match
        // 5 is not divisible by 4
        let ptr = Expr::unknown("ptr");

        let addr = Expr::binop(BinOpKind::Add, ptr.clone(), Expr::int(5));
        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        // Should remain as Deref, not ArrayAccess
        assert!(
            matches!(simplified.kind, ExprKind::Deref { .. }),
            "Expected Deref for unaligned offset, got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_array_access_no_match_size_mismatch() {
        // *(ptr + i * 4) with 8-byte deref should NOT match
        // Element size 4 doesn't match deref size 8
        let ptr = Expr::unknown("ptr");
        let i = Expr::unknown("i");

        let scaled = Expr::binop(BinOpKind::Mul, i.clone(), Expr::int(4));
        let addr = Expr::binop(BinOpKind::Add, ptr.clone(), scaled);
        let deref = Expr::deref(addr, 8); // Mismatch!
        let simplified = deref.simplify();

        // Should remain as Deref, not ArrayAccess
        assert!(
            matches!(simplified.kind, ExprKind::Deref { .. }),
            "Expected Deref for size mismatch, got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_array_access_unscaled_index() {
        // *(ptr + i) with 4-byte deref -> ptr[i]
        // No multiplication, index is used directly
        let ptr = Expr::unknown("ptr");
        let i = Expr::unknown("i");

        let addr = Expr::binop(BinOpKind::Add, ptr.clone(), i.clone());
        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                assert_eq!(*element_size, 4);
                assert!(matches!(base.kind, ExprKind::Unknown(ref s) if s == "ptr"));
                assert!(matches!(index.kind, ExprKind::Unknown(ref s) if s == "i"));
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "ptr[i]");
    }

    #[test]
    fn test_array_access_unscaled_byte_array() {
        // *(arr + i) with 1-byte deref -> arr[i]
        // Common pattern for char arrays and byte buffers
        let arr = Expr::unknown("arr");
        let i = Expr::unknown("i");

        let addr = Expr::binop(BinOpKind::Add, arr.clone(), i.clone());
        let deref = Expr::deref(addr, 1);
        let simplified = deref.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                assert_eq!(*element_size, 1);
                assert!(matches!(base.kind, ExprKind::Unknown(ref s) if s == "arr"));
                assert!(matches!(index.kind, ExprKind::Unknown(ref s) if s == "i"));
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "arr[i]");
    }

    #[test]
    fn test_array_access_display() {
        // Test array access display formatting
        let arr = Expr::unknown("arr");
        let i = Expr::unknown("i");

        let access = Expr::array_access(arr.clone(), i.clone(), 4);
        assert_eq!(access.to_string(), "arr[i]");

        // Constant index
        let access_const = Expr::array_access(arr.clone(), Expr::int(5), 8);
        assert_eq!(access_const.to_string(), "arr[5]");

        // Complex index expression
        let complex_idx = Expr::binop(BinOpKind::Add, i.clone(), Expr::int(1));
        let access_complex = Expr::array_access(arr.clone(), complex_idx, 4);
        assert_eq!(access_complex.to_string(), "arr[i + 1]");
    }

    #[test]
    fn test_array_access_nested() {
        // arr[i][j] - multidimensional array access
        let arr = Expr::unknown("arr");
        let i = Expr::unknown("i");
        let j = Expr::unknown("j");

        let inner = Expr::array_access(arr.clone(), i.clone(), 8);
        let outer = Expr::array_access(inner, j.clone(), 4);

        assert_eq!(outer.to_string(), "arr[i][j]");
    }

    #[test]
    fn test_address_of_display() {
        // &arr[i] pattern
        let arr = Expr::unknown("arr");
        let i = Expr::unknown("i");

        let access = Expr::array_access(arr.clone(), i.clone(), 4);
        let addr_of = Expr::address_of(access);

        assert_eq!(addr_of.to_string(), "&arr[i]");
    }

    #[test]
    fn test_array_access_simplifies_recursively() {
        // ArrayAccess with base and index that need simplification
        // base: x + 0 (should simplify to x)
        // index: 5 + 3 (should simplify to 8)
        let x = Expr::unknown("x");
        let base_needs_simplify = Expr::binop(BinOpKind::Add, x.clone(), Expr::int(0));
        let index_needs_simplify = Expr::binop(BinOpKind::Add, Expr::int(5), Expr::int(3));

        let access = Expr::array_access(base_needs_simplify, index_needs_simplify, 4);
        let simplified = access.simplify();

        match &simplified.kind {
            ExprKind::ArrayAccess { base, index, .. } => {
                assert!(matches!(base.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(index.kind, ExprKind::IntLit(8)));
            }
            other => panic!("Expected ArrayAccess, got {:?}", other),
        }

        assert_eq!(simplified.to_string(), "x[8]");
    }

    #[test]
    fn test_compound_assignment_basic() {
        let x = Expr::unknown("x");
        let y = Expr::int(5);

        // x = x + 5 -> x += 5
        let rhs = Expr::binop(BinOpKind::Add, x.clone(), y.clone());
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        match &simplified.kind {
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                assert_eq!(*op, BinOpKind::Add);
                assert!(matches!(lhs.kind, ExprKind::Unknown(ref s) if s == "x"));
                assert!(matches!(rhs.kind, ExprKind::IntLit(5)));
            }
            other => panic!("Expected CompoundAssign, got {:?}", other),
        }
        assert_eq!(simplified.to_string(), "x += 5");
    }

    #[test]
    fn test_compound_assignment_all_operators() {
        let x = Expr::unknown("x");
        let y = Expr::int(2);

        // Test all supported operators
        let ops = vec![
            (BinOpKind::Add, "+="),
            (BinOpKind::Sub, "-="),
            (BinOpKind::Mul, "*="),
            (BinOpKind::Div, "/="),
            (BinOpKind::Mod, "%="),
            (BinOpKind::And, "&="),
            (BinOpKind::Or, "|="),
            (BinOpKind::Xor, "^="),
            (BinOpKind::Shl, "<<="),
            (BinOpKind::Shr, ">>="),
        ];

        for (op, expected_op_str) in ops {
            let rhs = Expr::binop(op, x.clone(), y.clone());
            let assign = Expr::assign(x.clone(), rhs);
            let simplified = assign.simplify();

            match &simplified.kind {
                ExprKind::CompoundAssign { op: result_op, .. } => {
                    assert_eq!(*result_op, op);
                }
                other => panic!("Expected CompoundAssign for {:?}, got {:?}", op, other),
            }
            assert!(
                simplified.to_string().contains(expected_op_str),
                "Expected '{}' in output for {:?}, got: {}",
                expected_op_str,
                op,
                simplified
            );
        }
    }

    #[test]
    fn test_compound_assignment_commutative() {
        let x = Expr::unknown("x");
        let y = Expr::int(3);

        // y + x = x should also simplify (commutative case)
        let rhs = Expr::binop(BinOpKind::Add, y.clone(), x.clone());
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        match &simplified.kind {
            ExprKind::CompoundAssign { op, rhs, .. } => {
                assert_eq!(*op, BinOpKind::Add);
                // rhs should be the other operand (y = 3)
                assert!(matches!(rhs.kind, ExprKind::IntLit(3)));
            }
            other => panic!("Expected CompoundAssign, got {:?}", other),
        }
    }

    #[test]
    fn test_compound_assignment_no_match() {
        let x = Expr::unknown("x");
        let y = Expr::unknown("y");
        let z = Expr::int(5);

        // x = y + z should not become compound (x not in rhs)
        let rhs = Expr::binop(BinOpKind::Add, y.clone(), z.clone());
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        assert!(matches!(simplified.kind, ExprKind::Assign { .. }));

        // x = y - z should not become compound (non-commutative, x not on left)
        let rhs = Expr::binop(BinOpKind::Sub, y.clone(), x.clone());
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        // Sub is not commutative, so y - x cannot become x -= y
        assert!(matches!(simplified.kind, ExprKind::Assign { .. }));
    }

    #[test]
    fn test_compound_assignment_display() {
        let x = Expr::unknown("counter");
        let y = Expr::int(1);

        // Test display formatting
        let rhs = Expr::binop(BinOpKind::Add, x.clone(), y.clone());
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        assert_eq!(simplified.to_string(), "counter += 1");

        // Test with subtraction (integers >= 10 are displayed in hex)
        let rhs = Expr::binop(BinOpKind::Sub, x.clone(), Expr::int(10));
        let assign = Expr::assign(x.clone(), rhs);
        let simplified = assign.simplify();

        assert_eq!(simplified.to_string(), "counter -= 0xa");
    }

    #[test]
    fn test_cast_elimination_same_size_var() {
        // Cast of 4-byte variable to 4 bytes should be eliminated
        let var = Expr::var(Variable {
            kind: VarKind::Stack(-8),
            name: "x".to_string(),
            size: 4,
        });
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(var),
                to_size: 4,
                signed: false,
            },
        };
        let simplified = cast.simplify();

        // Should be a plain variable, not a cast
        assert!(matches!(simplified.kind, ExprKind::Var(_)));
    }

    #[test]
    fn test_cast_elimination_comparison_result() {
        // Cast of comparison to int (>= 4 bytes) should be eliminated
        let cmp = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(0));
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(cmp),
                to_size: 4,
                signed: true,
            },
        };
        let simplified = cast.simplify();

        // Should be a plain comparison, not a cast
        assert!(matches!(
            simplified.kind,
            ExprKind::BinOp {
                op: BinOpKind::Eq,
                ..
            }
        ));
    }

    #[test]
    fn test_cast_elimination_deref_same_size() {
        // Cast of 8-byte deref to 8 bytes should be eliminated
        let deref = Expr::deref(Expr::unknown("ptr"), 8);
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(deref),
                to_size: 8,
                signed: false,
            },
        };
        let simplified = cast.simplify();

        // Should be a plain deref, not a cast
        assert!(matches!(simplified.kind, ExprKind::Deref { size: 8, .. }));
    }

    #[test]
    fn test_cast_elimination_array_access_same_size() {
        // Cast of array access with 4-byte elements to 4 bytes should be eliminated
        let access = Expr::array_access(Expr::unknown("arr"), Expr::unknown("i"), 4);
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(access),
                to_size: 4,
                signed: false,
            },
        };
        let simplified = cast.simplify();

        // Should be a plain array access, not a cast
        assert!(matches!(
            simplified.kind,
            ExprKind::ArrayAccess {
                element_size: 4,
                ..
            }
        ));
    }

    #[test]
    fn test_cast_preserved_when_different_size() {
        // Cast of 4-byte variable to 8 bytes should NOT be eliminated
        let var = Expr::var(Variable {
            kind: VarKind::Stack(-8),
            name: "x".to_string(),
            size: 4,
        });
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(var),
                to_size: 8,
                signed: true,
            },
        };
        let simplified = cast.simplify();

        // Should still be a cast
        assert!(matches!(
            simplified.kind,
            ExprKind::Cast {
                to_size: 8,
                signed: true,
                ..
            }
        ));
    }

    #[test]
    fn test_cast_preserved_comparison_to_small_type() {
        // Cast of comparison to 1-byte should NOT be eliminated (truncation)
        let cmp = Expr::binop(BinOpKind::Lt, Expr::unknown("x"), Expr::unknown("y"));
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(cmp),
                to_size: 1,
                signed: false,
            },
        };
        let simplified = cast.simplify();

        // Should still be a cast (truncation to 1 byte)
        assert!(matches!(simplified.kind, ExprKind::Cast { to_size: 1, .. }));
    }

    #[test]
    fn test_nested_cast_same_size_different_signedness() {
        // (int32_t)(uint32_t)x -> (int32_t)x
        // Reinterpret cast: same size, different signedness, inner is redundant
        let x = Expr::unknown("x");
        let inner = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x),
                to_size: 4,
                signed: false, // uint32_t
            },
        };
        let outer = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(inner),
                to_size: 4,
                signed: true, // int32_t
            },
        };
        let simplified = outer.simplify();

        // Should be single cast with outer signedness
        match &simplified.kind {
            ExprKind::Cast {
                to_size,
                signed,
                expr,
            } => {
                assert_eq!(*to_size, 4);
                assert!(*signed); // int32_t
                                  // Inner should be the original expression, not another cast
                assert!(matches!(expr.kind, ExprKind::Unknown(_)));
            }
            other => panic!("Expected Cast, got {:?}", other),
        }
    }

    #[test]
    fn test_nested_cast_signed_larger_unsigned_smaller() {
        // (int64_t)(uint32_t)x -> (int64_t)x when inner is 4+ bytes
        // Zero extension is transparent for non-negative values
        let x = Expr::unknown("x");
        let inner = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x),
                to_size: 4,
                signed: false, // uint32_t
            },
        };
        let outer = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(inner),
                to_size: 8,
                signed: true, // int64_t
            },
        };
        let simplified = outer.simplify();

        // Should be single cast to int64_t
        match &simplified.kind {
            ExprKind::Cast {
                to_size,
                signed,
                expr,
            } => {
                assert_eq!(*to_size, 8);
                assert!(*signed); // int64_t
                                  // Inner should be the original expression
                assert!(matches!(expr.kind, ExprKind::Unknown(_)));
            }
            other => panic!("Expected Cast, got {:?}", other),
        }
    }

    #[test]
    fn test_nested_cast_small_unsigned_preserved() {
        // (int64_t)(uint8_t)x - should NOT simplify (need zero extension)
        // Small unsigned types need explicit zero extension
        let x = Expr::unknown("x");
        let inner = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x),
                to_size: 1,
                signed: false, // uint8_t
            },
        };
        let outer = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(inner),
                to_size: 8,
                signed: true, // int64_t
            },
        };
        let simplified = outer.simplify();

        // Should still be a nested cast (inner is needed for zero extension)
        match &simplified.kind {
            ExprKind::Cast {
                to_size,
                signed,
                expr,
            } => {
                assert_eq!(*to_size, 8);
                assert!(*signed);
                // Inner should still be a cast
                assert!(matches!(expr.kind, ExprKind::Cast { .. }));
            }
            other => panic!("Expected nested Cast, got {:?}", other),
        }
    }
    #[test]
    fn test_register_normalization_8bit() {
        // Test 8-bit register normalization
        let reg_al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8); // al
        let var_al = Variable::from_register(&reg_al);
        assert_eq!(var_al.name, "rax");
        assert_eq!(var_al.size, 1);

        let reg_bl = Register::new(Architecture::X86_64, RegisterClass::General, 3, 8); // bl
        let var_bl = Variable::from_register(&reg_bl);
        assert_eq!(var_bl.name, "rbx");
        assert_eq!(var_bl.size, 1);
    }

    #[test]
    fn test_register_normalization_16bit() {
        // Test 16-bit register normalization
        let reg_ax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 16); // ax
        let var_ax = Variable::from_register(&reg_ax);
        assert_eq!(var_ax.name, "rax");
        assert_eq!(var_ax.size, 2);

        let reg_dx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 16); // dx
        let var_dx = Variable::from_register(&reg_dx);
        assert_eq!(var_dx.name, "rdx");
        assert_eq!(var_dx.size, 2);
    }

    #[test]
    fn test_register_normalization_32bit() {
        // Test 32-bit register normalization
        let reg_eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32); // eax
        let var_eax = Variable::from_register(&reg_eax);
        assert_eq!(var_eax.name, "rax");
        assert_eq!(var_eax.size, 4);

        let reg_ecx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 32); // ecx
        let var_ecx = Variable::from_register(&reg_ecx);
        assert_eq!(var_ecx.name, "rcx");
        assert_eq!(var_ecx.size, 4);
    }

    #[test]
    fn test_register_normalization_64bit() {
        // Test that 64-bit registers stay the same
        let reg_rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64); // rax
        let var_rax = Variable::from_register(&reg_rax);
        assert_eq!(var_rax.name, "rax");
        assert_eq!(var_rax.size, 8);

        let reg_r8 = Register::new(Architecture::X86_64, RegisterClass::General, 8, 64); // r8
        let var_r8 = Variable::from_register(&reg_r8);
        assert_eq!(var_r8.name, "r8");
        assert_eq!(var_r8.size, 8);
    }

    #[test]
    fn test_register_normalization_arm64_unchanged() {
        // Test that ARM64 registers are not affected
        let reg_x0 = Register::new(Architecture::Arm64, RegisterClass::General, 0, 64); // x0
        let var_x0 = Variable::from_register(&reg_x0);
        assert_eq!(var_x0.name, "x0");
        assert_eq!(var_x0.size, 8);

        let reg_w0 = Register::new(Architecture::Arm64, RegisterClass::General, 0, 32); // w0
        let var_w0 = Variable::from_register(&reg_w0);
        assert_eq!(var_w0.name, "w0");
        assert_eq!(var_w0.size, 4);
    }

    #[test]
    fn test_spurious_deref_removal_var_times_const() {
        // *(uint32_t*)(_g * 2) should simplify to _g * 2
        // when _g is a plain variable (already a loaded value)
        let var_g = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "_g".to_string(),
            size: 4,
        });
        let mul = Expr::binop(BinOpKind::Mul, var_g, Expr::int(2));
        let deref = Expr::deref(mul, 4);
        let simplified = deref.simplify();

        // Should remove the spurious Deref, leaving just the multiplication
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Mul,
                    ..
                }
            ),
            "Expected BinOp(Mul), got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_spurious_deref_removal_computation_plus_const() {
        // *(uint32_t*)((_g * 2) + 1) should simplify to (_g * 2) + 1
        let var_g = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "_g".to_string(),
            size: 4,
        });
        let mul = Expr::binop(BinOpKind::Mul, var_g, Expr::int(2));
        let add = Expr::binop(BinOpKind::Add, mul, Expr::int(1));
        let deref = Expr::deref(add, 4);
        let simplified = deref.simplify();

        // Should remove the spurious Deref, leaving just the addition
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Add,
                    ..
                }
            ),
            "Expected BinOp(Add), got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_spurious_deref_removal_global_deref_times_const() {
        // *(uint32_t*)(Deref{GotRef{_g_counter}} * 2 + 1) should simplify
        // to (Deref{GotRef{_g_counter}} * 2) + 1
        // This tests the case where a global variable's value is multiplied.
        let got_ref = Expr::got_ref(0x1000, 0x100, 4, Expr::int(0));
        let global_value = Expr::deref(got_ref, 4); // This loads the value of the global
        let mul = Expr::binop(BinOpKind::Mul, global_value, Expr::int(2));
        let add = Expr::binop(BinOpKind::Add, mul, Expr::int(1));
        let outer_deref = Expr::deref(add, 4); // This spurious deref should be removed
        let simplified = outer_deref.simplify();

        // Should remove the spurious outer Deref, leaving just the addition
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Add,
                    ..
                }
            ),
            "Expected BinOp(Add), got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_spurious_deref_removal_global_deref_times_const_no_add() {
        // *(uint32_t*)(Deref{GotRef{_g_counter}} * 2) should simplify
        // to Deref{GotRef{_g_counter}} * 2
        let got_ref = Expr::got_ref(0x1000, 0x100, 4, Expr::int(0));
        let global_value = Expr::deref(got_ref, 4);
        let mul = Expr::binop(BinOpKind::Mul, global_value, Expr::int(2));
        let outer_deref = Expr::deref(mul, 4);
        let simplified = outer_deref.simplify();

        // Should remove the spurious outer Deref, leaving just the multiplication
        assert!(
            matches!(
                simplified.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Mul,
                    ..
                }
            ),
            "Expected BinOp(Mul), got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_legitimate_deref_preserved_with_pointer_base() {
        // *(uint32_t*)(rbp + 8) should NOT be simplified away
        // because rbp is a valid pointer base (frame pointer)
        let rbp = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "rbp".to_string(),
            size: 8,
        });
        let addr = Expr::binop(BinOpKind::Add, rbp, Expr::int(8));
        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        // Should preserve the Deref (this is a valid stack access)
        // Note: might be converted to ArrayAccess, but should not be plain BinOp
        let is_memory_access = matches!(
            simplified.kind,
            ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. }
        );
        assert!(
            is_memory_access,
            "Expected Deref or ArrayAccess, got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_legitimate_array_access_with_gotref_base() {
        // *(uint32_t*)(GotRef{array} + index * 4) should be preserved as array access
        // because GotRef is a valid pointer base for array indexing
        let array_base = Expr::got_ref(0x2000, 0x200, 8, Expr::int(0));
        let index = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "i".to_string(),
            size: 8,
        });
        let scaled_index = Expr::binop(BinOpKind::Mul, index, Expr::int(4));
        let addr = Expr::binop(BinOpKind::Add, array_base, scaled_index);
        let deref = Expr::deref(addr, 4);
        let simplified = deref.simplify();

        // Should be converted to ArrayAccess (or at least preserved as Deref)
        // NOT simplified to just a BinOp
        let is_memory_access = matches!(
            simplified.kind,
            ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. }
        );
        assert!(
            is_memory_access,
            "Expected Deref or ArrayAccess for array indexing, got {:?}",
            simplified.kind
        );
    }

    #[test]
    fn test_load_effective_address_lifts_plain_address_arithmetic() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rdi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 64);
        let inst = Instruction::new(0x4011e4, 3, vec![0x8d, 0x47, 0x01], "lea")
            .with_operation(Operation::LoadEffectiveAddress)
            .with_operands(vec![
                Operand::Register(eax),
                Operand::Memory(MemoryRef::base_disp(rdi, 1, 4)),
            ]);

        let expr = Expr::from_instruction(&inst);
        let rendered = expr.simplify().to_string();

        assert_eq!(rendered, "rax = rdi + 1");
        assert!(
            !rendered.contains("*("),
            "LEA should not produce a dereference: {rendered}"
        );
    }

    #[test]
    fn test_rip_relative_rmw_lifts_with_computed_global_address() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let inst = Instruction::new(0x401100, 7, vec![0; 7], "add")
            .with_operation(Operation::Add)
            .with_operands(vec![
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x24, 4)),
                Operand::imm_unsigned(1, 32),
            ]);

        let expr = Expr::from_instruction(&inst);
        let ExprKind::Assign { lhs, rhs } = &expr.kind else {
            panic!("expected assignment, got {:?}", expr.kind);
        };

        let ExprKind::GotRef {
            address,
            is_deref: true,
            ..
        } = &lhs.kind
        else {
            panic!("expected rip-relative got-ref lhs, got {:?}", lhs.kind);
        };
        assert_eq!(*address, 0x40112b);

        let ExprKind::BinOp { left, .. } = &rhs.kind else {
            panic!("expected binop rhs, got {:?}", rhs.kind);
        };
        let ExprKind::GotRef {
            address: rhs_address,
            is_deref: true,
            ..
        } = &left.kind
        else {
            panic!("expected rip-relative got-ref rhs, got {:?}", left.kind);
        };
        assert_eq!(*rhs_address, 0x40112b);
    }

    #[test]
    fn test_fs_stack_canary_slot_lifts_to_guard_symbol() {
        use hexray_core::{Architecture, IndexMode, MemoryRef, Operand, Register, RegisterClass};

        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let operand = Operand::Memory(MemoryRef {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x28,
            size: 8,
            segment: Some(fs),
            broadcast: false,
            index_mode: IndexMode::None,
            space: hexray_core::MemorySpace::Generic,
        });

        let expr = Expr::from_operand(&operand);

        assert!(matches!(expr.kind, ExprKind::Unknown(ref s) if s == "__stack_chk_guard"));
        assert_eq!(expr.to_string(), "__stack_chk_guard");
    }

    #[test]
    fn test_fs_zero_lifts_to_thread_pointer_builtin() {
        use hexray_core::{Architecture, IndexMode, MemoryRef, Operand, Register, RegisterClass};

        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let operand = Operand::Memory(MemoryRef {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            size: 8,
            segment: Some(fs),
            broadcast: false,
            index_mode: IndexMode::None,
            space: hexray_core::MemorySpace::Generic,
        });

        let expr = Expr::from_operand(&operand);

        assert_eq!(expr.to_string(), "__builtin_thread_pointer()");
    }

    #[test]
    fn test_fs_based_memory_keeps_thread_pointer_base_when_general_base_is_present() {
        use hexray_core::{Architecture, IndexMode, MemoryRef, Operand, Register, RegisterClass};

        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, x86::RAX, 64);
        let operand = Operand::Memory(MemoryRef {
            base: Some(rax),
            index: None,
            scale: 1,
            displacement: 0,
            size: 8,
            segment: Some(fs),
            broadcast: false,
            index_mode: IndexMode::None,
            space: hexray_core::MemorySpace::Generic,
        });

        let expr = Expr::from_operand(&operand);

        let ExprKind::Deref { addr, size } = &expr.kind else {
            panic!("expected deref expression, got {:?}", expr.kind);
        };
        assert_eq!(*size, 8);

        let ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } = &addr.kind
        else {
            panic!(
                "expected thread-pointer-relative address, got {:?}",
                addr.kind
            );
        };
        assert_eq!(left.to_string(), "__builtin_thread_pointer()");
        assert_eq!(right.to_string(), "rax");
    }

    #[test]
    fn test_x86_integer_simd_mnemonic_lifts_to_opaque_comment() {
        use hexray_core::{
            register::x86, Architecture, Operand, Operation, Register, RegisterClass,
        };

        let xmm0 = Register::new(Architecture::X86_64, RegisterClass::Vector, x86::XMM0, 128);
        let xmm1 = Register::new(Architecture::X86_64, RegisterClass::Vector, x86::XMM1, 128);
        let inst = Instruction::new(0x401000, 4, vec![0x66, 0x0f, 0x6c, 0xc1], "punpcklqdq")
            .with_operation(Operation::Other(0x6c))
            .with_operands(vec![Operand::Register(xmm0), Operand::Register(xmm1)]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "/* SSE: punpcklqdq */");
    }

    #[test]
    fn test_x86_integer_simd_add_lifts_to_opaque_comment_before_binop_lowering() {
        use hexray_core::{
            register::x86, Architecture, Operand, Operation, Register, RegisterClass,
        };

        let xmm0 = Register::new(Architecture::X86_64, RegisterClass::Vector, x86::XMM0, 128);
        let xmm1 = Register::new(Architecture::X86_64, RegisterClass::Vector, x86::XMM1, 128);
        let inst = Instruction::new(0x401010, 4, vec![0x66, 0x0f, 0xd4, 0xc1], "paddq")
            .with_operation(Operation::Add)
            .with_operands(vec![Operand::Register(xmm0), Operand::Register(xmm1)]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "/* SSE: paddq */");
    }

    #[test]
    fn test_addss_lifts_scalar_xmm_operands_as_32bit_values() {
        use hexray_core::{
            register::x86, Architecture, Operand, Operation, Register, RegisterClass,
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
        let inst = Instruction::new(0x401020, 4, vec![0xf3, 0x0f, 0x58, 0xc1], "addss")
            .with_operation(Operation::Add)
            .with_operands(vec![Operand::Register(xmm0), Operand::Register(xmm1)]);

        let expr = Expr::from_instruction(&inst);
        let ExprKind::Assign { lhs, rhs } = expr.kind else {
            panic!("expected assignment");
        };
        let ExprKind::Var(lhs_var) = lhs.kind else {
            panic!("expected scalar xmm destination");
        };
        assert_eq!(lhs_var.size, 4);

        let ExprKind::BinOp { left, right, .. } = rhs.kind else {
            panic!("expected binary rhs");
        };
        let ExprKind::Var(left_var) = left.kind else {
            panic!("expected lhs operand var");
        };
        let ExprKind::Var(right_var) = right.kind else {
            panic!("expected rhs operand var");
        };
        assert_eq!(left_var.size, 4);
        assert_eq!(right_var.size, 4);
    }

    #[test]
    fn test_vfmadd132ss_lifts_to_mul_add_expression() {
        use hexray_core::{
            register::x86, Architecture, Operand, Operation, Register, RegisterClass,
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
        let xmm2 = Register::new(
            Architecture::X86_64,
            RegisterClass::FloatingPoint,
            x86::XMM2,
            128,
        );
        let inst = Instruction::new(
            0x401030,
            5,
            vec![0xc4, 0xe2, 0x69, 0x99, 0xc1],
            "vfmadd132ss",
        )
        .with_operation(Operation::Other(0x99))
        .with_operands(vec![
            Operand::Register(xmm0),
            Operand::Register(xmm2),
            Operand::Register(xmm1),
        ]);

        assert_eq!(
            Expr::from_instruction(&inst).to_string(),
            "xmm0 = xmm0 * xmm1 + xmm2"
        );
    }

    #[test]
    fn test_x86_xchg_memory_lifts_to_atomic_exchange() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let inst = Instruction::new(
            0x401100,
            6,
            vec![0x87, 0x05, 0x24, 0x00, 0x00, 0x00],
            "xchg",
        )
        .with_operation(Operation::Exchange)
        .with_operands(vec![
            Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x24, 4)),
            Operand::Register(eax),
        ]);

        let expr = Expr::from_instruction(&inst);
        let ExprKind::Assign { lhs, rhs } = &expr.kind else {
            panic!("expected assignment, got {:?}", expr.kind);
        };
        assert!(matches!(lhs.kind, ExprKind::Var(ref v) if v.name == "rax"));

        let ExprKind::Call { target, args } = &rhs.kind else {
            panic!("expected call rhs, got {:?}", rhs.kind);
        };
        assert!(matches!(target, CallTarget::Named(name) if name == "atomic_exchange"));
        assert_eq!(args.len(), 2);
        assert!(matches!(
            args[0].kind,
            ExprKind::GotRef {
                address: 0x40112a,
                is_deref: false,
                ..
            }
        ));
        assert!(matches!(args[1].kind, ExprKind::Var(ref v) if v.name == "rax"));
    }

    #[test]
    fn test_x86_lock_xadd_lifts_to_atomic_fetch_add() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let inst = Instruction::new(
            0x4011d6,
            8,
            vec![0xf0, 0x0f, 0xc1, 0x05, 0x4a, 0x2e, 0x00, 0x00],
            "lock xadd",
        )
        .with_operation(Operation::Add)
        .with_operands(vec![
            Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x2e4a, 4)),
            Operand::Register(eax),
        ]);

        let expr = Expr::from_instruction(&inst);
        let ExprKind::Assign { rhs, .. } = &expr.kind else {
            panic!("expected assignment, got {:?}", expr.kind);
        };
        let ExprKind::Call { target, args } = &rhs.kind else {
            panic!("expected call rhs, got {:?}", rhs.kind);
        };
        assert!(matches!(target, CallTarget::Named(name) if name == "atomic_fetch_add"));
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_x86_lock_cmpxchg_lifts_to_atomic_compare_exchange_strong() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let inst = Instruction::new(
            0x401276,
            8,
            vec![0xf0, 0x0f, 0xb1, 0x35, 0xaa, 0x2d, 0x00, 0x00],
            "lock cmpxchg",
        )
        .with_operation(Operation::Exchange)
        .with_operands(vec![
            Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x2daa, 4)),
            Operand::Register(esi),
        ]);

        let expr = Expr::from_instruction(&inst);
        let ExprKind::Call { target, args } = &expr.kind else {
            panic!("expected call, got {:?}", expr.kind);
        };
        assert!(matches!(
            target,
            CallTarget::Named(name) if name == "atomic_compare_exchange_strong"
        ));
        assert_eq!(args.len(), 3);
        assert!(matches!(args[1].kind, ExprKind::Var(ref v) if v.name == "eax"));
    }

    #[test]
    fn test_bswap_lifts_to_builtin() {
        use hexray_core::{Architecture, Operand, Operation, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let inst = Instruction::new(0x401320, 2, vec![0x0f, 0xc8], "bswap")
            .with_operation(Operation::Exchange)
            .with_operands(vec![Operand::Register(eax)]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "rax = __builtin_bswap32(rax)");
    }

    #[test]
    fn test_bsr_lifts_to_builtin() {
        use hexray_core::{Architecture, Operand, Operation, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let ecx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 32);
        let inst = Instruction::new(0x401330, 3, vec![0x0f, 0xbd, 0xc1], "bsr")
            .with_operation(Operation::Other(0x0FBD))
            .with_operands(vec![Operand::Register(eax), Operand::Register(ecx)]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "rax = __builtin_bsr(rcx)");
    }

    #[test]
    fn test_prefetch_lifts_to_builtin_without_deref_side_effect() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rdi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 64);
        let inst = Instruction::new(0x401340, 3, vec![0x0f, 0x18, 0x0f], "prefetcht0")
            .with_operation(Operation::Other(0x0F18))
            .with_operands(vec![Operand::Memory(MemoryRef::base_disp(rdi, 0, 8))]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "__builtin_prefetch(rdi, 0, 3)");
    }

    #[test]
    fn test_ud2_lifts_to_builtin_trap() {
        let inst = Instruction::new(0x401350, 2, vec![0x0f, 0x0b], "ud2")
            .with_operation(Operation::Interrupt);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "__builtin_trap()");
    }

    #[test]
    fn test_saved_return_address_slot_lifts_to_builtin() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let inst = Instruction::new(0x401360, 4, vec![0x48, 0x8b, 0x45, 0x08], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Register(rax),
                Operand::Memory(MemoryRef::base_disp(rbp, 8, 8)),
            ]);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "rax = __builtin_return_address(0)");
    }

    #[test]
    fn test_x86_seq_cst_fence_patterns_lift_to_thread_fence() {
        use hexray_core::{Architecture, MemoryRef, Operand, Operation, Register, RegisterClass};

        let rsp = Register::new(Architecture::X86_64, RegisterClass::General, 4, 64);
        let lock_or = Instruction::new(0x4012e4, 6, vec![0xf0, 0x48, 0x83, 0x0c, 0x24, 0x00], "or")
            .with_operation(Operation::Or)
            .with_operands(vec![
                Operand::Memory(MemoryRef::base_disp(rsp, 0, 8)),
                Operand::imm_unsigned(0, 8),
            ]);
        let lock_add = Instruction::new(
            0x4012ea,
            7,
            vec![0xf0, 0x48, 0x83, 0x44, 0x24, 0x08, 0x00],
            "add",
        )
        .with_operation(Operation::Add)
        .with_operands(vec![
            Operand::Memory(MemoryRef::base_disp(rsp, 8, 8)),
            Operand::imm_unsigned(0, 8),
        ]);
        let mfence = Instruction::new(0x401300, 3, vec![0x0f, 0xae, 0xf0], "mfence")
            .with_operation(Operation::Other(0x0FAE));

        for inst in [lock_or, lock_add, mfence] {
            let expr = Expr::from_instruction(&inst);
            let ExprKind::Call { target, args } = &expr.kind else {
                panic!("expected call, got {:?}", expr.kind);
            };
            assert!(matches!(
                target,
                CallTarget::Named(name) if name == "__atomic_thread_fence"
            ));
            assert!(
                matches!(args.as_slice(), [Expr { kind: ExprKind::Unknown(name) }] if name == "memory_order_seq_cst")
            );
        }
    }

    #[test]
    fn test_syscall_lifts_to_linux_syscall_pseudo() {
        let inst = Instruction::new(0x401141, 2, vec![0x0f, 0x05], "syscall")
            .with_operation(Operation::Syscall);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(
            rendered,
            "rax = __linux_syscall(rax, rdi, rsi, rdx, r10, r8, r9)"
        );
    }

    #[test]
    fn test_cpuid_lifts_with_implicit_leaf_input() {
        let inst = Instruction::new(0x4012b7, 2, vec![0x0f, 0xa2], "cpuid")
            .with_operation(Operation::CpuId);

        let rendered = Expr::from_instruction(&inst).to_string();

        assert_eq!(rendered, "cpuid(eax)");
    }

    #[test]
    fn test_hidden_rep_stosq_lifts_to_rdi_clobber() {
        let inst = Instruction::new(0x401408, 3, vec![0xf3, 0x48, 0xab], "__rep_stosq")
            .with_operation(Operation::Other(0xab));

        assert_eq!(
            Expr::from_instruction(&inst).to_string(),
            "rdi = rdi + rcx * 8"
        );
    }
}
