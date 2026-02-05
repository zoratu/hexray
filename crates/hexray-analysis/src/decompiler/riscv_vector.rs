//! RISC-V Vector Extension (RVV) decompilation patterns.
//!
//! This module provides pattern recognition and simplification for RISC-V
//! vector extension instructions, converting low-level vector operations
//! into higher-level representations.
//!
//! # Supported Patterns
//!
//! - Vector configuration (vsetvli, vsetivli, vsetvl)
//! - Vector load/store operations (vle, vse, vlse, vsse, vluxei, etc.)
//! - Vector arithmetic (vadd, vsub, vmul, vdiv, etc.)
//! - Vector reduction operations (vredsum, vredmax, vredmin, etc.)
//! - Vector mask operations (vmand, vmnand, vmor, etc.)
//! - Vector comparison operations (vmseq, vmsne, vmslt, etc.)
//! - Vector permutation (vslide, vrgather, vcompress)

use super::expression::{CallTarget, Expr, ExprKind};
use super::structurer::StructuredNode;

/// RISC-V vector type configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorConfig {
    /// SEW (Selected Element Width) in bits: 8, 16, 32, 64.
    pub sew: u8,
    /// LMUL (Length Multiplier): 1/8, 1/4, 1/2, 1, 2, 4, 8 (stored as fraction * 8).
    pub lmul: i8,
    /// VTA (Vector Tail Agnostic).
    pub vta: bool,
    /// VMA (Vector Mask Agnostic).
    pub vma: bool,
    /// Application vector length (avl).
    pub avl: Option<u64>,
}

impl Default for VectorConfig {
    fn default() -> Self {
        Self {
            sew: 32,
            lmul: 8, // LMUL=1
            vta: false,
            vma: false,
            avl: None,
        }
    }
}

impl VectorConfig {
    /// Creates a new vector configuration.
    pub fn new(sew: u8, lmul: i8) -> Self {
        Self {
            sew,
            lmul,
            ..Default::default()
        }
    }

    /// Returns the element type as a C type string.
    pub fn element_type(&self) -> &'static str {
        match self.sew {
            8 => "int8_t",
            16 => "int16_t",
            32 => "int32_t",
            64 => "int64_t",
            _ => "void",
        }
    }

    /// Returns the unsigned element type as a C type string.
    pub fn unsigned_element_type(&self) -> &'static str {
        match self.sew {
            8 => "uint8_t",
            16 => "uint16_t",
            32 => "uint32_t",
            64 => "uint64_t",
            _ => "void",
        }
    }

    /// Returns the floating-point element type if applicable.
    pub fn float_element_type(&self) -> Option<&'static str> {
        match self.sew {
            16 => Some("_Float16"),
            32 => Some("float"),
            64 => Some("double"),
            _ => None,
        }
    }

    /// Returns the LMUL as a human-readable string.
    pub fn lmul_str(&self) -> String {
        match self.lmul {
            1 => "mf8".to_string(),
            2 => "mf4".to_string(),
            4 => "mf2".to_string(),
            8 => "m1".to_string(),
            16 => "m2".to_string(),
            32 => "m4".to_string(),
            64 => "m8".to_string(),
            _ => format!("m{}", self.lmul as f32 / 8.0),
        }
    }
}

/// RISC-V vector intrinsic kind.
#[derive(Debug, Clone)]
pub enum RvvIntrinsic {
    // Configuration
    Vsetvli {
        avl: Box<Expr>,
        vtypei: u32,
    },
    Vsetivli {
        avl: u8,
        vtypei: u32,
    },
    Vsetvl {
        avl: Box<Expr>,
        vtype: Box<Expr>,
    },

    // Load/Store
    Vle {
        eew: u8,
        base: Box<Expr>,
        vl: Box<Expr>,
    },
    Vse {
        eew: u8,
        base: Box<Expr>,
        vs: Box<Expr>,
        vl: Box<Expr>,
    },
    Vlse {
        eew: u8,
        base: Box<Expr>,
        stride: Box<Expr>,
        vl: Box<Expr>,
    },
    Vsse {
        eew: u8,
        base: Box<Expr>,
        stride: Box<Expr>,
        vs: Box<Expr>,
        vl: Box<Expr>,
    },
    Vluxei {
        eew: u8,
        base: Box<Expr>,
        index: Box<Expr>,
        vl: Box<Expr>,
    },
    Vsuxei {
        eew: u8,
        base: Box<Expr>,
        index: Box<Expr>,
        vs: Box<Expr>,
        vl: Box<Expr>,
    },

    // Arithmetic
    Vadd {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vsub {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vmul {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vdiv {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },

    // Widening operations
    Vwmul {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },
    Vwadd {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },

    // Floating-point
    Vfadd {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vfsub {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vfmul {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vfdiv {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vfmadd {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vs3: Box<Expr>,
        vl: Box<Expr>,
    },

    // Reductions
    Vredsum {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
    },
    Vredmax {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },
    Vredmin {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },
    Vredand {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
    },
    Vredor {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
    },
    Vredxor {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
    },
    Vfredusum {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vs1: Box<Expr>,
        vl: Box<Expr>,
    },

    // Mask operations
    Vmand {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
    },
    Vmnand {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
    },
    Vmor {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
    },
    Vmnor {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
    },
    Vmxor {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
    },
    Vmnot {
        vd: Box<Expr>,
        vs: Box<Expr>,
    },

    // Comparisons (produce mask)
    Vmseq {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vmsne {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
    },
    Vmslt {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },
    Vmsle {
        vd: Box<Expr>,
        vs1: Box<Expr>,
        vs2: Box<Expr>,
        vl: Box<Expr>,
        signed: bool,
    },

    // Permutation
    Vslidedown {
        vd: Box<Expr>,
        vs: Box<Expr>,
        offset: Box<Expr>,
        vl: Box<Expr>,
    },
    Vslideup {
        vd: Box<Expr>,
        vs: Box<Expr>,
        offset: Box<Expr>,
        vl: Box<Expr>,
    },
    Vrgather {
        vd: Box<Expr>,
        vs: Box<Expr>,
        index: Box<Expr>,
        vl: Box<Expr>,
    },
    Vcompress {
        vd: Box<Expr>,
        vs: Box<Expr>,
        vm: Box<Expr>,
        vl: Box<Expr>,
    },

    // Move operations
    Vmv {
        vd: Box<Expr>,
        vs: Box<Expr>,
    },
    VmvXS {
        rd: Box<Expr>,
        vs: Box<Expr>,
    },
    VmvSX {
        vd: Box<Expr>,
        rs: Box<Expr>,
    },
}

/// Simplifies RISC-V vector extension patterns in structured nodes.
pub fn simplify_rvv_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(simplify_rvv_patterns_in_node)
        .collect()
}

fn simplify_rvv_patterns_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = simplify_rvv_statements(statements);
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::Expr(expr) => StructuredNode::Expr(simplify_rvv_expr(expr)),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: simplify_rvv_expr(condition),
            then_body: simplify_rvv_patterns(then_body),
            else_body: else_body.map(simplify_rvv_patterns),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: simplify_rvv_expr(condition),
            body: simplify_rvv_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_rvv_patterns(body),
            condition: simplify_rvv_expr(condition),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(simplify_rvv_expr),
            condition: simplify_rvv_expr(condition),
            update: update.map(simplify_rvv_expr),
            body: simplify_rvv_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_rvv_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: simplify_rvv_expr(value),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, simplify_rvv_patterns(body)))
                .collect(),
            default: default.map(simplify_rvv_patterns),
        },
        StructuredNode::Return(Some(expr)) => StructuredNode::Return(Some(simplify_rvv_expr(expr))),
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(simplify_rvv_patterns(nodes)),
        other => other,
    }
}

/// Simplify a sequence of statements, looking for vector loop patterns.
fn simplify_rvv_statements(statements: Vec<Expr>) -> Vec<Expr> {
    let mut result = Vec::with_capacity(statements.len());

    for stmt in statements {
        let simplified = simplify_rvv_expr(stmt);
        result.push(simplified);
    }

    // Try to detect and simplify vector loop patterns
    result = try_simplify_vector_loop(result);

    result
}

/// Simplify RISC-V vector expressions.
fn simplify_rvv_expr(expr: Expr) -> Expr {
    match expr.kind {
        ExprKind::Assign { lhs, rhs } => {
            let rhs = simplify_rvv_expr(*rhs);
            Expr::assign(*lhs, rhs)
        }
        ExprKind::Call { target, args } => {
            let args: Vec<Expr> = args.into_iter().map(simplify_rvv_expr).collect();

            // Try to recognize RVV intrinsic patterns
            if let Some(simplified) = try_simplify_rvv_intrinsic(&target, &args) {
                return simplified;
            }

            Expr::call(target, args)
        }
        _ => expr,
    }
}

/// Try to simplify an RVV intrinsic call to a higher-level representation.
fn try_simplify_rvv_intrinsic(target: &CallTarget, args: &[Expr]) -> Option<Expr> {
    let name = match target {
        CallTarget::Named(n) => n.as_str(),
        _ => return None,
    };

    // Match RVV intrinsic patterns
    match name {
        // Vector element-wise addition -> array addition
        n if n.starts_with("__riscv_vadd_") || n.starts_with("vadd.") => {
            simplify_vector_binop("vector_add", args)
        }

        // Vector element-wise subtraction
        n if n.starts_with("__riscv_vsub_") || n.starts_with("vsub.") => {
            simplify_vector_binop("vector_sub", args)
        }

        // Vector element-wise multiplication
        n if n.starts_with("__riscv_vmul_") || n.starts_with("vmul.") => {
            simplify_vector_binop("vector_mul", args)
        }

        // Vector element-wise division
        n if n.starts_with("__riscv_vdiv_") || n.starts_with("vdiv.") => {
            simplify_vector_binop("vector_div", args)
        }

        // Floating-point operations
        n if n.starts_with("__riscv_vfadd_") || n.starts_with("vfadd.") => {
            simplify_vector_binop("vector_fadd", args)
        }
        n if n.starts_with("__riscv_vfsub_") || n.starts_with("vfsub.") => {
            simplify_vector_binop("vector_fsub", args)
        }
        n if n.starts_with("__riscv_vfmul_") || n.starts_with("vfmul.") => {
            simplify_vector_binop("vector_fmul", args)
        }
        n if n.starts_with("__riscv_vfdiv_") || n.starts_with("vfdiv.") => {
            simplify_vector_binop("vector_fdiv", args)
        }

        // Fused multiply-add
        n if n.starts_with("__riscv_vfmacc_") || n.starts_with("__riscv_vfmadd_") => {
            simplify_vector_fma(args)
        }

        // Reductions
        n if n.starts_with("__riscv_vredsum_") || n.starts_with("vredsum.") => {
            simplify_reduction("vector_reduce_sum", args)
        }
        n if n.starts_with("__riscv_vredmax_") || n.starts_with("vredmax.") => {
            simplify_reduction("vector_reduce_max", args)
        }
        n if n.starts_with("__riscv_vredmin_") || n.starts_with("vredmin.") => {
            simplify_reduction("vector_reduce_min", args)
        }
        n if n.starts_with("__riscv_vfredusum_") || n.starts_with("vfredosum.") => {
            simplify_reduction("vector_reduce_fsum", args)
        }

        // Vector load
        n if n.starts_with("__riscv_vle") || n.starts_with("vle") => {
            simplify_vector_load(name, args)
        }

        // Vector store
        n if n.starts_with("__riscv_vse") || n.starts_with("vse") => {
            simplify_vector_store(name, args)
        }

        // Strided load
        n if n.starts_with("__riscv_vlse") || n.starts_with("vlse") => {
            simplify_strided_load(name, args)
        }

        // Indexed (gather) load
        n if n.starts_with("__riscv_vluxei") || n.starts_with("vluxei") => {
            simplify_gather_load(name, args)
        }

        // Indexed (scatter) store
        n if n.starts_with("__riscv_vsuxei") || n.starts_with("vsuxei") => {
            simplify_scatter_store(name, args)
        }

        // Mask operations
        n if n.starts_with("__riscv_vmand") => simplify_mask_binop("vector_mask_and", args),
        n if n.starts_with("__riscv_vmor") => simplify_mask_binop("vector_mask_or", args),
        n if n.starts_with("__riscv_vmxor") => simplify_mask_binop("vector_mask_xor", args),
        n if n.starts_with("__riscv_vmnot") => simplify_mask_unary("vector_mask_not", args),

        // Comparison operations
        n if n.starts_with("__riscv_vmseq") => simplify_vector_compare("vector_eq", args),
        n if n.starts_with("__riscv_vmsne") => simplify_vector_compare("vector_ne", args),
        n if n.starts_with("__riscv_vmslt") => simplify_vector_compare("vector_lt", args),
        n if n.starts_with("__riscv_vmsle") => simplify_vector_compare("vector_le", args),
        n if n.starts_with("__riscv_vmsgt") => simplify_vector_compare("vector_gt", args),
        n if n.starts_with("__riscv_vmsge") => simplify_vector_compare("vector_ge", args),

        // Slide operations
        n if n.starts_with("__riscv_vslidedown") => simplify_slide("vector_slide_down", args),
        n if n.starts_with("__riscv_vslideup") => simplify_slide("vector_slide_up", args),

        // Gather
        n if n.starts_with("__riscv_vrgather") => simplify_permutation("vector_gather", args),

        // Compress
        n if n.starts_with("__riscv_vcompress") => simplify_compress(args),

        // Move scalar to/from vector
        n if n.starts_with("__riscv_vmv_x_s") => simplify_extract_scalar(args),
        n if n.starts_with("__riscv_vmv_s_x") => simplify_insert_scalar(args),

        // vsetvl/vsetvli
        n if n.starts_with("__riscv_vsetvl") => simplify_vsetvl(name, args),

        _ => None,
    }
}

fn simplify_vector_binop(op_name: &str, args: &[Expr]) -> Option<Expr> {
    // Typical RVV intrinsic: op(vs2, vs1, vl) or op(mask, vs2, vs1, vl)
    if args.len() >= 2 {
        let (vs1, vs2, vl) = if args.len() >= 3 {
            (&args[0], &args[1], Some(&args[args.len() - 1]))
        } else {
            (&args[0], &args[1], None)
        };

        let mut call_args = vec![vs1.clone(), vs2.clone()];
        if let Some(vl_expr) = vl {
            call_args.push(vl_expr.clone());
        }

        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            call_args,
        ));
    }
    None
}

fn simplify_vector_fma(args: &[Expr]) -> Option<Expr> {
    // vfmacc(vd, vs1, vs2, vl) -> vd + vs1 * vs2
    if args.len() >= 3 {
        return Some(Expr::call(
            CallTarget::Named("vector_fma".to_string()),
            vec![args[0].clone(), args[1].clone(), args[2].clone()],
        ));
    }
    None
}

fn simplify_reduction(op_name: &str, args: &[Expr]) -> Option<Expr> {
    // vredsum(vd_scalar, vs_vector, vs1_init, vl)
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone()],
        ));
    }
    None
}

fn simplify_vector_load(name: &str, args: &[Expr]) -> Option<Expr> {
    // vle{eew}(base, vl) -> vector_load(base, eew)
    let eew = extract_element_width(name)?;

    if !args.is_empty() {
        let base = &args[0];
        let type_suffix = match eew {
            8 => "i8",
            16 => "i16",
            32 => "i32",
            64 => "i64",
            _ => "unknown",
        };

        return Some(Expr::call(
            CallTarget::Named(format!("vector_load_{}", type_suffix)),
            vec![base.clone()],
        ));
    }
    None
}

fn simplify_vector_store(name: &str, args: &[Expr]) -> Option<Expr> {
    // vse{eew}(base, vs, vl) -> vector_store(base, vs, eew)
    let eew = extract_element_width(name)?;

    if args.len() >= 2 {
        let base = &args[0];
        let vs = &args[1];
        let type_suffix = match eew {
            8 => "i8",
            16 => "i16",
            32 => "i32",
            64 => "i64",
            _ => "unknown",
        };

        return Some(Expr::call(
            CallTarget::Named(format!("vector_store_{}", type_suffix)),
            vec![base.clone(), vs.clone()],
        ));
    }
    None
}

fn simplify_strided_load(_name: &str, args: &[Expr]) -> Option<Expr> {
    // vlse(base, stride, vl) -> vector_strided_load(base, stride)
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named("vector_strided_load".to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_gather_load(_name: &str, args: &[Expr]) -> Option<Expr> {
    // vluxei(base, indices, vl) -> vector_gather(base, indices)
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named("vector_gather".to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_scatter_store(_name: &str, args: &[Expr]) -> Option<Expr> {
    // vsuxei(base, indices, vs, vl) -> vector_scatter(base, indices, vs)
    if args.len() >= 3 {
        return Some(Expr::call(
            CallTarget::Named("vector_scatter".to_string()),
            vec![args[0].clone(), args[1].clone(), args[2].clone()],
        ));
    }
    None
}

fn simplify_mask_binop(op_name: &str, args: &[Expr]) -> Option<Expr> {
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_mask_unary(op_name: &str, args: &[Expr]) -> Option<Expr> {
    if !args.is_empty() {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone()],
        ));
    }
    None
}

fn simplify_vector_compare(op_name: &str, args: &[Expr]) -> Option<Expr> {
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_slide(op_name: &str, args: &[Expr]) -> Option<Expr> {
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_permutation(op_name: &str, args: &[Expr]) -> Option<Expr> {
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named(op_name.to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_compress(args: &[Expr]) -> Option<Expr> {
    // vcompress(vs, mask, vl) -> vector_compress(vs, mask)
    if args.len() >= 2 {
        return Some(Expr::call(
            CallTarget::Named("vector_compress".to_string()),
            vec![args[0].clone(), args[1].clone()],
        ));
    }
    None
}

fn simplify_extract_scalar(args: &[Expr]) -> Option<Expr> {
    // vmv_x_s(vs) -> vector_extract_first(vs)
    if !args.is_empty() {
        return Some(Expr::call(
            CallTarget::Named("vector_extract_first".to_string()),
            vec![args[0].clone()],
        ));
    }
    None
}

fn simplify_insert_scalar(args: &[Expr]) -> Option<Expr> {
    // vmv_s_x(scalar, vl) -> vector_broadcast(scalar)
    if !args.is_empty() {
        return Some(Expr::call(
            CallTarget::Named("vector_broadcast".to_string()),
            vec![args[0].clone()],
        ));
    }
    None
}

fn simplify_vsetvl(name: &str, args: &[Expr]) -> Option<Expr> {
    // vsetvl(avl, vtype) -> set_vector_length(avl, sew, lmul)
    // For now, keep it as a configuration call
    let suffix = name.strip_prefix("__riscv_")?;
    Some(Expr::call(
        CallTarget::Named(suffix.to_string()),
        args.to_vec(),
    ))
}

fn extract_element_width(name: &str) -> Option<u8> {
    // Extract element width from intrinsic name like "vle32" or "__riscv_vle32_v_i32m1"
    if name.contains("8") {
        Some(8)
    } else if name.contains("16") {
        Some(16)
    } else if name.contains("32") {
        Some(32)
    } else if name.contains("64") {
        Some(64)
    } else {
        None
    }
}

/// Try to simplify a vector loop pattern.
///
/// Detects patterns like:
/// ```text
/// size_t n = len;
/// while (n > 0) {
///     size_t vl = vsetvl(n, ...);
///     v = vle(p);
///     v = vadd(v, k);
///     vse(p, v);
///     n -= vl;
///     p += vl;
/// }
/// ```
/// And simplifies to:
/// ```text
/// vector_for_each(p, len, |v| v + k);
/// ```
fn try_simplify_vector_loop(statements: Vec<Expr>) -> Vec<Expr> {
    // This is a complex pattern that requires detecting:
    // 1. A vsetvl call at the start
    // 2. Vector load(s)
    // 3. Vector operation(s)
    // 4. Vector store(s)
    // 5. Pointer/counter updates
    //
    // For now, just return statements unchanged
    // Future work: implement full loop detection

    statements
}

/// Detect common RVV loop idioms.
#[derive(Debug, Clone)]
pub struct VectorLoopPattern {
    /// The source pointer/array.
    pub src: Option<Expr>,
    /// The destination pointer/array.
    pub dst: Option<Expr>,
    /// The element count.
    pub count: Option<Expr>,
    /// The vector operations performed.
    pub operations: Vec<VectorOperation>,
    /// Whether this is an in-place operation (src == dst).
    pub in_place: bool,
}

/// A vector operation within a loop.
#[derive(Debug, Clone)]
pub enum VectorOperation {
    /// Element-wise binary operation.
    BinaryOp { op: String, src1: Expr, src2: Expr },
    /// Unary operation.
    UnaryOp { op: String, src: Expr },
    /// Reduction.
    Reduction { op: String, src: Expr },
    /// Type conversion.
    Convert {
        from_type: String,
        to_type: String,
        src: Expr,
    },
}

/// Convert a detected vector loop pattern to a high-level representation.
pub fn vector_loop_to_high_level(pattern: &VectorLoopPattern) -> Option<Expr> {
    if pattern.operations.is_empty() {
        return None;
    }

    // Simple case: single operation on array
    if pattern.operations.len() == 1 {
        if let VectorOperation::BinaryOp { op, src1, src2 } = &pattern.operations[0] {
            if let (Some(dst), Some(count)) = (&pattern.dst, &pattern.count) {
                return Some(Expr::call(
                    CallTarget::Named(format!("array_{}", op)),
                    vec![dst.clone(), src1.clone(), src2.clone(), count.clone()],
                ));
            }
        }

        if let VectorOperation::Reduction { op, src } = &pattern.operations[0] {
            if let Some(count) = &pattern.count {
                return Some(Expr::call(
                    CallTarget::Named(format!("array_{}", op)),
                    vec![src.clone(), count.clone()],
                ));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            name: name.to_string(),
            kind: VarKind::Register(0),
            size: 8,
        })
    }

    #[test]
    fn test_vector_config() {
        let config = VectorConfig::new(32, 8);
        assert_eq!(config.element_type(), "int32_t");
        assert_eq!(config.unsigned_element_type(), "uint32_t");
        assert_eq!(config.float_element_type(), Some("float"));
        assert_eq!(config.lmul_str(), "m1");
    }

    #[test]
    fn test_simplify_vadd() {
        let target = CallTarget::Named("__riscv_vadd_vv_i32m1".to_string());
        let args = vec![make_var("vs1"), make_var("vs2"), make_var("vl")];

        let result = try_simplify_rvv_intrinsic(&target, &args);
        assert!(result.is_some());

        if let Some(Expr {
            kind: ExprKind::Call { target, .. },
            ..
        }) = result
        {
            if let CallTarget::Named(name) = target {
                assert_eq!(name, "vector_add");
            } else {
                panic!("Expected named call target");
            }
        }
    }

    #[test]
    fn test_simplify_vredsum() {
        let target = CallTarget::Named("__riscv_vredsum_vs_i32m1".to_string());
        let args = vec![make_var("vs"), make_var("vs1"), make_var("vl")];

        let result = try_simplify_rvv_intrinsic(&target, &args);
        assert!(result.is_some());

        if let Some(Expr {
            kind: ExprKind::Call { target, .. },
            ..
        }) = result
        {
            if let CallTarget::Named(name) = target {
                assert_eq!(name, "vector_reduce_sum");
            } else {
                panic!("Expected named call target");
            }
        }
    }

    #[test]
    fn test_simplify_vle32() {
        let target = CallTarget::Named("__riscv_vle32_v_i32m1".to_string());
        let args = vec![make_var("base"), make_var("vl")];

        let result = try_simplify_rvv_intrinsic(&target, &args);
        assert!(result.is_some());

        if let Some(Expr {
            kind: ExprKind::Call { target, .. },
            ..
        }) = result
        {
            if let CallTarget::Named(name) = target {
                assert_eq!(name, "vector_load_i32");
            } else {
                panic!("Expected named call target");
            }
        }
    }

    #[test]
    fn test_extract_element_width() {
        assert_eq!(extract_element_width("vle8"), Some(8));
        assert_eq!(extract_element_width("__riscv_vle16_v_i16m1"), Some(16));
        assert_eq!(extract_element_width("vse32"), Some(32));
        assert_eq!(extract_element_width("vluxei64"), Some(64));
        assert_eq!(extract_element_width("vsetvl"), None);
    }

    #[test]
    fn test_simplify_vmseq() {
        let target = CallTarget::Named("__riscv_vmseq_vv_i32m1_b32".to_string());
        let args = vec![make_var("vs1"), make_var("vs2"), make_var("vl")];

        let result = try_simplify_rvv_intrinsic(&target, &args);
        assert!(result.is_some());

        if let Some(Expr {
            kind: ExprKind::Call { target, .. },
            ..
        }) = result
        {
            if let CallTarget::Named(name) = target {
                assert_eq!(name, "vector_eq");
            } else {
                panic!("Expected named call target");
            }
        }
    }
}
