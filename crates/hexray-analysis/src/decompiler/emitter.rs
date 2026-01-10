//! Pseudo-code emitter.
//!
//! Emits readable pseudo-code from structured control flow.

#![allow(dead_code)]

use super::structurer::{StructuredCfg, StructuredNode};
use super::expression::{CallTarget, Expr, ExprKind};
use super::{StringTable, SymbolTable, RelocationTable};
use std::collections::HashSet;
use std::fmt::Write;

/// Information about a function's signature detected from analysis.
struct FunctionInfo {
    /// Detected parameter names (in order).
    parameters: Vec<String>,
    /// Whether the function has a return value.
    has_return_value: bool,
    /// Statements to skip (block_idx, stmt_idx) - these are parameter assignments.
    skip_statements: HashSet<(usize, usize)>,
}

/// Returns the argument index (0-based) for an argument register, or None if not an arg register.
fn get_arg_register_index(name: &str) -> Option<usize> {
    match name {
        // x86-64 System V ABI
        "edi" | "rdi" => Some(0),
        "esi" | "rsi" => Some(1),
        "edx" | "rdx" => Some(2),
        "ecx" | "rcx" => Some(3),
        "r8d" | "r8" => Some(4),
        "r9d" | "r9" => Some(5),
        // ARM64 AAPCS64
        "x0" | "w0" => Some(0),
        "x1" | "w1" => Some(1),
        "x2" | "w2" => Some(2),
        "x3" | "w3" => Some(3),
        "x4" | "w4" => Some(4),
        "x5" | "w5" => Some(5),
        "x6" | "w6" => Some(6),
        "x7" | "w7" => Some(7),
        // RISC-V
        "a0" => Some(0),
        "a1" => Some(1),
        "a2" => Some(2),
        "a3" => Some(3),
        "a4" => Some(4),
        "a5" => Some(5),
        "a6" => Some(6),
        "a7" => Some(7),
        _ => None,
    }
}

/// Emits pseudo-code from structured control flow.
pub struct PseudoCodeEmitter {
    indent: String,
    emit_addresses: bool,
    string_table: Option<StringTable>,
    symbol_table: Option<SymbolTable>,
    relocation_table: Option<RelocationTable>,
}

impl PseudoCodeEmitter {
    /// Creates a new emitter.
    pub fn new(indent: &str, emit_addresses: bool) -> Self {
        Self {
            indent: indent.to_string(),
            emit_addresses,
            string_table: None,
            symbol_table: None,
            relocation_table: None,
        }
    }

    /// Sets the string table for resolving addresses.
    pub fn with_string_table(mut self, table: Option<StringTable>) -> Self {
        self.string_table = table;
        self
    }

    /// Sets the symbol table for resolving function addresses.
    pub fn with_symbol_table(mut self, table: Option<SymbolTable>) -> Self {
        self.symbol_table = table;
        self
    }

    /// Sets the relocation table for resolving call targets in relocatable files.
    pub fn with_relocation_table(mut self, table: Option<RelocationTable>) -> Self {
        self.relocation_table = table;
        self
    }

    /// Formats an expression, resolving strings from the string table.
    fn format_expr(&self, expr: &Expr) -> String {
        if let Some(ref table) = self.string_table {
            self.format_expr_with_strings(expr, table)
        } else {
            expr.to_string()
        }
    }

    /// Formats an expression with string resolution.
    fn format_expr_with_strings(&self, expr: &Expr, table: &StringTable) -> String {
        match &expr.kind {
            ExprKind::IntLit(n) => {
                // Check if this integer might be a string address
                if *n > 0 && *n < i128::from(u64::MAX) {
                    let addr = *n as u64;
                    if let Some(s) = table.get(addr) {
                        // Escape the string for C output
                        return format!("\"{}\"", escape_string(s));
                    }
                }
                // Format integers as decimal for readability
                format_integer(*n)
            }
            ExprKind::BinOp { op, left, right } => {
                format!("{} {} {}",
                    self.format_expr_with_strings(left, table),
                    op.as_str(),
                    self.format_expr_with_strings(right, table))
            }
            ExprKind::UnaryOp { op, operand } => {
                format!("{}{}", op.as_str(), self.format_expr_with_strings(operand, table))
            }
            ExprKind::Deref { addr, size } => {
                // Check if this is a stack slot access (rbp + offset or rbp - offset)
                if let Some(var_name) = self.try_format_stack_slot(addr, *size) {
                    return var_name;
                }
                // Fall back to default deref formatting
                let prefix = match size {
                    1 => "*(uint8_t*)",
                    2 => "*(uint16_t*)",
                    4 => "*(uint32_t*)",
                    8 => "*(uint64_t*)",
                    _ => "*",
                };
                format!("{}({})", prefix, self.format_expr_with_strings(addr, table))
            }
            ExprKind::Assign { lhs, rhs } => {
                // Check for compound assignment patterns: x = x op y → x op= y
                if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                    if exprs_equal(lhs, left) {
                        let lhs_str = self.format_expr_with_strings(lhs, table);
                        let rhs_str = self.format_expr_with_strings(right, table);

                        // Special case: x = x + 1 → x++ and x = x - 1 → x--
                        if let ExprKind::IntLit(1) = right.kind {
                            match op {
                                super::expression::BinOpKind::Add => return format!("{}++", lhs_str),
                                super::expression::BinOpKind::Sub => return format!("{}--", lhs_str),
                                _ => {}
                            }
                        }

                        // General compound assignment: x = x op y → x op= y
                        if let Some(compound_op) = op.compound_op_str() {
                            return format!("{} {}= {}", lhs_str, compound_op, rhs_str);
                        }
                    }
                }
                format!("{} = {}",
                    self.format_expr_with_strings(lhs, table),
                    self.format_expr_with_strings(rhs, table))
            }
            ExprKind::GotRef { address, size, display_expr, is_deref } => {
                // Try to resolve the GOT/data address to a symbol name
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*address) {
                        // Found symbol in GOT - return just the symbol name
                        return name.to_string();
                    }
                }
                // Try symbol table
                if let Some(ref sym_table) = self.symbol_table {
                    if let Some(name) = sym_table.get(*address) {
                        return name.to_string();
                    }
                }
                // Try string table
                if let Some(s) = table.get(*address) {
                    return format!("\"{}\"", escape_string(s));
                }
                // Fall back to default display
                if *is_deref {
                    let prefix = match size {
                        1 => "*(uint8_t*)",
                        2 => "*(uint16_t*)",
                        4 => "*(uint32_t*)",
                        8 => "*(uint64_t*)",
                        _ => "*",
                    };
                    format!("{}({})", prefix, self.format_expr_with_strings(display_expr, table))
                } else {
                    // Address-of (LEA) - format as sub_XXXX if it looks like a code address
                    format!("sub_{:x}", address)
                }
            }
            ExprKind::Call { target, args } => {
                let target_str = match target {
                    super::expression::CallTarget::Direct { target: addr, call_site } => {
                        // First check relocation table (for kernel modules)
                        // This uses the call instruction address to find the target symbol
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get(*call_site) {
                                name.to_string()
                            } else if let Some(ref sym_table) = self.symbol_table {
                                // Fall back to symbol table by target address
                                if let Some(name) = sym_table.get(*addr) {
                                    name.to_string()
                                } else {
                                    format!("sub_{:x}", addr)
                                }
                            } else {
                                format!("sub_{:x}", addr)
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Check symbol table by target address
                            if let Some(name) = sym_table.get(*addr) {
                                name.to_string()
                            } else if let Some(s) = table.get(*addr) {
                                // Check if this is a string address (for lea/adr patterns)
                                return format!("\"{}\"", escape_string(s));
                            } else {
                                format!("sub_{:x}", addr)
                            }
                        } else if let Some(s) = table.get(*addr) {
                            // Check if this is a string address (for lea/adr patterns)
                            return format!("\"{}\"", escape_string(s));
                        } else {
                            format!("sub_{:x}", addr)
                        }
                    }
                    super::expression::CallTarget::Named(name) => name.clone(),
                    super::expression::CallTarget::Indirect(e) => {
                        format!("({})", self.format_expr_with_strings(e, table))
                    }
                    super::expression::CallTarget::IndirectGot { got_address, expr } => {
                        // Try to resolve the GOT entry to a symbol name
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get_got(*got_address) {
                                name.to_string()
                            } else {
                                // Fall back to showing the expression
                                format!("({})", self.format_expr_with_strings(expr, table))
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Try symbol table by GOT address (rare, but possible)
                            if let Some(name) = sym_table.get(*got_address) {
                                name.to_string()
                            } else {
                                format!("({})", self.format_expr_with_strings(expr, table))
                            }
                        } else {
                            format!("({})", self.format_expr_with_strings(expr, table))
                        }
                    }
                };
                let args_str: Vec<_> = args.iter()
                    .map(|a| self.format_expr_with_strings(a, table))
                    .collect();
                format!("{}({})", target_str, args_str.join(", "))
            }
            // Handle variables - convert ARM64 zero register to literal 0
            ExprKind::Var(var) => {
                let name_lower = var.name.to_lowercase();
                if name_lower == "wzr" || name_lower == "xzr" {
                    // ARM64 zero register represents constant 0
                    "0".to_string()
                } else {
                    var.name.clone()
                }
            }
            // For other cases, use default formatting
            _ => expr.to_string(),
        }
    }

    /// Emits pseudo-code for a structured CFG.
    pub fn emit(&self, cfg: &StructuredCfg, func_name: &str) -> String {
        let mut output = String::new();

        // Analyze function to detect parameters and return type
        let func_info = self.analyze_function(&cfg.body);

        // Function header with detected signature
        let return_type = if func_info.has_return_value { "int" } else { "void" };
        if func_info.parameters.is_empty() {
            writeln!(output, "{} {}()", return_type, func_name).unwrap();
        } else {
            let params: Vec<_> = func_info.parameters.iter()
                .map(|p| format!("int {}", p))
                .collect();
            writeln!(output, "{} {}({})", return_type, func_name, params.join(", ")).unwrap();
        }
        writeln!(output, "{{").unwrap();

        // Collect all local variables used in the function (excluding parameters)
        let all_vars = self.collect_local_variables(&cfg.body, &func_info.parameters);

        // Emit variable declarations at the top (C89 style)
        if !all_vars.is_empty() {
            let indent = &self.indent;
            for var in &all_vars {
                writeln!(output, "{}int {};", indent, var).unwrap();
            }
            writeln!(output).unwrap(); // Blank line after declarations
        }

        // Track declared variables (parameters + locals)
        let mut declared_vars: HashSet<String> = func_info.parameters.iter().cloned().collect();
        declared_vars.extend(all_vars);

        // Emit body, skipping parameter assignment statements
        self.emit_nodes_with_skip_and_decls(&cfg.body, &mut output, 1, &func_info.skip_statements, &mut declared_vars);

        writeln!(output, "}}").unwrap();
        output
    }

    /// Collects all local variables assigned to in the function body.
    fn collect_local_variables(&self, nodes: &[StructuredNode], params: &[String]) -> Vec<String> {
        let mut vars = HashSet::new();
        self.collect_vars_from_nodes(nodes, &mut vars);

        // Remove parameters
        for p in params {
            vars.remove(p);
        }

        // Sort for consistent output
        let mut vars: Vec<_> = vars.into_iter().collect();
        vars.sort();
        vars
    }

    fn collect_vars_from_nodes(&self, nodes: &[StructuredNode], vars: &mut HashSet<String>) {
        for node in nodes {
            self.collect_vars_from_node(node, vars);
        }
    }

    fn collect_vars_from_node(&self, node: &StructuredNode, vars: &mut HashSet<String>) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    // Skip prologue/epilogue
                    if self.is_prologue_epilogue(stmt) {
                        continue;
                    }
                    if let ExprKind::Assign { lhs, .. } = &stmt.kind {
                        if let Some(var_name) = get_stack_var_name(lhs) {
                            vars.insert(var_name);
                        }
                    }
                }
            }
            StructuredNode::If { then_body, else_body, .. } => {
                self.collect_vars_from_nodes(then_body, vars);
                if let Some(else_nodes) = else_body {
                    self.collect_vars_from_nodes(else_nodes, vars);
                }
            }
            StructuredNode::While { body, .. } |
            StructuredNode::DoWhile { body, .. } |
            StructuredNode::For { body, .. } |
            StructuredNode::Loop { body } => {
                self.collect_vars_from_nodes(body, vars);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    self.collect_vars_from_nodes(case_body, vars);
                }
                if let Some(def) = default {
                    self.collect_vars_from_nodes(def, vars);
                }
            }
            StructuredNode::Sequence(nodes) => {
                self.collect_vars_from_nodes(nodes, vars);
            }
            _ => {}
        }
    }

    /// Analyzes a function body to detect parameters and return type.
    fn analyze_function(&self, body: &[StructuredNode]) -> FunctionInfo {
        let mut info = FunctionInfo {
            parameters: Vec::new(),
            has_return_value: false,
            skip_statements: HashSet::new(),
        };

        // Check first block for parameter patterns and prologue
        if let Some(StructuredNode::Block { statements, .. }) = body.first() {
            for (idx, stmt) in statements.iter().enumerate() {
                // Skip prologue statements
                if is_prologue_statement(stmt) {
                    info.skip_statements.insert((0, idx));
                    continue;
                }

                // Check for parameter assignments (var = arg_register)
                if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                    // Check if RHS is an argument register
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if let Some(arg_idx) = get_arg_register_index(&rhs_var.name) {
                            // Check if LHS is a stack variable (either Var or Deref that formats to var_N)
                            let lhs_name = get_stack_var_name(lhs);
                            if let Some(var_name) = lhs_name {
                                if var_name.starts_with("var_") {
                                    // This is a parameter: use the stack var name as param name
                                    // Ensure we have enough slots
                                    while info.parameters.len() <= arg_idx {
                                        info.parameters.push(String::new());
                                    }
                                    info.parameters[arg_idx] = var_name;
                                    info.skip_statements.insert((0, idx));
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check last block for epilogue
        for (block_idx, node) in body.iter().enumerate() {
            if let StructuredNode::Block { statements, .. } = node {
                for (idx, stmt) in statements.iter().enumerate() {
                    if is_epilogue_statement(stmt) {
                        info.skip_statements.insert((block_idx, idx));
                    }
                }
            }
        }

        // Remove empty parameter slots (non-contiguous parameters)
        info.parameters = info.parameters.into_iter()
            .take_while(|p| !p.is_empty())
            .collect();

        // Check for return values
        info.has_return_value = self.has_return_value(body);

        info
    }

    /// Checks if the function body has any return statements with values.
    fn has_return_value(&self, nodes: &[StructuredNode]) -> bool {
        for node in nodes {
            match node {
                StructuredNode::Return(Some(_)) => return true,
                StructuredNode::If { then_body, else_body, .. } => {
                    if self.has_return_value(then_body) {
                        return true;
                    }
                    if let Some(else_nodes) = else_body {
                        if self.has_return_value(else_nodes) {
                            return true;
                        }
                    }
                }
                StructuredNode::While { body, .. } |
                StructuredNode::DoWhile { body, .. } |
                StructuredNode::For { body, .. } |
                StructuredNode::Loop { body } => {
                    if self.has_return_value(body) {
                        return true;
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        if self.has_return_value(case_body) {
                            return true;
                        }
                    }
                    if let Some(def) = default {
                        if self.has_return_value(def) {
                            return true;
                        }
                    }
                }
                StructuredNode::Sequence(nodes) => {
                    if self.has_return_value(nodes) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Emits nodes, skipping specified statements and tracking variable declarations.
    fn emit_nodes_with_skip_and_decls(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        skip: &HashSet<(usize, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        for (block_idx, node) in nodes.iter().enumerate() {
            self.emit_node_with_skip_and_decls(node, output, depth, block_idx, skip, declared_vars);
            if self.is_control_exit(node) {
                break;
            }
        }
    }

    fn emit_node_with_skip_and_decls(
        &self,
        node: &StructuredNode,
        output: &mut String,
        depth: usize,
        block_idx: usize,
        skip: &HashSet<(usize, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block { id, statements, address_range } => {
                // Filter out skipped statements
                let filtered: Vec<_> = statements.iter()
                    .enumerate()
                    .filter(|(stmt_idx, _)| !skip.contains(&(block_idx, *stmt_idx)))
                    .map(|(_, stmt)| stmt)
                    .collect();

                if self.emit_addresses {
                    let indent = self.indent.repeat(depth);
                    writeln!(output, "{}// bb{} [{:#x}..{:#x}]", indent, id.0, address_range.0, address_range.1).unwrap();
                }
                for stmt in filtered {
                    self.emit_statement_with_decl(stmt, output, depth, declared_vars);
                }
            }
            // For control flow structures, recurse with the same declared_vars
            StructuredNode::If { condition, then_body, else_body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}if ({}) {{", indent, self.format_expr(condition)).unwrap();
                self.emit_nodes_with_decls(then_body, output, depth + 1, declared_vars);
                if let Some(else_nodes) = else_body {
                    if else_nodes.len() == 1 {
                        if let StructuredNode::If { .. } = &else_nodes[0] {
                            write!(output, "{}}} else ", indent).unwrap();
                            self.emit_node_with_decls(&else_nodes[0], output, depth, declared_vars);
                            return;
                        }
                    }
                    writeln!(output, "{}}} else {{", indent).unwrap();
                    self.emit_nodes_with_decls(else_nodes, output, depth + 1, declared_vars);
                }
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::While { condition, body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while ({}) {{", indent, self.format_expr(condition)).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::DoWhile { body, condition } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}} while ({});", indent, self.format_expr(condition)).unwrap();
            }
            StructuredNode::Loop { body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            // For other node types, delegate to the normal emit_node
            _ => self.emit_node(node, output, depth),
        }
    }

    /// Emits nodes tracking variable declarations.
    fn emit_nodes_with_decls(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        declared_vars: &mut HashSet<String>,
    ) {
        for node in nodes {
            self.emit_node_with_decls(node, output, depth, declared_vars);
            if self.is_control_exit(node) {
                break;
            }
        }
    }

    fn emit_node_with_decls(
        &self,
        node: &StructuredNode,
        output: &mut String,
        depth: usize,
        declared_vars: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block { id, statements, address_range } => {
                if self.emit_addresses {
                    let indent = self.indent.repeat(depth);
                    writeln!(output, "{}// bb{} [{:#x}..{:#x}]", indent, id.0, address_range.0, address_range.1).unwrap();
                }
                for stmt in statements {
                    self.emit_statement_with_decl(stmt, output, depth, declared_vars);
                }
            }
            // For control flow structures, recurse
            StructuredNode::If { condition, then_body, else_body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}if ({}) {{", indent, self.format_expr(condition)).unwrap();
                self.emit_nodes_with_decls(then_body, output, depth + 1, declared_vars);
                if let Some(else_nodes) = else_body {
                    if else_nodes.len() == 1 {
                        if let StructuredNode::If { .. } = &else_nodes[0] {
                            write!(output, "{}}} else ", indent).unwrap();
                            self.emit_node_with_decls(&else_nodes[0], output, depth, declared_vars);
                            return;
                        }
                    }
                    writeln!(output, "{}}} else {{", indent).unwrap();
                    self.emit_nodes_with_decls(else_nodes, output, depth + 1, declared_vars);
                }
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::While { condition, body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while ({}) {{", indent, self.format_expr(condition)).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::DoWhile { body, condition } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}} while ({});", indent, self.format_expr(condition)).unwrap();
            }
            StructuredNode::Loop { body } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            _ => self.emit_node(node, output, depth),
        }
    }

    /// Emits a statement (variables are declared at function top, so no inline declarations).
    fn emit_statement_with_decl(&self, expr: &Expr, output: &mut String, depth: usize, _declared_vars: &mut HashSet<String>) {
        // Skip prologue/epilogue boilerplate
        if self.is_prologue_epilogue(expr) {
            return;
        }

        // Skip redundant no-op assignments
        if self.is_noop_assignment(expr) {
            return;
        }

        let indent = self.indent.repeat(depth);
        let expr_str = self.format_expr(expr);

        if expr_str.is_empty() || expr_str == "/* nop */" {
            return;
        }

        if expr_str == "return" {
            writeln!(output, "{}return;", indent).unwrap();
            return;
        }

        writeln!(output, "{}{};", indent, expr_str).unwrap();
    }

    fn emit_nodes(&self, nodes: &[StructuredNode], output: &mut String, depth: usize) {
        for node in nodes {
            self.emit_node(node, output, depth);
            // Stop emitting after control flow that exits the current scope
            if self.is_control_exit(node) {
                break;
            }
        }
    }

    /// Checks if a node is a control flow exit (goto, return, break, continue).
    fn is_control_exit(&self, node: &StructuredNode) -> bool {
        match node {
            StructuredNode::Goto(_) |
            StructuredNode::Return(_) |
            StructuredNode::Break |
            StructuredNode::Continue => true,
            // Check if an if-else exits on both branches
            StructuredNode::If { then_body, else_body, .. } => {
                let then_exits = then_body.last().is_some_and(|n| self.is_control_exit(n));
                let else_exits = else_body.as_ref()
                    .and_then(|e| e.last())
                    .is_some_and(|n| self.is_control_exit(n));
                then_exits && else_exits
            }
            _ => false,
        }
    }

    fn emit_node(&self, node: &StructuredNode, output: &mut String, depth: usize) {
        let indent = self.indent.repeat(depth);

        match node {
            StructuredNode::Block { id, statements, address_range } => {
                if self.emit_addresses {
                    writeln!(output, "{}// {} [{:#x} - {:#x}]", indent, id, address_range.0, address_range.1).unwrap();
                }
                // Get data relocations for this block to resolve `reg = 0` assignments
                let data_relocs = if let Some(ref reloc_table) = self.relocation_table {
                    reloc_table.get_data_in_range(address_range.0, address_range.1)
                } else {
                    Vec::new()
                };
                let mut reloc_idx = 0;

                for stmt in statements {
                    // Check if this is an assignment of 0 and we have a data relocation
                    if let ExprKind::Assign { rhs, .. } = &stmt.kind {
                        if let ExprKind::IntLit(0) = rhs.kind {
                            if reloc_idx < data_relocs.len() {
                                // Replace with symbol reference
                                let (_, symbol) = data_relocs[reloc_idx];
                                reloc_idx += 1;
                                self.emit_statement_with_data_symbol(stmt, symbol, output, depth);
                                continue;
                            }
                        }
                    }
                    self.emit_statement(stmt, output, depth);
                }
            }

            StructuredNode::If { condition, then_body, else_body } => {
                // If then_body is empty but else_body has content, invert the condition
                let (actual_cond, actual_then, actual_else) = if then_body.is_empty() && else_body.is_some() {
                    (condition.clone().negate(), else_body.as_ref().unwrap().clone(), None)
                } else {
                    (condition.clone(), then_body.clone(), else_body.clone())
                };

                writeln!(output, "{}if ({}) {{", indent, self.format_expr(&actual_cond)).unwrap();
                self.emit_nodes(&actual_then, output, depth + 1);

                if let Some(else_body) = actual_else {
                    if else_body.len() == 1 {
                        if let StructuredNode::If { .. } = &else_body[0] {
                            // else if
                            write!(output, "{}}} else ", indent).unwrap();
                            self.emit_node(&else_body[0], output, depth);
                            return;
                        }
                    }
                    writeln!(output, "{}}} else {{", indent).unwrap();
                    self.emit_nodes(&else_body, output, depth + 1);
                }

                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::While { condition, body } => {
                writeln!(output, "{}while ({}) {{", indent, self.format_expr(condition)).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::DoWhile { body, condition } => {
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}} while ({});", indent, self.format_expr(condition)).unwrap();
            }

            StructuredNode::For { init, condition, update, body } => {
                let init_str = init.as_ref().map(|e| self.format_expr(e)).unwrap_or_default();
                let update_str = update.as_ref().map(|e| self.format_expr(e)).unwrap_or_default();
                writeln!(output, "{}for ({}; {}; {}) {{", indent, init_str, self.format_expr(condition), update_str).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Loop { body } => {
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Break => {
                writeln!(output, "{}break;", indent).unwrap();
            }

            StructuredNode::Continue => {
                writeln!(output, "{}continue;", indent).unwrap();
            }

            StructuredNode::Return(expr) => {
                if let Some(e) = expr {
                    writeln!(output, "{}return {};", indent, self.format_expr(e)).unwrap();
                } else {
                    writeln!(output, "{}return;", indent).unwrap();
                }
            }

            StructuredNode::Goto(target) => {
                writeln!(output, "{}goto {};", indent, target).unwrap();
            }

            StructuredNode::Label(id) => {
                // Labels are at column 0
                writeln!(output, "{}:", id).unwrap();
            }

            StructuredNode::Switch { value, cases, default } => {
                writeln!(output, "{}switch ({}) {{", indent, self.format_expr(value)).unwrap();
                for (values, body) in cases {
                    for v in values {
                        writeln!(output, "{}case {}:", indent, v).unwrap();
                    }
                    self.emit_nodes(body, output, depth + 1);
                    writeln!(output, "{}    break;", indent).unwrap();
                }
                if let Some(default_body) = default {
                    writeln!(output, "{}default:", indent).unwrap();
                    self.emit_nodes(default_body, output, depth + 1);
                }
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Sequence(nodes) => {
                self.emit_nodes(nodes, output, depth);
            }

            StructuredNode::Expr(expr) => {
                self.emit_statement(expr, output, depth);
            }
        }
    }

    fn emit_statement(&self, expr: &Expr, output: &mut String, depth: usize) {
        // Skip prologue/epilogue boilerplate
        if self.is_prologue_epilogue(expr) {
            return;
        }

        // Skip redundant no-op assignments
        if self.is_noop_assignment(expr) {
            return;
        }

        let indent = self.indent.repeat(depth);
        let expr_str = self.format_expr(expr);

        // Skip empty/nop statements
        if expr_str.is_empty() || expr_str == "/* nop */" {
            return;
        }

        // Check if it's a return
        if expr_str == "return" {
            writeln!(output, "{}return;", indent).unwrap();
            return;
        }

        writeln!(output, "{}{};", indent, expr_str).unwrap();
    }

    /// Checks if a statement is function prologue/epilogue boilerplate.
    /// These patterns don't add semantic value and clutter the output.
    fn is_prologue_epilogue(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // push(rbp) / pop(rbp) - prologue/epilogue
            ExprKind::Call { target, args } => {
                if let CallTarget::Named(name) = target {
                    if name == "push" || name == "pop" {
                        if let Some(arg) = args.first() {
                            if let ExprKind::Var(v) = &arg.kind {
                                if v.name == "rbp" {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            // rbp = rsp (prologue) or rsp = rsp +/- N (stack frame)
            ExprKind::Assign { lhs, rhs } => {
                if let ExprKind::Var(lhs_var) = &lhs.kind {
                    // rbp = rsp (frame pointer setup)
                    if lhs_var.name == "rbp" {
                        if let ExprKind::Var(rhs_var) = &rhs.kind {
                            if rhs_var.name == "rsp" {
                                return true;
                            }
                        }
                    }
                    // rsp = rsp +/- N (stack allocation/deallocation)
                    if lhs_var.name == "rsp" {
                        if let ExprKind::BinOp { left, .. } = &rhs.kind {
                            if let ExprKind::Var(inner_var) = &left.kind {
                                if inner_var.name == "rsp" {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Checks if an assignment is a no-op (e.g., x = x, x = x + 0, x = x * 1).
    fn is_noop_assignment(&self, expr: &Expr) -> bool {
        use super::expression::BinOpKind;

        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            // Check for exact self-assignment: x = x
            if exprs_equal(lhs, rhs) {
                return true;
            }

            // Check for identity operations: x = x + 0, x = x - 0, x = x * 1, x = x | 0, x = x ^ 0
            if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                if exprs_equal(lhs, left) {
                    // Check if the right operand is an identity value for this operation
                    if let ExprKind::IntLit(n) = &right.kind {
                        match op {
                            BinOpKind::Add | BinOpKind::Sub | BinOpKind::Or | BinOpKind::Xor | BinOpKind::Shl | BinOpKind::Shr => {
                                if *n == 0 {
                                    return true;
                                }
                            }
                            BinOpKind::Mul | BinOpKind::Div => {
                                if *n == 1 {
                                    return true;
                                }
                            }
                            BinOpKind::And => {
                                // x & -1 (all bits set) is identity
                                if *n == -1 {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        false
    }

    /// Try to format a stack slot dereference as a local variable name.
    /// Detects patterns like rbp + -0x8 and converts to var_8.
    fn try_format_stack_slot(&self, addr: &Expr, _size: u8) -> Option<String> {
        use super::expression::BinOpKind;

        // Check for base-only pattern (offset 0): just "sp" or "x29"
        if let ExprKind::Var(base) = &addr.kind {
            if base.name == "sp" {
                return Some("var_0".to_string());
            }
        }

        // Check for base + offset pattern
        if let ExprKind::BinOp { op, left, right } = &addr.kind {
            if let ExprKind::Var(base) = &left.kind {
                // Frame pointers: rbp (x86-64), x29 (ARM64) - locals at negative offsets
                let is_frame_pointer = base.name == "rbp" || base.name == "x29";
                // Stack pointer: sp (ARM64) - locals at positive offsets
                let is_stack_pointer = base.name == "sp";

                if is_frame_pointer || is_stack_pointer {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        let actual_offset = match op {
                            BinOpKind::Add => *offset,
                            BinOpKind::Sub => -*offset,
                            _ => return None,
                        };

                        if is_frame_pointer {
                            // Frame pointer: locals at negative offsets, args at positive
                            if actual_offset < 0 {
                                return Some(format!("var_{:x}", -actual_offset));
                            } else if actual_offset > 0 {
                                return Some(format!("arg_{:x}", actual_offset));
                            }
                        } else {
                            // Stack pointer: locals at positive offsets
                            if actual_offset >= 0 {
                                return Some(format!("var_{:x}", actual_offset));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Emits a statement where the RHS 0 should be replaced with a symbol.
    fn emit_statement_with_data_symbol(&self, expr: &Expr, symbol: &str, output: &mut String, depth: usize) {
        let indent = self.indent.repeat(depth);

        if let ExprKind::Assign { lhs, .. } = &expr.kind {
            let lhs_str = self.format_expr(lhs);
            // Format as address-of symbol (since we're loading an address)
            writeln!(output, "{}{} = &{};", indent, lhs_str, symbol).unwrap();
        } else {
            // Fallback to regular emission
            self.emit_statement(expr, output, depth);
        }
    }
}

/// Formats an integer for C output.
/// Uses decimal for "normal" values and hex for large addresses.
fn format_integer(n: i128) -> String {
    if n < 0 {
        // Negative numbers in decimal
        format!("{}", n)
    } else if n <= 255 {
        // Small values in decimal
        format!("{}", n)
    } else if n <= 0xFFFF && !looks_like_address(n) {
        // Medium values in decimal if they don't look like addresses
        format!("{}", n)
    } else {
        // Large values (likely addresses) in hex
        format!("{:#x}", n)
    }
}

/// Heuristic: does this value look like a memory address?
fn looks_like_address(n: i128) -> bool {
    // Common address ranges for x86-64
    let n = n as u64;
    // Stack addresses (high memory)
    if n >= 0x7FFF_0000_0000 {
        return true;
    }
    // Code/data addresses (typically 0x400000+ for ELF, 0x100000000+ for Mach-O)
    if n >= 0x400000 && (n & 0xFFF) == 0 {
        return true; // Page-aligned addresses
    }
    false
}

/// Escapes a string for C output.
fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_ascii_control() => {
                result.push_str(&format!("\\x{:02x}", c as u8));
            }
            c => result.push(c),
        }
    }
    result
}

/// Helper to format a condition nicely.
pub fn format_condition(cond: &Expr) -> String {
    cond.to_string()
}

/// Extracts the stack variable name from an expression.
/// Handles both Var("var_4") and Deref patterns like [rbp - 0x4] → "var_4".
fn get_stack_var_name(expr: &Expr) -> Option<String> {
    use super::expression::BinOpKind;

    match &expr.kind {
        ExprKind::Var(v) => {
            if v.name.starts_with("var_") || v.name.starts_with("arg_") {
                Some(v.name.clone())
            } else {
                None
            }
        }
        ExprKind::Deref { addr, .. } => {
            // Check for base + offset pattern (rbp for x86-64, sp/x29 for ARM64)
            if let ExprKind::BinOp { op, left, right } = &addr.kind {
                if let ExprKind::Var(base) = &left.kind {
                    let is_x86_frame = base.name == "rbp";
                    let is_arm64_stack = base.name == "sp" || base.name == "x29";

                    if is_x86_frame || is_arm64_stack {
                        if let ExprKind::IntLit(offset) = &right.kind {
                            let actual_offset = match op {
                                BinOpKind::Add => *offset,
                                BinOpKind::Sub => -*offset,
                                _ => return None,
                            };

                            if is_x86_frame {
                                // x86-64: locals at negative offsets from rbp
                                if actual_offset < 0 {
                                    return Some(format!("var_{:x}", -actual_offset));
                                } else if actual_offset > 0 {
                                    return Some(format!("arg_{:x}", actual_offset));
                                }
                            } else {
                                // ARM64: locals at positive offsets from sp
                                if actual_offset >= 0 {
                                    return Some(format!("var_{:x}", actual_offset));
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Checks if a statement is a prologue pattern (push rbp, rbp = rsp, sp = sp - N, etc.)
fn is_prologue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // push(rbp) - x86-64 prologue
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "push" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: stp (store pair) for x29, x30
                if name == "stp" {
                    return true;
                }
            }
            false
        }
        // Frame setup patterns for x86-64 and ARM64
        ExprKind::Assign { lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rbp = rsp (frame pointer setup)
                if lhs_var.name == "rbp" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        return rhs_var.name == "rsp";
                    }
                }
                // x86-64: rsp = rsp - N (stack allocation)
                // ARM64: sp = sp - N or sp = N (stack allocation)
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // sp = 0 or sp = constant (ARM64 sub sp, sp, #N becomes sp = 0 after structuring)
                    if let ExprKind::IntLit(_) = &rhs.kind {
                        return true;
                    }
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = sp + N (frame pointer setup)
                if lhs_var.name == "x29" {
                    return true;
                }
                // ARM64: x30 = x29 (link register save pattern)
                if lhs_var.name == "x30" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x29" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Checks if a statement is an epilogue pattern (pop rbp, rsp = rsp + N, ldp, etc.)
fn is_epilogue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // pop(rbp) - x86-64 epilogue
        // ldp - ARM64 epilogue (load pair, restores x29/x30)
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "pop" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: ldp (load pair) for x29, x30
                if name == "ldp" {
                    return true;
                }
            }
            false
        }
        // Stack deallocation patterns
        ExprKind::Assign { lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rsp = rsp + N
                // ARM64: sp = sp + N
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = x30 (restore frame pointer from link register)
                if lhs_var.name == "x29" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x30" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Checks if two expressions are structurally equal.
fn exprs_equal(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(va), ExprKind::Var(vb)) => va.name == vb.name,
        (ExprKind::IntLit(na), ExprKind::IntLit(nb)) => na == nb,
        (ExprKind::BinOp { op: opa, left: la, right: ra },
         ExprKind::BinOp { op: opb, left: lb, right: rb }) => {
            opa == opb && exprs_equal(la, lb) && exprs_equal(ra, rb)
        }
        (ExprKind::UnaryOp { op: opa, operand: oa },
         ExprKind::UnaryOp { op: opb, operand: ob }) => {
            opa == opb && exprs_equal(oa, ob)
        }
        (ExprKind::Deref { addr: aa, size: sa },
         ExprKind::Deref { addr: ab, size: sb }) => {
            sa == sb && exprs_equal(aa, ab)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::expression::BinOpKind;

    #[test]
    fn test_emit_if_else() {
        let cond = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(0));
        let then_body = vec![StructuredNode::Expr(
            Expr::assign(Expr::unknown("y"), Expr::int(1))
        )];
        let else_body = Some(vec![StructuredNode::Expr(
            Expr::assign(Expr::unknown("y"), Expr::int(2))
        )]);

        let node = StructuredNode::If {
            condition: cond,
            then_body,
            else_body,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("if (x == 0)"));
        assert!(output.contains("y = 1"));
        assert!(output.contains("else"));
        assert!(output.contains("y = 2"));
    }

    #[test]
    fn test_emit_while() {
        let cond = Expr::binop(BinOpKind::Lt, Expr::unknown("i"), Expr::int(10));
        let body = vec![
            StructuredNode::Expr(Expr::assign(
                Expr::unknown("i"),
                Expr::binop(BinOpKind::Add, Expr::unknown("i"), Expr::int(1))
            ))
        ];

        let node = StructuredNode::While {
            condition: cond,
            body,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("while (i < 0xa)"));
        assert!(output.contains("i = i + 1"));
    }
}
