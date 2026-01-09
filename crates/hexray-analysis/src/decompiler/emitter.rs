//! Pseudo-code emitter.
//!
//! Emits readable pseudo-code from structured control flow.

#![allow(dead_code)]

use super::structurer::{StructuredCfg, StructuredNode};
use super::expression::{Expr, ExprKind};
use super::{StringTable, SymbolTable, RelocationTable};
use std::fmt::Write;

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
                // Default integer formatting
                if *n >= 0 && *n < 10 {
                    format!("{}", n)
                } else if *n < 0 {
                    format!("-{:#x}", -n)
                } else {
                    format!("{:#x}", n)
                }
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
            ExprKind::Assign { lhs, rhs } => {
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
            // For other cases, use default formatting
            _ => expr.to_string(),
        }
    }

    /// Emits pseudo-code for a structured CFG.
    pub fn emit(&self, cfg: &StructuredCfg, func_name: &str) -> String {
        let mut output = String::new();

        // Function header
        writeln!(output, "void {}()", func_name).unwrap();
        writeln!(output, "{{").unwrap();

        // Emit body
        self.emit_nodes(&cfg.body, &mut output, 1);

        writeln!(output, "}}").unwrap();
        output
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
