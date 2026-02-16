//! Variable naming inference.
//!
//! Infers better variable names based on how variables are used in the code.
//! This improves readability by giving meaningful names to temporary variables.

use std::collections::HashMap;

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::structurer::StructuredNode;

/// Naming hints collected from code analysis.
#[derive(Debug, Clone, Default)]
pub struct NamingHints {
    /// Suggested names for variables.
    pub suggestions: HashMap<String, String>,
    /// Usage patterns for variables.
    pub usage_patterns: HashMap<String, Vec<UsagePattern>>,
    /// Track which loop index names have been assigned.
    pub assigned_loop_indices: HashMap<String, String>,
}

/// How a variable is used.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum UsagePattern {
    /// Used as loop counter.
    LoopCounter,
    /// Used as pointer/iterator.
    Iterator,
    /// Used as index into array.
    ArrayIndex,
    /// Used as function argument.
    FunctionArg { func_name: String, arg_index: usize },
    /// Result of function call.
    FunctionResult { func_name: String },
    /// Used in string operation.
    StringOp,
    /// Used as size/count.
    SizeOrCount,
    /// Used as boolean/flag.
    Boolean,
    /// Used in comparison against specific value.
    ComparedTo(i128),
}

/// Analyze nodes and collect naming hints.
pub fn collect_naming_hints(nodes: &[StructuredNode]) -> NamingHints {
    let mut hints = NamingHints::default();

    for node in nodes {
        collect_hints_from_node(node, &mut hints);
    }

    // Generate suggestions based on collected patterns
    generate_suggestions(&mut hints);

    hints
}

/// Collect hints from a single node.
fn collect_hints_from_node(node: &StructuredNode, hints: &mut NamingHints) {
    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                collect_hints_from_expr(stmt, hints);
            }
        }

        StructuredNode::Expr(expr) => {
            collect_hints_from_expr(expr, hints);
        }

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_hints_from_expr(condition, hints);
            for node in then_body {
                collect_hints_from_node(node, hints);
            }
            if let Some(else_body) = else_body {
                for node in else_body {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        StructuredNode::While {
            condition, body, ..
        } => {
            // Variables in while condition might be iterators
            if let Some(var) = extract_iterator_var(condition) {
                add_usage_pattern(hints, &var, UsagePattern::Iterator);
            }
            collect_hints_from_expr(condition, hints);
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            // For loop init variable is likely a counter
            if let Some(init) = init {
                if let Some(var) = extract_assigned_var(init) {
                    add_usage_pattern(hints, &var, UsagePattern::LoopCounter);
                }
                collect_hints_from_expr(init, hints);
            }
            collect_hints_from_expr(condition, hints);
            if let Some(update) = update {
                collect_hints_from_expr(update, hints);
            }
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::DoWhile {
            body, condition, ..
        } => {
            for node in body {
                collect_hints_from_node(node, hints);
            }
            collect_hints_from_expr(condition, hints);
        }

        StructuredNode::Loop { body, .. } => {
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            collect_hints_from_expr(value, hints);
            for (_, case_body) in cases {
                for node in case_body {
                    collect_hints_from_node(node, hints);
                }
            }
            if let Some(default) = default {
                for node in default {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        StructuredNode::Return(Some(expr)) => {
            collect_hints_from_expr(expr, hints);
        }

        StructuredNode::Sequence(nodes) => {
            for node in nodes {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for node in try_body {
                collect_hints_from_node(node, hints);
            }
            for handler in catch_handlers {
                for node in &handler.body {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        _ => {}
    }
}

/// Collect hints from an expression.
fn collect_hints_from_expr(expr: &Expr, hints: &mut NamingHints) {
    match &expr.kind {
        ExprKind::Assign { lhs, rhs } => {
            // Check if rhs is a function call
            if let ExprKind::Call { target, .. } = &rhs.kind {
                if let Some(var) = extract_var_name(lhs) {
                    if let Some(func_name) = get_call_target_name(target) {
                        add_usage_pattern(
                            hints,
                            &var,
                            UsagePattern::FunctionResult {
                                func_name: func_name.to_string(),
                            },
                        );
                    }
                }
            }
            collect_hints_from_expr(lhs, hints);
            collect_hints_from_expr(rhs, hints);
        }

        ExprKind::Call { target, args } => {
            // Track function arguments
            if let Some(func_name) = get_call_target_name(target) {
                for (i, arg) in args.iter().enumerate() {
                    if let Some(var) = extract_var_name(arg) {
                        add_usage_pattern(
                            hints,
                            &var,
                            UsagePattern::FunctionArg {
                                func_name: func_name.to_string(),
                                arg_index: i,
                            },
                        );
                    }
                }

                // Detect string operations
                if is_string_function(func_name) {
                    for arg in args {
                        if let Some(var) = extract_var_name(arg) {
                            add_usage_pattern(hints, &var, UsagePattern::StringOp);
                        }
                    }
                }
            }
        }

        ExprKind::BinOp { op, left, right } => {
            // Check for comparison patterns
            if is_comparison_op(op) {
                if let Some(var) = extract_var_name(left) {
                    if let ExprKind::IntLit(n) = &right.kind {
                        add_usage_pattern(hints, &var, UsagePattern::ComparedTo(*n));
                    }
                }
                if let Some(var) = extract_var_name(right) {
                    if let ExprKind::IntLit(n) = &left.kind {
                        add_usage_pattern(hints, &var, UsagePattern::ComparedTo(*n));
                    }
                }
            }
            collect_hints_from_expr(left, hints);
            collect_hints_from_expr(right, hints);
        }

        ExprKind::ArrayAccess { index, .. } => {
            // Index variable is likely an array index
            if let Some(var) = extract_var_name(index) {
                add_usage_pattern(hints, &var, UsagePattern::ArrayIndex);
            }
        }

        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_hints_from_expr(cond, hints);
            collect_hints_from_expr(then_expr, hints);
            collect_hints_from_expr(else_expr, hints);
        }

        ExprKind::UnaryOp { operand, .. } => {
            collect_hints_from_expr(operand, hints);
        }

        ExprKind::Deref { addr, .. } => {
            collect_hints_from_expr(addr, hints);
        }

        ExprKind::Cast { expr: inner, .. } => {
            collect_hints_from_expr(inner, hints);
        }

        _ => {}
    }
}

/// Extract variable name from expression.
fn extract_var_name(expr: &Expr) -> Option<String> {
    if let ExprKind::Var(v) = &expr.kind {
        return Some(v.name.clone());
    }
    None
}

/// Extract assigned variable from assignment expression.
fn extract_assigned_var(expr: &Expr) -> Option<String> {
    if let ExprKind::Assign { lhs, .. } = &expr.kind {
        return extract_var_name(lhs);
    }
    None
}

/// Extract iterator variable from condition.
fn extract_iterator_var(condition: &Expr) -> Option<String> {
    match &condition.kind {
        ExprKind::BinOp {
            op: BinOpKind::Ne,
            left,
            right,
        }
        | ExprKind::BinOp {
            op: BinOpKind::Lt,
            left,
            right,
        }
        | ExprKind::BinOp {
            op: BinOpKind::Le,
            left,
            right,
        } => {
            // Check for != 0 (NULL check) or < n
            if matches!(right.kind, ExprKind::IntLit(_)) {
                return extract_var_name(left);
            }
            if matches!(left.kind, ExprKind::IntLit(_)) {
                return extract_var_name(right);
            }
            None
        }
        ExprKind::Var(v) => Some(v.name.clone()),
        _ => None,
    }
}

/// Get call target name.
fn get_call_target_name(target: &CallTarget) -> Option<&str> {
    match target {
        CallTarget::Named(name) => Some(name.as_str()),
        _ => None,
    }
}

/// Check if a function is a string operation.
fn is_string_function(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        // String functions
        "strlen"
            | "strcmp"
            | "strncmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strpbrk"
            | "strspn"
            | "strcspn"
            | "strtok"
            | "strtok_r"
            | "strdup"
            | "strndup"
            | "strcasecmp"
            | "strncasecmp"
            | "strsep"
            // Wide string functions
            | "wcslen"
            | "wcscmp"
            | "wcsncmp"
            | "wcscpy"
            | "wcsncpy"
            | "wcscat"
            | "wcsncat"
            | "wcschr"
            | "wcsrchr"
            | "wcsstr"
            // Memory functions
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "memrchr"
            | "memmem"
            | "bzero"
            | "bcopy"
            // Wide memory functions
            | "wmemcpy"
            | "wmemmove"
            | "wmemset"
            | "wmemcmp"
            | "wmemchr"
    ) || lower.starts_with("str")
        || lower.starts_with("wcs")
        || lower.starts_with("mem")
}

/// Check if operator is a comparison.
fn is_comparison_op(op: &BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
    )
}

/// Add a usage pattern for a variable.
fn add_usage_pattern(hints: &mut NamingHints, var: &str, pattern: UsagePattern) {
    hints
        .usage_patterns
        .entry(var.to_string())
        .or_default()
        .push(pattern);
}

/// Generate name suggestions based on collected patterns.
fn generate_suggestions(hints: &mut NamingHints) {
    // First pass: collect loop counters to assign i, j, k, etc.
    let mut loop_counter_vars: Vec<String> = Vec::new();
    for (var, patterns) in &hints.usage_patterns {
        if should_rename(var)
            && patterns
                .iter()
                .any(|p| matches!(p, UsagePattern::LoopCounter))
        {
            loop_counter_vars.push(var.clone());
        }
    }

    // Sort to ensure consistent ordering
    loop_counter_vars.sort();

    // Assign loop indices in order
    static LOOP_INDICES: &[&str] = &[
        "i", "j", "k", "l", "m", "n", "ii", "jj", "kk", "idx", "idx2", "idx3",
    ];
    for (i, var) in loop_counter_vars.iter().enumerate() {
        let index_name = if i < LOOP_INDICES.len() {
            LOOP_INDICES[i].to_string()
        } else {
            format!("i{}", i)
        };
        hints.assigned_loop_indices.insert(var.clone(), index_name);
    }

    // Second pass: generate suggestions
    for (var, patterns) in hints.usage_patterns.clone() {
        // Skip already well-named variables
        if !should_rename(&var) {
            continue;
        }

        if let Some(suggestion) = suggest_name_from_patterns_with_hints(&var, &patterns, hints) {
            hints.suggestions.insert(var, suggestion);
        }
    }
}

/// Check if a variable should be considered for renaming.
fn should_rename(var: &str) -> bool {
    // Rename temporaries and generic register names
    var.starts_with("temp")
        || var.starts_with("tmp")
        || var.starts_with("t_")
        || var.starts_with("v_")
        || var.starts_with("var_")
        || is_generic_register(var)
}

/// Check if name is a generic register name.
fn is_generic_register(var: &str) -> bool {
    let lower = var.to_lowercase();
    // x86 registers
    if matches!(
        lower.as_str(),
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    ) {
        return true;
    }
    // ARM registers
    if lower.starts_with('x') || lower.starts_with('w') {
        if let Some(num_str) = lower.get(1..) {
            if num_str.parse::<u32>().is_ok() {
                return true;
            }
        }
    }
    false
}

/// Suggest a name based on usage patterns (old version for compatibility).
#[allow(dead_code)]
fn suggest_name_from_patterns(original: &str, patterns: &[UsagePattern]) -> Option<String> {
    let hints = NamingHints::default();
    suggest_name_from_patterns_with_hints(original, patterns, &hints)
}

/// Suggest a name based on usage patterns with access to naming hints.
fn suggest_name_from_patterns_with_hints(
    original: &str,
    patterns: &[UsagePattern],
    hints: &NamingHints,
) -> Option<String> {
    // Prioritize certain patterns
    for pattern in patterns {
        match pattern {
            UsagePattern::LoopCounter => {
                // Use assigned loop index if available, otherwise fall back to "i"
                if let Some(assigned) = hints.assigned_loop_indices.get(original) {
                    return Some(assigned.clone());
                }
                return Some("i".to_string());
            }
            UsagePattern::ArrayIndex => {
                // Check if it's also a loop counter
                if patterns
                    .iter()
                    .any(|p| matches!(p, UsagePattern::LoopCounter))
                {
                    if let Some(assigned) = hints.assigned_loop_indices.get(original) {
                        return Some(assigned.clone());
                    }
                }
                return Some("idx".to_string());
            }
            UsagePattern::Iterator => return Some("iter".to_string()),
            UsagePattern::StringOp => return Some("str".to_string()),
            UsagePattern::SizeOrCount => return Some("size".to_string()),
            UsagePattern::Boolean => return Some("flag".to_string()),
            UsagePattern::FunctionResult { func_name } => {
                if let Some(name) = suggest_from_function_result(func_name) {
                    return Some(name);
                }
            }
            UsagePattern::FunctionArg {
                func_name,
                arg_index,
            } => {
                if let Some(name) = suggest_from_function_arg(func_name, *arg_index) {
                    return Some(name);
                }
            }
            UsagePattern::ComparedTo(0) => {
                // Compared to 0 might be a pointer or boolean
                if original.starts_with('p') || original.contains("ptr") {
                    return Some("ptr".to_string());
                }
            }
            UsagePattern::ComparedTo(-1) => {
                // Often an error check (read/write return -1 on error)
                return Some("result".to_string());
            }
            _ => {}
        }
    }

    None
}

/// Suggest a name based on function result.
fn suggest_from_function_result(func_name: &str) -> Option<String> {
    match func_name.to_lowercase().as_str() {
        // String/memory length
        "strlen" | "wcslen" => Some("len".to_string()),
        // Memory allocation
        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "memalign" => Some("ptr".to_string()),
        // File descriptors
        "open" | "creat" => Some("fd".to_string()),
        "fopen" | "freopen" | "fdopen" | "tmpfile" => Some("file".to_string()),
        "opendir" => Some("dir".to_string()),
        "socket" => Some("sock".to_string()),
        "accept" => Some("client_fd".to_string()),
        "pipe" => Some("pipe_fd".to_string()),
        "dup" | "dup2" | "dup3" => Some("new_fd".to_string()),
        // I/O sizes
        "read" | "pread" | "pread64" => Some("bytes_read".to_string()),
        "write" | "pwrite" | "pwrite64" => Some("bytes_written".to_string()),
        "recv" | "recvfrom" | "recvmsg" => Some("bytes_recv".to_string()),
        "send" | "sendto" | "sendmsg" => Some("bytes_sent".to_string()),
        "fread" => Some("items_read".to_string()),
        "fwrite" => Some("items_written".to_string()),
        // Character I/O
        "getchar" | "fgetc" | "getc" | "getc_unlocked" => Some("ch".to_string()),
        "getline" | "getdelim" => Some("line_len".to_string()),
        // Comparisons
        "strcmp" | "strncmp" | "memcmp" | "strcasecmp" | "strncasecmp" | "wcscmp" | "wcsncmp" => {
            Some("cmp_result".to_string())
        }
        // String search
        "strchr" | "strrchr" | "strstr" | "strpbrk" | "wcschr" | "wcsrchr" | "wcsstr" => {
            Some("found".to_string())
        }
        "memmem" | "memchr" | "memrchr" => Some("match".to_string()),
        "bsearch" => Some("found_elem".to_string()),
        // String conversion
        "atoi" | "atol" | "atoll" => Some("num".to_string()),
        "strtol" | "strtoll" | "strtoimax" => Some("value".to_string()),
        "strtoul" | "strtoull" | "strtoumax" => Some("uvalue".to_string()),
        "strtof" | "strtod" | "strtold" | "atof" => Some("fvalue".to_string()),
        // String manipulation
        "strdup" | "strndup" => Some("dup_str".to_string()),
        "strtok" | "strtok_r" | "strsep" => Some("token".to_string()),
        // Memory mapping
        "mmap" | "mmap64" => Some("mapped".to_string()),
        // Process/thread
        "fork" | "vfork" => Some("pid".to_string()),
        "pthread_create" => Some("thread_result".to_string()),
        "getpid" | "getppid" => Some("pid".to_string()),
        "gettid" => Some("tid".to_string()),
        "wait" | "waitpid" | "wait3" | "wait4" => Some("child_pid".to_string()),
        // Time
        "time" => Some("timestamp".to_string()),
        "clock" | "clock_gettime" => Some("ticks".to_string()),
        // Environment
        "getenv" => Some("env_val".to_string()),
        // Error handling
        "errno" | "__errno_location" => Some("err".to_string()),
        "strerror" | "strerror_r" => Some("err_msg".to_string()),
        "perror" => Some("err_result".to_string()),
        // Math functions
        "abs" | "labs" | "llabs" | "fabs" | "fabsf" => Some("abs_val".to_string()),
        "sqrt" | "sqrtf" | "sqrtl" => Some("root".to_string()),
        "pow" | "powf" | "powl" => Some("power".to_string()),
        "floor" | "floorf" | "floorl" => Some("floored".to_string()),
        "ceil" | "ceilf" | "ceill" => Some("ceiled".to_string()),
        "round" | "roundf" | "roundl" => Some("rounded".to_string()),
        "sin" | "sinf" | "sinl" | "cos" | "cosf" | "cosl" | "tan" | "tanf" | "tanl" => {
            Some("trig".to_string())
        }
        "log" | "logf" | "logl" | "log10" | "log2" => Some("logarithm".to_string()),
        "exp" | "expf" | "expl" | "exp2" => Some("exponential".to_string()),
        // Random
        "rand" | "random" | "lrand48" | "mrand48" => Some("random_val".to_string()),
        // Networking
        "inet_addr" | "inet_aton" => Some("ip_addr".to_string()),
        "htons" | "htonl" | "ntohs" | "ntohl" => Some("converted".to_string()),
        "gethostbyname" | "gethostbyaddr" => Some("host".to_string()),
        "getaddrinfo" => Some("addr_result".to_string()),
        _ => None,
    }
}

/// Suggest a name based on function argument position.
fn suggest_from_function_arg(func_name: &str, arg_index: usize) -> Option<String> {
    match (func_name.to_lowercase().as_str(), arg_index) {
        // Copy operations - dest/src pattern
        (
            "strcpy" | "strncpy" | "memcpy" | "memmove" | "wcscpy" | "wcsncpy" | "wmemcpy"
            | "wmemmove",
            0,
        ) => Some("dst".to_string()),
        (
            "strcpy" | "strncpy" | "memcpy" | "memmove" | "wcscpy" | "wcsncpy" | "wmemcpy"
            | "wmemmove",
            1,
        ) => Some("src".to_string()),
        // Size/length arguments
        (
            "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "wmemcpy" | "wmemmove"
            | "wmemset" | "wcsncpy" | "wcsncat",
            2,
        ) => Some("n".to_string()),
        ("strncmp" | "memcmp" | "wcsncmp" | "wmemcmp", 2) => Some("n".to_string()),
        // String comparison
        (
            "strcmp" | "strncmp" | "memcmp" | "strcasecmp" | "strncasecmp" | "wcscmp" | "wcsncmp",
            0 | 1,
        ) => Some("str".to_string()),
        // String operations
        (
            "strlen" | "strchr" | "strrchr" | "strdup" | "strndup" | "wcslen" | "wcschr"
            | "wcsrchr",
            0,
        ) => Some("str".to_string()),
        ("strstr", 0) => Some("haystack".to_string()),
        ("strstr", 1) => Some("needle".to_string()),
        ("strtok" | "strtok_r", 0) => Some("str".to_string()),
        ("strtok" | "strtok_r", 1) => Some("delim".to_string()),
        // String concatenation
        ("strcat" | "strncat" | "wcscat" | "wcsncat", 0) => Some("dst".to_string()),
        ("strcat" | "strncat" | "wcscat" | "wcsncat", 1) => Some("src".to_string()),
        // Character search
        ("strchr" | "strrchr" | "memchr" | "memrchr" | "wcschr" | "wcsrchr", 1) => {
            Some("ch".to_string())
        }
        // Printf family
        ("printf" | "wprintf", 0) => Some("fmt".to_string()),
        ("fprintf" | "fwprintf", 0) => Some("stream".to_string()),
        ("fprintf" | "fwprintf", 1) => Some("fmt".to_string()),
        ("sprintf" | "swprintf", 0) => Some("buf".to_string()),
        ("sprintf" | "swprintf", 1) => Some("fmt".to_string()),
        ("snprintf" | "snwprintf", 0) => Some("buf".to_string()),
        ("snprintf" | "snwprintf", 1) => Some("size".to_string()),
        ("snprintf" | "snwprintf", 2) => Some("fmt".to_string()),
        // Scanf family
        ("scanf" | "wscanf", 0) => Some("fmt".to_string()),
        ("fscanf" | "fwscanf", 0) => Some("stream".to_string()),
        ("fscanf" | "fwscanf", 1) => Some("fmt".to_string()),
        ("sscanf" | "swscanf", 0) => Some("str".to_string()),
        ("sscanf" | "swscanf", 1) => Some("fmt".to_string()),
        // Memory allocation
        ("malloc" | "aligned_alloc", 0) => Some("size".to_string()),
        ("calloc", 0) => Some("count".to_string()),
        ("calloc", 1) => Some("size".to_string()),
        ("realloc", 0) => Some("ptr".to_string()),
        ("realloc", 1) => Some("new_size".to_string()),
        ("free", 0) => Some("ptr".to_string()),
        // Memory operations
        ("memset" | "wmemset", 0) => Some("ptr".to_string()),
        ("memset", 1) => Some("value".to_string()),
        ("bzero", 0) => Some("ptr".to_string()),
        ("bzero", 1) => Some("n".to_string()),
        // File I/O
        ("fopen" | "freopen", 0) => Some("filename".to_string()),
        ("fopen" | "freopen", 1) => Some("mode".to_string()),
        ("fread" | "fwrite", 0) => Some("buf".to_string()),
        ("fread" | "fwrite", 1) => Some("size".to_string()),
        ("fread" | "fwrite", 2) => Some("count".to_string()),
        ("fread" | "fwrite", 3) => Some("stream".to_string()),
        ("fgets", 0) => Some("buf".to_string()),
        ("fgets", 1) => Some("size".to_string()),
        ("fgets", 2) => Some("stream".to_string()),
        ("fputs", 0) => Some("str".to_string()),
        ("fputs", 1) => Some("stream".to_string()),
        ("fclose" | "fflush" | "feof" | "ferror" | "fileno", 0) => Some("stream".to_string()),
        ("fseek" | "fseeko", 0) => Some("stream".to_string()),
        ("fseek" | "fseeko", 1) => Some("offset".to_string()),
        ("fseek" | "fseeko", 2) => Some("whence".to_string()),
        // POSIX file I/O
        ("open", 0) => Some("pathname".to_string()),
        ("open", 1) => Some("flags".to_string()),
        ("open", 2) => Some("mode".to_string()),
        ("close", 0) => Some("fd".to_string()),
        ("read" | "write", 0) => Some("fd".to_string()),
        ("read" | "write", 1) => Some("buf".to_string()),
        ("read" | "write", 2) => Some("count".to_string()),
        ("lseek" | "lseek64", 0) => Some("fd".to_string()),
        ("lseek" | "lseek64", 1) => Some("offset".to_string()),
        ("lseek" | "lseek64", 2) => Some("whence".to_string()),
        ("ioctl", 0) => Some("fd".to_string()),
        ("ioctl", 1) => Some("request".to_string()),
        // Socket operations
        ("socket", 0) => Some("domain".to_string()),
        ("socket", 1) => Some("type".to_string()),
        ("socket", 2) => Some("protocol".to_string()),
        ("bind" | "connect", 0) => Some("sockfd".to_string()),
        ("bind" | "connect", 1) => Some("addr".to_string()),
        ("bind" | "connect", 2) => Some("addrlen".to_string()),
        ("listen", 0) => Some("sockfd".to_string()),
        ("listen", 1) => Some("backlog".to_string()),
        ("accept", 0) => Some("sockfd".to_string()),
        ("accept", 1) => Some("addr".to_string()),
        ("accept", 2) => Some("addrlen".to_string()),
        ("send" | "recv", 0) => Some("sockfd".to_string()),
        ("send" | "recv", 1) => Some("buf".to_string()),
        ("send" | "recv", 2) => Some("len".to_string()),
        ("send" | "recv", 3) => Some("flags".to_string()),
        ("setsockopt" | "getsockopt", 0) => Some("sockfd".to_string()),
        ("setsockopt" | "getsockopt", 1) => Some("level".to_string()),
        ("setsockopt" | "getsockopt", 2) => Some("optname".to_string()),
        // Memory mapping
        ("mmap", 0) => Some("addr".to_string()),
        ("mmap", 1) => Some("length".to_string()),
        ("mmap", 2) => Some("prot".to_string()),
        ("mmap", 3) => Some("flags".to_string()),
        ("mmap", 4) => Some("fd".to_string()),
        ("mmap", 5) => Some("offset".to_string()),
        ("munmap" | "mprotect", 0) => Some("addr".to_string()),
        ("munmap" | "mprotect", 1) => Some("length".to_string()),
        ("mprotect", 2) => Some("prot".to_string()),
        // Thread operations
        ("pthread_create", 0) => Some("thread".to_string()),
        ("pthread_create", 1) => Some("attr".to_string()),
        ("pthread_create", 2) => Some("start_routine".to_string()),
        ("pthread_create", 3) => Some("arg".to_string()),
        ("pthread_join", 0) => Some("thread".to_string()),
        ("pthread_join", 1) => Some("retval".to_string()),
        ("pthread_mutex_lock" | "pthread_mutex_unlock" | "pthread_mutex_trylock", 0) => {
            Some("mutex".to_string())
        }
        // Process operations
        ("execve" | "execv", 0) => Some("pathname".to_string()),
        ("execve", 1) | ("execv", 1) => Some("argv".to_string()),
        ("execve", 2) => Some("envp".to_string()),
        ("waitpid", 0) => Some("pid".to_string()),
        ("waitpid", 1) => Some("status".to_string()),
        ("waitpid", 2) => Some("options".to_string()),
        ("kill", 0) => Some("pid".to_string()),
        ("kill", 1) => Some("sig".to_string()),
        // Signal handling
        ("signal" | "sigaction", 0) => Some("signum".to_string()),
        ("signal", 1) => Some("handler".to_string()),
        ("sigaction", 1) => Some("act".to_string()),
        ("sigaction", 2) => Some("oldact".to_string()),
        // Error handling
        ("strerror", 0) => Some("errnum".to_string()),
        ("perror", 0) => Some("msg".to_string()),
        // qsort/bsearch
        ("qsort", 0) => Some("base".to_string()),
        ("bsearch", 0) => Some("key".to_string()),
        ("bsearch", 1) => Some("base".to_string()),
        ("qsort", 1) | ("bsearch", 2) => Some("num".to_string()),
        ("qsort", 2) | ("bsearch", 3) => Some("size".to_string()),
        ("qsort", 3) | ("bsearch", 4) => Some("compar".to_string()),
        _ => None,
    }
}

/// Reserved names that shouldn't be used for local variables.
/// These are common libc globals that would shadow important symbols.
const RESERVED_VARIABLE_NAMES: &[&str] = &[
    "stdin",
    "stdout",
    "stderr",
    "errno",
    "optarg",
    "optind",
    "opterr",
    "optopt",
    "environ",
    "tzname",
    "daylight",
    "timezone",
    "signgam",
    "getdate_err",
    "h_errno",
    "program_invocation_name",
    "program_invocation_short_name",
];

/// Checks if a name is a reserved global name that shouldn't be used for variables.
fn is_reserved_name(name: &str) -> bool {
    RESERVED_VARIABLE_NAMES.contains(&name)
}

/// Generates a safe alternative name for a reserved name.
fn safe_name_for_reserved(name: &str) -> String {
    match name {
        "stdin" | "stdout" | "stderr" => "result".to_string(),
        "errno" => "err_code".to_string(),
        "optarg" | "optind" | "opterr" | "optopt" => format!("{}_val", name),
        _ => format!("{}_var", name),
    }
}

/// Analyzes nodes and applies suggested variable names.
///
/// This is the main entry point for the variable naming pass.
pub fn suggest_variable_names(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let hints = collect_naming_hints(&nodes);
    let nodes = apply_naming_hints(nodes, &hints);
    // Final pass: rename any variables that have reserved names
    rename_reserved_variables(nodes)
}

/// Renames variables that use reserved names (libc globals).
fn rename_reserved_variables(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(rename_reserved_in_node).collect()
}

fn rename_reserved_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: statements
                .into_iter()
                .map(rename_reserved_in_expr)
                .collect(),
            address_range,
        },
        StructuredNode::Expr(expr) => StructuredNode::Expr(rename_reserved_in_expr(expr)),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: rename_reserved_in_expr(condition),
            then_body: rename_reserved_variables(then_body),
            else_body: else_body.map(rename_reserved_variables),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: rename_reserved_in_expr(condition),
            body: rename_reserved_variables(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: rename_reserved_variables(body),
            condition: rename_reserved_in_expr(condition),
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
            init: init.map(rename_reserved_in_expr),
            condition: rename_reserved_in_expr(condition),
            update: update.map(rename_reserved_in_expr),
            body: rename_reserved_variables(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: rename_reserved_variables(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: rename_reserved_in_expr(value),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, rename_reserved_variables(body)))
                .collect(),
            default: default.map(rename_reserved_variables),
        },
        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(rename_reserved_in_expr(expr)))
        }
        StructuredNode::Sequence(seq) => StructuredNode::Sequence(rename_reserved_variables(seq)),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: rename_reserved_variables(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: rename_reserved_variables(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn rename_reserved_in_expr(expr: Expr) -> Expr {
    use super::expression::Variable;

    let kind = match expr.kind {
        ExprKind::Var(ref v) if is_reserved_name(&v.name) => {
            let new_name = safe_name_for_reserved(&v.name);
            ExprKind::Var(Variable {
                name: new_name,
                kind: v.kind.clone(),
                size: v.size,
            })
        }
        ExprKind::BinOp { op, left, right } => ExprKind::BinOp {
            op,
            left: Box::new(rename_reserved_in_expr(*left)),
            right: Box::new(rename_reserved_in_expr(*right)),
        },
        ExprKind::UnaryOp { op, operand } => ExprKind::UnaryOp {
            op,
            operand: Box::new(rename_reserved_in_expr(*operand)),
        },
        ExprKind::Deref { addr, size } => ExprKind::Deref {
            addr: Box::new(rename_reserved_in_expr(*addr)),
            size,
        },
        ExprKind::AddressOf(inner) => {
            ExprKind::AddressOf(Box::new(rename_reserved_in_expr(*inner)))
        }
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => ExprKind::Cast {
            expr: Box::new(rename_reserved_in_expr(*inner)),
            to_size,
            signed,
        },
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => ExprKind::ArrayAccess {
            base: Box::new(rename_reserved_in_expr(*base)),
            index: Box::new(rename_reserved_in_expr(*index)),
            element_size,
        },
        ExprKind::Assign { lhs, rhs } => ExprKind::Assign {
            lhs: Box::new(rename_reserved_in_expr(*lhs)),
            rhs: Box::new(rename_reserved_in_expr(*rhs)),
        },
        ExprKind::CompoundAssign { op, lhs, rhs } => ExprKind::CompoundAssign {
            op,
            lhs: Box::new(rename_reserved_in_expr(*lhs)),
            rhs: Box::new(rename_reserved_in_expr(*rhs)),
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => ExprKind::Conditional {
            cond: Box::new(rename_reserved_in_expr(*cond)),
            then_expr: Box::new(rename_reserved_in_expr(*then_expr)),
            else_expr: Box::new(rename_reserved_in_expr(*else_expr)),
        },
        ExprKind::Call { target, args } => ExprKind::Call {
            target,
            args: args.into_iter().map(rename_reserved_in_expr).collect(),
        },
        other => other,
    };

    Expr { kind }
}

/// Apply naming suggestions to nodes.
pub fn apply_naming_hints(nodes: Vec<StructuredNode>, hints: &NamingHints) -> Vec<StructuredNode> {
    if hints.suggestions.is_empty() {
        return nodes;
    }

    nodes
        .into_iter()
        .map(|node| apply_hints_to_node(node, hints))
        .collect()
}

fn apply_hints_to_node(node: StructuredNode, hints: &NamingHints) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: statements
                .into_iter()
                .map(|e| apply_hints_to_expr(e, hints))
                .collect(),
            address_range,
        },

        StructuredNode::Expr(expr) => StructuredNode::Expr(apply_hints_to_expr(expr, hints)),

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: apply_hints_to_expr(condition, hints),
            then_body: apply_naming_hints(then_body, hints),
            else_body: else_body.map(|e| apply_naming_hints(e, hints)),
        },

        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: apply_hints_to_expr(condition, hints),
            body: apply_naming_hints(body, hints),
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
            init: init.map(|e| apply_hints_to_expr(e, hints)),
            condition: apply_hints_to_expr(condition, hints),
            update: update.map(|e| apply_hints_to_expr(e, hints)),
            body: apply_naming_hints(body, hints),
            header,
            exit_block,
        },

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: apply_naming_hints(body, hints),
            condition: apply_hints_to_expr(condition, hints),
            header,
            exit_block,
        },

        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: apply_naming_hints(body, hints),
            header,
            exit_block,
        },

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: apply_hints_to_expr(value, hints),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, apply_naming_hints(body, hints)))
                .collect(),
            default: default.map(|d| apply_naming_hints(d, hints)),
        },

        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(apply_hints_to_expr(expr, hints)))
        }

        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(apply_naming_hints(nodes, hints))
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: apply_naming_hints(try_body, hints),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: apply_naming_hints(h.body, hints),
                    ..h
                })
                .collect(),
        },

        other => other,
    }
}

fn apply_hints_to_expr(expr: Expr, hints: &NamingHints) -> Expr {
    match expr.kind {
        ExprKind::Var(mut v) => {
            if let Some(new_name) = hints.suggestions.get(&v.name) {
                v.name = new_name.clone();
            }
            Expr::var(v)
        }

        ExprKind::Assign { lhs, rhs } => Expr::assign(
            apply_hints_to_expr(*lhs, hints),
            apply_hints_to_expr(*rhs, hints),
        ),

        ExprKind::BinOp { op, left, right } => Expr::binop(
            op,
            apply_hints_to_expr(*left, hints),
            apply_hints_to_expr(*right, hints),
        ),

        ExprKind::UnaryOp { op, operand } => Expr::unary(op, apply_hints_to_expr(*operand, hints)),

        ExprKind::Call { target, args } => Expr::call(
            target,
            args.into_iter()
                .map(|a| apply_hints_to_expr(a, hints))
                .collect(),
        ),

        ExprKind::Deref { addr, size } => Expr::deref(apply_hints_to_expr(*addr, hints), size),

        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            apply_hints_to_expr(*base, hints),
            apply_hints_to_expr(*index, hints),
            element_size,
        ),

        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(apply_hints_to_expr(*base, hints), field_name, offset),

        ExprKind::Cast {
            expr,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(apply_hints_to_expr(*expr, hints)),
                to_size,
                signed,
            },
        },

        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(apply_hints_to_expr(*cond, hints)),
                then_expr: Box::new(apply_hints_to_expr(*then_expr, hints)),
                else_expr: Box::new(apply_hints_to_expr(*else_expr, hints)),
            },
        },

        _ => expr,
    }
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
    fn test_should_rename() {
        assert!(should_rename("temp0"));
        assert!(should_rename("tmp_val"));
        assert!(should_rename("var_8"));
        assert!(should_rename("eax"));
        assert!(should_rename("x0"));

        assert!(!should_rename("size"));
        assert!(!should_rename("count"));
        assert!(!should_rename("ptr"));
    }

    #[test]
    fn test_suggest_from_function_result() {
        assert_eq!(
            suggest_from_function_result("strlen"),
            Some("len".to_string())
        );
        assert_eq!(
            suggest_from_function_result("malloc"),
            Some("ptr".to_string())
        );
        assert_eq!(suggest_from_function_result("open"), Some("fd".to_string()));
        // New additions
        assert_eq!(
            suggest_from_function_result("fopen"),
            Some("file".to_string())
        );
        assert_eq!(
            suggest_from_function_result("fork"),
            Some("pid".to_string())
        );
        assert_eq!(
            suggest_from_function_result("read"),
            Some("bytes_read".to_string())
        );
        assert_eq!(
            suggest_from_function_result("socket"),
            Some("sock".to_string())
        );
        assert_eq!(
            suggest_from_function_result("accept"),
            Some("client_fd".to_string())
        );
        assert_eq!(
            suggest_from_function_result("getenv"),
            Some("env_val".to_string())
        );
        assert_eq!(
            suggest_from_function_result("sqrt"),
            Some("root".to_string())
        );
    }

    #[test]
    fn test_suggest_from_function_arg() {
        assert_eq!(
            suggest_from_function_arg("strcpy", 0),
            Some("dst".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("strcpy", 1),
            Some("src".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("memcpy", 2),
            Some("n".to_string())
        );
        // New additions
        assert_eq!(
            suggest_from_function_arg("socket", 0),
            Some("domain".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("mmap", 1),
            Some("length".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("pthread_create", 2),
            Some("start_routine".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("fread", 3),
            Some("stream".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("snprintf", 1),
            Some("size".to_string())
        );
    }

    #[test]
    fn test_is_string_function() {
        assert!(is_string_function("strlen"));
        assert!(is_string_function("strcpy"));
        assert!(is_string_function("memcpy"));
        assert!(is_string_function("strdup"));
        assert!(is_string_function("wcslen"));
        assert!(is_string_function("wmemcpy"));
        // Generic prefix matching
        assert!(is_string_function("strtok_r"));
        assert!(is_string_function("memrchr"));
    }

    #[test]
    fn test_collect_hints_from_loop() {
        let init = Expr::assign(make_var("temp0"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("temp0"), make_var("n"));
        let update = Expr::assign(
            make_var("temp0"),
            Expr::binop(BinOpKind::Add, make_var("temp0"), Expr::int(1)),
        );

        let for_loop = StructuredNode::For {
            init: Some(init),
            condition,
            update: Some(update),
            body: vec![],
            header: Some(hexray_core::BasicBlockId::new(0)),
            exit_block: None,
        };

        let hints = collect_naming_hints(&[for_loop]);

        assert!(hints.usage_patterns.contains_key("temp0"));
        let patterns = &hints.usage_patterns["temp0"];
        assert!(patterns
            .iter()
            .any(|p| matches!(p, UsagePattern::LoopCounter)));
    }

    #[test]
    fn test_multiple_loop_indices() {
        // Create two nested for loops with different variables
        let inner_init = Expr::assign(make_var("temp1"), Expr::int(0));
        let inner_condition = Expr::binop(BinOpKind::Lt, make_var("temp1"), make_var("m"));
        let inner_update = Expr::assign(
            make_var("temp1"),
            Expr::binop(BinOpKind::Add, make_var("temp1"), Expr::int(1)),
        );

        let inner_loop = StructuredNode::For {
            init: Some(inner_init),
            condition: inner_condition,
            update: Some(inner_update),
            body: vec![],
            header: Some(hexray_core::BasicBlockId::new(1)),
            exit_block: None,
        };

        let outer_init = Expr::assign(make_var("temp0"), Expr::int(0));
        let outer_condition = Expr::binop(BinOpKind::Lt, make_var("temp0"), make_var("n"));
        let outer_update = Expr::assign(
            make_var("temp0"),
            Expr::binop(BinOpKind::Add, make_var("temp0"), Expr::int(1)),
        );

        let outer_loop = StructuredNode::For {
            init: Some(outer_init),
            condition: outer_condition,
            update: Some(outer_update),
            body: vec![inner_loop],
            header: Some(hexray_core::BasicBlockId::new(0)),
            exit_block: None,
        };

        let hints = collect_naming_hints(&[outer_loop]);

        // Both variables should be identified as loop counters
        assert!(hints.usage_patterns.contains_key("temp0"));
        assert!(hints.usage_patterns.contains_key("temp1"));

        // They should get different index names (i and j)
        assert!(hints.assigned_loop_indices.contains_key("temp0"));
        assert!(hints.assigned_loop_indices.contains_key("temp1"));

        // Verify they're different
        let idx0 = hints.assigned_loop_indices.get("temp0").unwrap();
        let idx1 = hints.assigned_loop_indices.get("temp1").unwrap();
        assert_ne!(idx0, idx1);
    }

    #[test]
    fn test_reserved_name_renaming() {
        // Create a simple expression using the reserved name "stdin"
        let stdin_var = make_var("stdin");
        let comparison = Expr::binop(BinOpKind::Le, stdin_var, Expr::int(107));

        // Create a condition using the comparison
        let if_node = StructuredNode::If {
            condition: comparison,
            then_body: vec![],
            else_body: None,
        };

        // Apply the full naming pass
        let result = suggest_variable_names(vec![if_node]);

        // Extract the condition from the result
        if let StructuredNode::If { condition, .. } = &result[0] {
            // The variable named "stdin" should be renamed to "result"
            if let ExprKind::BinOp { left, .. } = &condition.kind {
                if let ExprKind::Var(v) = &left.kind {
                    assert_eq!(v.name, "result", "stdin should be renamed to result");
                } else {
                    panic!("Expected Var on left side of comparison");
                }
            } else {
                panic!("Expected BinOp condition");
            }
        } else {
            panic!("Expected If node");
        }
    }
}
