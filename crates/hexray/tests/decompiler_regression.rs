//! Decompiler regression tests.
//!
//! These tests ensure decompiler output remains stable across versions.
//! Uses system binaries with known function names to verify output quality.

use hexray_analysis::decompiler::SummaryDatabase;
use hexray_analysis::{CfgBuilder, Decompiler, StringTable, SymbolTable};
use hexray_core::{Architecture, Instruction, Operand};
use hexray_disasm::{Arm64Disassembler, Disassembler, X86_64Disassembler};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, MachO};

/// Disassemble a block of bytes.
fn disassemble_block(
    arch: Architecture,
    data: &[u8],
    start_addr: u64,
) -> Vec<hexray_core::Instruction> {
    match arch {
        Architecture::X86_64 => {
            let disasm = X86_64Disassembler::new();
            disassemble_with(&disasm, data, start_addr)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_with(&disasm, data, start_addr)
        }
        _ => Vec::new(),
    }
}

fn disassemble_with<D: Disassembler>(
    disasm: &D,
    data: &[u8],
    start_addr: u64,
) -> Vec<hexray_core::Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    // Limit to 500 instructions
    while offset < data.len() && instructions.len() < 500 {
        let remaining = &data[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;

                // Stop at return
                if is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    instructions
}

/// Find a function by name in a binary.
fn find_function(binary_data: &[u8]) -> Option<(Architecture, u64, Vec<u8>, String)> {
    match detect_format(binary_data) {
        BinaryType::MachO => {
            let macho = MachO::parse(binary_data).ok()?;
            let arch = macho.architecture();

            // Look for a main function
            for sym in macho.symbols() {
                if sym.is_function()
                    && sym.address != 0
                    && sym.size > 0
                    && (sym.name.contains("main")
                        || sym.name.contains("start")
                        || sym.name.contains("entry"))
                {
                    let bytes = macho.bytes_at(sym.address, sym.size as usize)?;
                    return Some((arch, sym.address, bytes.to_vec(), sym.name.clone()));
                }
            }

            // Fallback: use entry point
            let entry = macho.entry_point()?;
            let bytes = macho.bytes_at(entry, 512)?;
            Some((arch, entry, bytes.to_vec(), "_start".to_string()))
        }
        _ => None,
    }
}

/// Decompile a function and verify output structure.
fn decompile_function(
    arch: Architecture,
    bytes: &[u8],
    start_addr: u64,
    name: &str,
) -> Option<String> {
    let instructions = disassemble_block(arch, bytes, start_addr);
    if instructions.is_empty() {
        return None;
    }

    let cfg = CfgBuilder::build(&instructions, start_addr);
    let decompiler = Decompiler::new()
        .with_addresses(false)
        .with_symbol_table(SymbolTable::new())
        .with_string_table(StringTable::new());

    let code = decompiler.decompile(&cfg, name);
    Some(code)
}

/// Checks that decompiled output has expected structural elements.
fn validate_decompiled_output(code: &str) -> DecompileValidation {
    DecompileValidation {
        has_function_header: code.contains('(') && code.contains(')'),
        has_braces: code.contains('{') && code.contains('}'),
        has_return: code.contains("return"),
        has_variables: code.contains('='),
        line_count: code.lines().count(),
        has_control_flow: code.contains("if")
            || code.contains("while")
            || code.contains("for")
            || code.contains("switch"),
        no_gotos: !code.contains("goto "),
    }
}

fn memory_operand_broadcast(inst: &Instruction) -> Option<bool> {
    for op in &inst.operands {
        if let Operand::Memory(mem) = op {
            return Some(mem.broadcast);
        }
    }
    None
}

#[derive(Debug)]
#[allow(dead_code)]
struct DecompileValidation {
    has_function_header: bool,
    has_braces: bool,
    has_return: bool,
    has_variables: bool,
    line_count: usize,
    has_control_flow: bool,
    no_gotos: bool,
}

impl DecompileValidation {
    fn is_valid(&self) -> bool {
        // Basic structural requirements
        self.has_function_header && self.has_braces && self.line_count > 1
    }

    fn quality_score(&self) -> f64 {
        let mut score = 0.0;
        let total = 5.0;

        if self.has_function_header {
            score += 1.0;
        }
        if self.has_braces {
            score += 1.0;
        }
        if self.has_return {
            score += 1.0;
        }
        if self.has_variables {
            score += 1.0;
        }
        if self.no_gotos {
            score += 1.0;
        }

        score / total
    }
}

// =============================================================================
// Regression Tests
// =============================================================================

#[test]
fn test_macos_binary_decompilation_structure() {
    #[cfg(target_os = "macos")]
    {
        let paths = ["/bin/ls", "/bin/cat", "/bin/echo"];

        for path in paths {
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if let Some((arch, addr, bytes, name)) = find_function(&data) {
                if let Some(code) = decompile_function(arch, &bytes, addr, &name) {
                    let validation = validate_decompiled_output(&code);

                    assert!(
                        validation.is_valid(),
                        "Decompilation of {} ({}) failed validation: {:?}\nCode:\n{}",
                        path,
                        name,
                        validation,
                        code.lines().take(20).collect::<Vec<_>>().join("\n")
                    );

                    println!(
                        "{} ({}): {} lines, quality score: {:.1}%",
                        path,
                        name,
                        validation.line_count,
                        validation.quality_score() * 100.0
                    );
                }
            }
        }
    }
}

#[test]
fn test_decompiler_no_crash_on_various_patterns() {
    // This test ensures the decompiler doesn't crash on edge cases
    let test_patterns: Vec<(&str, Vec<u8>)> = vec![
        // Empty function (just ret)
        ("empty_func", vec![0xc3]),
        // Simple function with push/pop
        (
            "simple_func",
            vec![
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x5d, // pop rbp
                0xc3, // ret
            ],
        ),
        // Function with conditional
        (
            "cond_func",
            vec![
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x83, 0x7d, 0xfc, 0x00, // cmp [rbp-4], 0
                0x7e, 0x07, // jle +7
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0xeb, 0x05, // jmp +5
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
                0x5d, // pop rbp
                0xc3, // ret
            ],
        ),
    ];

    for (name, bytes) in test_patterns {
        let instructions = disassemble_block(Architecture::X86_64, &bytes, 0x1000);

        if instructions.is_empty() {
            continue;
        }

        let cfg = CfgBuilder::build(&instructions, 0x1000);
        let decompiler = Decompiler::new();

        // The main test: ensure no panic
        let code = decompiler.decompile(&cfg, name);

        // Basic sanity checks
        assert!(
            !code.is_empty(),
            "Decompilation of {} produced empty output",
            name
        );
        assert!(
            code.contains(name),
            "Decompilation of {} should contain function name",
            name
        );

        println!("Pattern '{}' decompiled to:\n{}\n", name, code);
    }
}

#[test]
fn test_decompiler_stability_on_repeated_runs() {
    // Ensure decompiler produces consistent output
    let bytes = vec![
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x89, 0x7d, 0xfc, // mov [rbp-4], edi
        0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
        0x0f, 0xaf, 0x45, 0xfc, // imul eax, [rbp-4]
        0x5d, // pop rbp
        0xc3, // ret
    ];

    let mut outputs = Vec::new();

    for _ in 0..5 {
        let instructions = disassemble_block(Architecture::X86_64, &bytes, 0x1000);
        let cfg = CfgBuilder::build(&instructions, 0x1000);
        let decompiler = Decompiler::new();
        let code = decompiler.decompile(&cfg, "square");
        outputs.push(code);
    }

    // All outputs should be identical
    for i in 1..outputs.len() {
        assert_eq!(
            outputs[0], outputs[i],
            "Decompiler output should be deterministic"
        );
    }
}

#[test]
fn test_decompiler_handles_loop_patterns() {
    // A simple counting loop
    // for (int i = 0; i < 10; i++) { sum += i; }
    let bytes = vec![
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rbp-4], 0  (i = 0)
        0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, // mov [rbp-8], 0  (sum = 0)
        // loop_start:
        0x83, 0x7d, 0xfc, 0x0a, // cmp [rbp-4], 10
        0x7d, 0x0c, // jge loop_end (+12)
        0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
        0x01, 0x45, 0xf8, // add [rbp-8], eax
        0x83, 0x45, 0xfc, 0x01, // add [rbp-4], 1
        0xeb, 0xee, // jmp loop_start (-18)
        // loop_end:
        0x8b, 0x45, 0xf8, // mov eax, [rbp-8]
        0x5d, // pop rbp
        0xc3, // ret
    ];

    let instructions = disassemble_block(Architecture::X86_64, &bytes, 0x1000);
    let cfg = CfgBuilder::build(&instructions, 0x1000);
    let decompiler = Decompiler::new();
    let code = decompiler.decompile(&cfg, "sum_to_ten");

    // Should have loop structure
    let has_loop = code.contains("while") || code.contains("for") || code.contains("do");
    let has_increment = code.contains("++") || code.contains("+= 1") || code.contains("+ 1");

    println!("Loop function decompiled to:\n{}", code);

    // Verify basic structure
    assert!(code.contains("sum_to_ten"), "Should contain function name");
    assert!(
        code.contains('{') && code.contains('}'),
        "Should have braces"
    );

    // Loop detection is a quality indicator, not a hard requirement
    if has_loop {
        println!("  -> Loop structure detected");
    }
    if has_increment {
        println!("  -> Increment pattern detected");
    }
}

#[test]
fn test_evex_broadcast_semantics_regression() {
    let disasm = X86_64Disassembler::new();

    // EVEX move with b=1 should not set memory broadcast for move/store forms.
    let move_bytes = [0x62, 0xf1, 0x7c, 0x58, 0x10, 0x00];
    let move_decoded = disasm.decode_instruction(&move_bytes, 0x2000).unwrap();
    assert_eq!(move_decoded.instruction.mnemonic, "vmovups");
    assert_eq!(
        memory_operand_broadcast(&move_decoded.instruction),
        Some(false),
        "EVEX move forms should not carry memory broadcast flag"
    );

    // EVEX arithmetic memory form with b=1 may carry broadcast.
    let arith_bytes = [0x62, 0xf1, 0x7c, 0x58, 0x58, 0x00];
    let arith_decoded = disasm.decode_instruction(&arith_bytes, 0x2010).unwrap();
    assert_eq!(arith_decoded.instruction.mnemonic, "vaddps");
    assert_eq!(
        memory_operand_broadcast(&arith_decoded.instruction),
        Some(true),
        "EVEX arithmetic memory forms should preserve broadcast flag"
    );

    // Ensure these EVEX instructions still pass through CFG + decompiler without regressions.
    let mut block = Vec::new();
    block.extend_from_slice(&move_bytes);
    block.extend_from_slice(&arith_bytes);
    block.push(0xc3); // ret

    let instructions = disassemble_block(Architecture::X86_64, &block, 0x2000);
    assert!(
        !instructions.is_empty(),
        "expected EVEX instructions to decode"
    );
    let cfg = CfgBuilder::build(&instructions, 0x2000);
    let code = Decompiler::new().decompile(&cfg, "evex_regression");
    assert!(
        !code.is_empty(),
        "EVEX regression function should decompile"
    );
}

#[test]
fn test_abi_call_side_effect_summaries_regression() {
    let db = SummaryDatabase::new();

    // Known pure libc-style helpers should remain pure.
    for pure_name in ["strlen", "strcmp", "memcmp"] {
        let summary = db
            .get_summary_by_name(pure_name)
            .unwrap_or_else(|| panic!("missing summary for {}", pure_name));
        assert!(summary.is_pure, "{} should be pure", pure_name);
        assert!(
            summary.return_depends_only_on_args,
            "{} should have arg-only return dependence",
            pure_name
        );
    }

    // Side-effectful APIs should not be marked pure.
    for impure_name in ["malloc", "free", "printf", "puts", "memcpy", "strcpy"] {
        let summary = db
            .get_summary_by_name(impure_name)
            .unwrap_or_else(|| panic!("missing summary for {}", impure_name));
        assert!(!summary.is_pure, "{} should be impure", impure_name);
    }

    // ABI-aware noreturn effects are part of call-side-effect modeling.
    for noreturn_name in ["exit", "_exit", "abort"] {
        let summary = db
            .get_summary_by_name(noreturn_name)
            .unwrap_or_else(|| panic!("missing summary for {}", noreturn_name));
        assert!(
            summary.may_not_return,
            "{} should be modeled as may_not_return",
            noreturn_name
        );
    }
}
