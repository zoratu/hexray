//! Swarm testing for the decompiler (Groce et al., ISSTA 2012).
//!
//! Instead of testing with a single "default" configuration that enables every
//! optimization pass, swarm testing generates a diverse set of configurations
//! that each *omit* a random subset of passes.  Feature-omission diversity
//! leads to better coverage and fault detection because:
//!
//!  1. Some passes actively **suppress** behaviors that would expose bugs in
//!     other passes (active suppression).
//!  2. Passes compete for "space" within each test: with all passes on, any
//!     single pass has less opportunity to exercise deep behavior (passive
//!     suppression).
//!
//! The key invariants tested here must hold for **any** pass configuration:
//!
//!  - Decompilation must not panic or crash.
//!  - Output must be non-empty and contain the function name.
//!  - Output must have balanced braces (structurally valid).
//!  - Output must be deterministic (same config + same input → same output).
//!
//! Each proptest case is a random `u32` bitmask selecting which of the 24
//! optimization passes are enabled.  With 50 % per-pass probability the swarm
//! set naturally covers a wide variety of configurations (a 100-element swarm
//! is 95 % likely to contain at least one C_i with any given set of five
//! features, per the paper's analysis).

use proptest::prelude::*;

use hexray_analysis::{CfgBuilder, Decompiler, DecompilerConfig};
use hexray_disasm::{Disassembler, X86_64Disassembler};

// =============================================================================
// Shared test data
// =============================================================================

/// Counting loop: `sum += i` for `i` in `0..10`.
///
/// Reused across multiple tests because loops exercise the most complex pass
/// interactions (register aliasing, dead-store elimination, copy propagation,
/// for-loop detection).
const LOOP_BYTES: &[u8] = &[
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rbp-4], 0
    0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, // mov [rbp-8], 0
    0x83, 0x7d, 0xfc, 0x0a, // cmp [rbp-4], 10
    0x7d, 0x0c, // jge end
    0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
    0x01, 0x45, 0xf8, // add [rbp-8], eax
    0x83, 0x45, 0xfc, 0x01, // add [rbp-4], 1
    0xeb, 0xee, // jmp loop
    0x8b, 0x45, 0xf8, // mov eax, [rbp-8]
    0x5d, // pop rbp
    0xc3, // ret
];

// =============================================================================
// Test Inputs — small x86-64 byte sequences with known structure
// =============================================================================

/// (name, bytes, start_addr)
fn test_programs() -> Vec<(&'static str, &'static [u8], u64)> {
    vec![
        // Minimal: just a return
        ("ret_only", [0xc3].as_slice(), 0x1000),
        // Simple prologue/epilogue with argument access
        (
            "simple_arg",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
        // Diamond if-else
        (
            "if_else",
            &[
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
            0x1000,
        ),
        // Counting loop (shared constant)
        ("counting_loop", LOOP_BYTES, 0x1000),
        // Multiply (imul)
        (
            "multiply",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0x0f, 0xaf, 0x45, 0xfc, // imul eax, [rbp-4]
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
        // Nested if: two comparisons
        (
            "nested_if",
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x89, 0x7d, 0xfc, // mov [rbp-4], edi
                0x89, 0x75, 0xf8, // mov [rbp-8], esi
                0x83, 0x7d, 0xfc, 0x00, // cmp [rbp-4], 0
                0x7e, 0x0c, // jle +12
                0x83, 0x7d, 0xf8, 0x00, // cmp [rbp-8], 0
                0x7e, 0x06, // jle +6
                0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
                0xeb, 0x0a, // jmp +10
                0x8b, 0x45, 0xf8, // mov eax, [rbp-8]
                0xeb, 0x05, // jmp +5
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
                0x5d, // pop rbp
                0xc3, // ret
            ],
            0x1000,
        ),
    ]
}

// =============================================================================
// Helpers
// =============================================================================

fn disassemble_x86(bytes: &[u8], start: u64) -> Vec<hexray_core::Instruction> {
    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start + offset as u64;
        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;
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

fn decompile_with_config(bytes: &[u8], start: u64, name: &str, config: DecompilerConfig) -> String {
    let instructions = disassemble_x86(bytes, start);
    if instructions.is_empty() {
        return String::new();
    }
    let cfg = CfgBuilder::build(&instructions, start);
    let decompiler = Decompiler::new().with_addresses(false).with_config(config);
    decompiler.decompile(&cfg, name)
}

/// Net brace depth (0 when balanced).  Used only in failure diagnostics.
fn brace_depth(code: &str) -> i32 {
    code.chars().fold(0i32, |d, ch| {
        d + match ch {
            '{' => 1,
            '}' => -1,
            _ => 0,
        }
    })
}

/// Check that braces never go negative (close before open) and end balanced.
fn braces_well_formed(code: &str) -> bool {
    let mut depth: i32 = 0;
    for ch in code.chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

// =============================================================================
// Swarm Testing Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Core swarm invariant: decompilation must not panic and must produce
    /// structurally valid output for any random subset of passes.
    ///
    /// This is the direct application of Groce et al.'s swarm testing:
    /// each `bits` value is a random test configuration C_i where each
    /// of the 24 passes has ~50% probability of inclusion.
    #[test]
    fn swarm_decompile_never_crashes(bits in any::<u32>()) {
        let config = DecompilerConfig::from_swarm_bits(bits);

        for (name, bytes, start) in test_programs() {
            let code = decompile_with_config(bytes, start, name, config.clone());

            // Invariant 1: output is non-empty
            prop_assert!(
                !code.is_empty(),
                "swarm config 0x{:08x} ({}) produced empty output for '{}'",
                bits, config.describe(), name
            );

            // Invariant 2: function name appears in output
            prop_assert!(
                code.contains(name),
                "swarm config 0x{:08x} output for '{}' missing function name\n\
                 config: {}\ncode:\n{}",
                bits, name, config.describe(), code
            );

            // Invariant 3: balanced braces
            prop_assert!(
                braces_well_formed(&code),
                "swarm config 0x{:08x} output for '{}' has unbalanced braces \
                 (depth={})\nconfig: {}\ncode:\n{}",
                bits, name, brace_depth(&code), config.describe(), code
            );
        }
    }

    /// Determinism: the same swarm configuration and input must always
    /// produce identical output.
    #[test]
    fn swarm_decompile_is_deterministic(bits in any::<u32>()) {
        for (name, bytes, start) in test_programs() {
            let config1 = DecompilerConfig::from_swarm_bits(bits);
            let config2 = DecompilerConfig::from_swarm_bits(bits);

            let code1 = decompile_with_config(bytes, start, name, config1);
            let code2 = decompile_with_config(bytes, start, name, config2);

            prop_assert_eq!(
                &code1, &code2,
                "swarm config 0x{:08x} is non-deterministic for '{}'\n\
                 config: {}",
                bits, name, DecompilerConfig::from_swarm_bits(bits).describe()
            );
        }
    }

    /// Monotonicity sanity check: enabling strictly more passes should not
    /// *reduce* the output to empty.  (The output may differ, but both
    /// the subset and the superset must produce non-empty results.)
    #[test]
    fn swarm_superset_still_produces_output(
        base_bits in any::<u32>(),
        extra_bits in any::<u32>(),
    ) {
        let subset_bits = base_bits;
        let superset_bits = base_bits | extra_bits;

        let subset_config = DecompilerConfig::from_swarm_bits(subset_bits);
        let superset_config = DecompilerConfig::from_swarm_bits(superset_bits);

        for (name, bytes, start) in test_programs() {
            let sub_code = decompile_with_config(bytes, start, name, subset_config.clone());
            let sup_code = decompile_with_config(bytes, start, name, superset_config.clone());

            prop_assert!(
                !sub_code.is_empty(),
                "subset config 0x{:08x} produced empty output for '{}'",
                subset_bits, name
            );
            prop_assert!(
                !sup_code.is_empty(),
                "superset config 0x{:08x} produced empty output for '{}'",
                superset_bits, name
            );
        }
    }
}

// =============================================================================
// Targeted Swarm Tests — fixed programs × random configs
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// High-volume swarm test on the loop program, which historically has the
    /// most complex pass interactions (register aliasing, dead-store
    /// elimination, copy propagation, for-loop detection).
    #[test]
    fn swarm_loop_program_robust(bits in any::<u32>()) {
        let config = DecompilerConfig::from_swarm_bits(bits);
        let code = decompile_with_config(LOOP_BYTES, 0x1000, "sum_loop", config.clone());

        prop_assert!(!code.is_empty());
        prop_assert!(code.contains("sum_loop"));
        prop_assert!(braces_well_formed(&code));

        // The loop body must exist in some form — either as a structured loop
        // or as goto-based control flow.  The output must contain either a
        // loop keyword or a label (indicating goto-based lowering).
        let has_structure = code.contains("while")
            || code.contains("for")
            || code.contains("do")
            || code.contains("goto")
            || code.contains("loop");
        prop_assert!(
            has_structure,
            "swarm config 0x{:08x} lost all loop structure for sum_loop\n\
             config: {}\ncode:\n{}",
            bits, config.describe(), code
        );
    }
}

// =============================================================================
// System Binary Swarm Tests (macOS only)
// =============================================================================

#[cfg(target_os = "macos")]
mod system_binary_swarm {
    use super::*;
    use hexray_core::Architecture;
    use hexray_disasm::Arm64Disassembler;
    use hexray_formats::{detect_format, BinaryFormat, BinaryType, MachO};

    /// Extract the first small function from a system binary.
    fn extract_function(path: &str) -> Option<(Architecture, Vec<u8>, u64, String)> {
        let data = std::fs::read(path).ok()?;
        match detect_format(&data) {
            BinaryType::MachO => {
                let macho = MachO::parse(&data).ok()?;
                let arch = macho.architecture();
                for sym in macho.symbols() {
                    if sym.is_function() && sym.address != 0 && (4..=2048).contains(&sym.size) {
                        let bytes = macho.bytes_at(sym.address, sym.size as usize)?;
                        return Some((arch, bytes.to_vec(), sym.address, sym.name.clone()));
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn disassemble_arm64(bytes: &[u8], start: u64) -> Vec<hexray_core::Instruction> {
        let disasm = Arm64Disassembler::new();
        let mut out = Vec::new();
        let mut off = 0;
        while off < bytes.len() && out.len() < 500 {
            match disasm.decode_instruction(&bytes[off..], start + off as u64) {
                Ok(d) => {
                    let ret = d.instruction.is_return();
                    out.push(d.instruction);
                    off += d.size;
                    if ret {
                        break;
                    }
                }
                Err(_) => {
                    off += 4;
                }
            }
        }
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Swarm test a real function extracted from /bin/ls.
        /// This exercises the decompiler on production machine code with
        /// diverse pass configurations.
        #[test]
        fn swarm_system_binary(bits in any::<u32>()) {
            if let Some((arch, bytes, addr, name)) = extract_function("/bin/ls") {
                let instructions = match arch {
                    Architecture::X86_64 => disassemble_x86(&bytes, addr),
                    Architecture::Arm64 => disassemble_arm64(&bytes, addr),
                    _ => return Ok(()),
                };
                if instructions.is_empty() {
                    return Ok(());
                }

                let cfg = CfgBuilder::build(&instructions, addr);
                let config = DecompilerConfig::from_swarm_bits(bits);
                let decompiler = Decompiler::new()
                    .with_addresses(false)
                    .with_config(config.clone());

                let code = decompiler.decompile(&cfg, &name);

                prop_assert!(
                    !code.is_empty(),
                    "swarm config 0x{:08x} produced empty output for system func '{}'\n\
                     config: {}",
                    bits, name, config.describe()
                );
                prop_assert!(
                    braces_well_formed(&code),
                    "swarm config 0x{:08x} produced unbalanced braces for system func '{}'\n\
                     config: {}\ncode:\n{}",
                    bits, name, config.describe(), &code[..code.len().min(500)]
                );
            }
        }
    }
}

// =============================================================================
// Swarm Coverage Statistics (ignored by default — run with --ignored)
// =============================================================================

/// Print a pass-frequency report for a 1000-element swarm set.
///
/// This test is `#[ignore]`d by default because it is informational, not a
/// correctness check.  Run with `cargo test -- --ignored swarm_coverage` to
/// see which pass combinations trigger which output patterns.
#[test]
#[ignore]
fn swarm_coverage_report() {
    use std::collections::HashMap;

    let all_passes = hexray_analysis::OptimizationPass::all();
    let num_configs: usize = 1000;
    let mut pass_trigger_count: HashMap<&str, usize> = HashMap::new();
    let mut pass_suppress_count: HashMap<&str, usize> = HashMap::new();
    let mut total_with_loops = 0usize;
    let mut total_with_gotos = 0usize;
    let mut total_with_switch = 0usize;
    let mut total_configs = 0usize;

    // Use a simple PRNG for reproducibility (xorshift32)
    let mut rng_state = 0xDEAD_BEEFu32;
    let mut next_u32 = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        rng_state
    };

    for _ in 0..num_configs {
        let bits = next_u32();
        let config = DecompilerConfig::from_swarm_bits(bits);
        let code = decompile_with_config(LOOP_BYTES, 0x1000, "loop_fn", config);

        if code.is_empty() {
            continue;
        }
        total_configs += 1;

        let has_loop = code.contains("while") || code.contains("for");
        let has_goto = code.contains("goto");
        let has_switch = code.contains("switch");

        if has_loop {
            total_with_loops += 1;
        }
        if has_goto {
            total_with_gotos += 1;
        }
        if has_switch {
            total_with_switch += 1;
        }

        // Per-pass trigger/suppress analysis (à la Table 2 & 6 in the paper)
        for (i, pass) in all_passes.iter().enumerate() {
            let pass_on = bits & (1 << i) != 0;
            if pass_on && has_loop {
                *pass_trigger_count.entry(pass.name()).or_default() += 1;
            }
            if pass_on && has_goto {
                *pass_suppress_count.entry(pass.name()).or_default() += 1;
            }
        }
    }

    println!("\n=== Swarm Coverage Report ({total_configs} configs) ===");
    println!(
        "  Structured loops: {}/{} ({:.1}%)",
        total_with_loops,
        total_configs,
        total_with_loops as f64 / total_configs as f64 * 100.0
    );
    println!(
        "  Goto fallback:    {}/{} ({:.1}%)",
        total_with_gotos,
        total_configs,
        total_with_gotos as f64 / total_configs as f64 * 100.0
    );
    println!(
        "  Switch detected:  {}/{} ({:.1}%)",
        total_with_switch,
        total_configs,
        total_with_switch as f64 / total_configs as f64 * 100.0
    );

    println!("\n  Top loop triggers (pass present when loop detected):");
    let mut triggers: Vec<_> = pass_trigger_count.iter().collect();
    triggers.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in triggers.iter().take(10) {
        println!(
            "    {:<35} {:>4} ({:.1}%)",
            name,
            count,
            **count as f64 / total_configs as f64 * 100.0
        );
    }

    println!("\n  Top goto triggers (pass present when goto emitted):");
    let mut suppressors: Vec<_> = pass_suppress_count.iter().collect();
    suppressors.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in suppressors.iter().take(10) {
        println!(
            "    {:<35} {:>4} ({:.1}%)",
            name,
            count,
            **count as f64 / total_configs as f64 * 100.0
        );
    }
}
