//! Benchmarks for analysis performance (CFG, decompilation).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hexray_analysis::{CfgBuilder, Decompiler};
use hexray_core::{Condition, ControlFlow, Instruction};

/// Create a simple linear sequence of instructions.
fn create_linear_instructions(count: usize) -> Vec<Instruction> {
    let mut instructions = Vec::with_capacity(count);
    let base_addr = 0x1000u64;

    for i in 0..count.saturating_sub(1) {
        let addr = base_addr + (i * 4) as u64;
        let inst = Instruction::new(addr, 4, vec![0x90, 0x90, 0x90, 0x90], "nop");
        instructions.push(inst);
    }

    // Add a return at the end
    if count > 0 {
        let addr = base_addr + ((count - 1) * 4) as u64;
        let mut inst = Instruction::new(addr, 1, vec![0xc3], "ret");
        inst.control_flow = ControlFlow::Return;
        instructions.push(inst);
    }

    instructions
}

/// Create instructions with branches (more complex CFG).
fn create_branching_instructions(branch_count: usize) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let base_addr = 0x1000u64;
    let mut offset = 0usize;

    for i in 0..branch_count {
        let block_start = base_addr + offset as u64;

        // Add a few instructions per block
        for j in 0..3 {
            let addr = block_start + (j * 4) as u64;
            let inst = Instruction::new(addr, 4, vec![0x90, 0x90, 0x90, 0x90], "nop");
            instructions.push(inst);
        }
        offset += 12;

        // Add conditional branch (except last block)
        if i < branch_count - 1 {
            let branch_addr = base_addr + offset as u64;
            let target_addr = base_addr + (offset + 20) as u64;
            let fallthrough_addr = branch_addr + 2;

            let mut inst = Instruction::new(branch_addr, 2, vec![0x75, 0x10], "jne");
            inst.control_flow = ControlFlow::ConditionalBranch {
                target: target_addr,
                condition: Condition::NotEqual,
                fallthrough: fallthrough_addr,
            };
            instructions.push(inst);
            offset += 2;
        }
    }

    // Final return
    let ret_addr = base_addr + offset as u64;
    let mut ret = Instruction::new(ret_addr, 1, vec![0xc3], "ret");
    ret.control_flow = ControlFlow::Return;
    instructions.push(ret);

    instructions
}

/// Create a loop structure.
fn create_loop_instructions() -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let base = 0x1000u64;

    // Prologue
    instructions.push(Instruction::new(
        base,
        4,
        vec![0x55, 0x48, 0x89, 0xe5],
        "push rbp",
    ));

    // Loop header (block 1)
    let loop_header = base + 4;
    instructions.push(Instruction::new(
        loop_header,
        3,
        vec![0x83, 0xf8, 0x00],
        "cmp eax, 0",
    ));

    // Conditional exit
    let exit_addr = base + 20;
    let body_addr = loop_header + 5;
    let mut jz = Instruction::new(loop_header + 3, 2, vec![0x74, 0x08], "je");
    jz.control_flow = ControlFlow::ConditionalBranch {
        target: exit_addr,
        condition: Condition::Equal,
        fallthrough: body_addr,
    };
    instructions.push(jz);

    // Loop body (block 2)
    instructions.push(Instruction::new(body_addr, 2, vec![0xff, 0xc8], "dec eax"));

    // Back edge
    let mut jmp = Instruction::new(body_addr + 2, 2, vec![0xeb, 0xf6], "jmp");
    jmp.control_flow = ControlFlow::UnconditionalBranch {
        target: loop_header,
    };
    instructions.push(jmp);

    // Exit (block 3)
    instructions.push(Instruction::new(exit_addr, 1, vec![0x5d], "pop rbp"));

    let mut ret = Instruction::new(exit_addr + 1, 1, vec![0xc3], "ret");
    ret.control_flow = ControlFlow::Return;
    instructions.push(ret);

    instructions
}

fn bench_cfg_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cfg_construction");

    // Benchmark linear CFG construction
    for size in [10, 50, 100, 500, 1000] {
        let instructions = create_linear_instructions(size);
        group.bench_with_input(
            BenchmarkId::new("linear", size),
            &instructions,
            |b, instructions| b.iter(|| CfgBuilder::build(black_box(instructions), 0x1000)),
        );
    }

    // Benchmark branching CFG construction
    for branches in [5, 10, 20, 50] {
        let instructions = create_branching_instructions(branches);
        group.bench_with_input(
            BenchmarkId::new("branching", branches),
            &instructions,
            |b, instructions| b.iter(|| CfgBuilder::build(black_box(instructions), 0x1000)),
        );
    }

    // Benchmark loop CFG
    let loop_instructions = create_loop_instructions();
    group.bench_function("loop_structure", |b| {
        b.iter(|| CfgBuilder::build(black_box(&loop_instructions), 0x1000))
    });

    group.finish();
}

fn bench_decompilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompilation");

    // Pre-build CFGs for decompilation benchmarks
    let linear_small = CfgBuilder::build(&create_linear_instructions(20), 0x1000);
    let linear_medium = CfgBuilder::build(&create_linear_instructions(100), 0x1000);
    let branching = CfgBuilder::build(&create_branching_instructions(10), 0x1000);
    let loop_cfg = CfgBuilder::build(&create_loop_instructions(), 0x1000);

    let decompiler = Decompiler::new();

    group.bench_function("linear_small", |b| {
        b.iter(|| decompiler.decompile(black_box(&linear_small), "test_func"))
    });

    group.bench_function("linear_medium", |b| {
        b.iter(|| decompiler.decompile(black_box(&linear_medium), "test_func"))
    });

    group.bench_function("branching", |b| {
        b.iter(|| decompiler.decompile(black_box(&branching), "test_func"))
    });

    group.bench_function("loop", |b| {
        b.iter(|| decompiler.decompile(black_box(&loop_cfg), "test_func"))
    });

    group.finish();
}

fn bench_signature_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_recovery");

    let loop_cfg = CfgBuilder::build(&create_loop_instructions(), 0x1000);
    let branching = CfgBuilder::build(&create_branching_instructions(10), 0x1000);

    let decompiler = Decompiler::new();

    group.bench_function("loop_function", |b| {
        b.iter(|| decompiler.recover_signature(black_box(&loop_cfg)))
    });

    group.bench_function("branching_function", |b| {
        b.iter(|| decompiler.recover_signature(black_box(&branching)))
    });

    group.finish();
}

fn bench_optimization_levels(c: &mut Criterion) {
    use hexray_analysis::{DecompilerConfig, OptimizationLevel};

    let mut group = c.benchmark_group("optimization_levels");

    // Create a complex CFG for benchmarking
    let complex_cfg = CfgBuilder::build(&create_branching_instructions(20), 0x1000);
    let loop_cfg = CfgBuilder::build(&create_loop_instructions(), 0x1000);

    // Benchmark no optimizations
    let config_none = DecompilerConfig::new(OptimizationLevel::None);
    let decompiler_none = Decompiler::new().with_config(config_none);
    group.bench_function("branching_opt_none", |b| {
        b.iter(|| decompiler_none.decompile(black_box(&complex_cfg), "test_func"))
    });

    // Benchmark basic optimizations
    let config_basic = DecompilerConfig::new(OptimizationLevel::Basic);
    let decompiler_basic = Decompiler::new().with_config(config_basic);
    group.bench_function("branching_opt_basic", |b| {
        b.iter(|| decompiler_basic.decompile(black_box(&complex_cfg), "test_func"))
    });

    // Benchmark standard optimizations
    let config_standard = DecompilerConfig::new(OptimizationLevel::Standard);
    let decompiler_standard = Decompiler::new().with_config(config_standard);
    group.bench_function("branching_opt_standard", |b| {
        b.iter(|| decompiler_standard.decompile(black_box(&complex_cfg), "test_func"))
    });

    // Benchmark aggressive optimizations
    let config_aggressive = DecompilerConfig::new(OptimizationLevel::Aggressive);
    let decompiler_aggressive = Decompiler::new().with_config(config_aggressive);
    group.bench_function("branching_opt_aggressive", |b| {
        b.iter(|| decompiler_aggressive.decompile(black_box(&complex_cfg), "test_func"))
    });

    // Loop benchmarks at different optimization levels
    group.bench_function("loop_opt_none", |b| {
        b.iter(|| decompiler_none.decompile(black_box(&loop_cfg), "test_func"))
    });

    group.bench_function("loop_opt_standard", |b| {
        b.iter(|| decompiler_standard.decompile(black_box(&loop_cfg), "test_func"))
    });

    group.bench_function("loop_opt_aggressive", |b| {
        b.iter(|| decompiler_aggressive.decompile(black_box(&loop_cfg), "test_func"))
    });

    group.finish();
}

fn bench_output_quality(c: &mut Criterion) {
    use hexray_analysis::{DecompilerConfig, OptimizationLevel};

    let mut group = c.benchmark_group("output_quality");

    // This benchmark measures how long it takes to produce output
    // at different quality levels. More optimizations = potentially better output
    // but may take longer.

    let complex_cfg = CfgBuilder::build(&create_branching_instructions(30), 0x1000);

    // Measure output size at different levels (as a proxy for quality)
    let config_none = DecompilerConfig::new(OptimizationLevel::None);
    let config_standard = DecompilerConfig::new(OptimizationLevel::Standard);
    let config_aggressive = DecompilerConfig::new(OptimizationLevel::Aggressive);

    let decompiler_none = Decompiler::new().with_config(config_none);
    let decompiler_standard = Decompiler::new().with_config(config_standard);
    let decompiler_aggressive = Decompiler::new().with_config(config_aggressive);

    // Benchmark that includes output length tracking
    group.bench_function("complex_none", |b| {
        b.iter(|| {
            let output = decompiler_none.decompile(black_box(&complex_cfg), "test");
            black_box(output.len())
        })
    });

    group.bench_function("complex_standard", |b| {
        b.iter(|| {
            let output = decompiler_standard.decompile(black_box(&complex_cfg), "test");
            black_box(output.len())
        })
    });

    group.bench_function("complex_aggressive", |b| {
        b.iter(|| {
            let output = decompiler_aggressive.decompile(black_box(&complex_cfg), "test");
            black_box(output.len())
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cfg_construction,
    bench_decompilation,
    bench_signature_recovery,
    bench_optimization_levels,
    bench_output_quality
);
criterion_main!(benches);
