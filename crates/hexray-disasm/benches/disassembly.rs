//! Benchmarks for disassembly performance.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hexray_disasm::{Disassembler, X86_64Disassembler};

#[cfg(feature = "arm64")]
use hexray_disasm::Arm64Disassembler;

/// Sample x86_64 code: a small function with various instruction types.
/// This is a realistic mix of mov, arithmetic, control flow, and memory ops.
const X86_64_CODE: &[u8] = &[
    // Function prologue
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
    // Some arithmetic
    0x48, 0x89, 0x7d, 0xf8, // mov [rbp-8], rdi
    0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp-8]
    0x48, 0x83, 0xc0, 0x01, // add rax, 1
    0x48, 0x89, 0x45, 0xf0, // mov [rbp-16], rax
    // Conditional
    0x48, 0x83, 0x7d, 0xf0, 0x0a, // cmp qword [rbp-16], 10
    0x7e, 0x07, // jle .L1
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xeb, 0x05, // jmp .L2
    // .L1:
    0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
    // .L2: epilogue
    0x48, 0x83, 0xc4, 0x20, // add rsp, 0x20
    0x5d, // pop rbp
    0xc3, // ret
];

/// Larger code block for throughput testing (repeated pattern).
fn generate_large_x86_64_block(size: usize) -> Vec<u8> {
    let pattern = X86_64_CODE;
    let mut result = Vec::with_capacity(size);
    while result.len() < size {
        let remaining = size - result.len();
        let to_copy = remaining.min(pattern.len());
        result.extend_from_slice(&pattern[..to_copy]);
    }
    result
}

/// Sample ARM64 code: basic function.
#[cfg(feature = "arm64")]
const ARM64_CODE: &[u8] = &[
    // stp x29, x30, [sp, #-16]!
    0xfd, 0x7b, 0xbf, 0xa9, // mov x29, sp
    0xfd, 0x03, 0x00, 0x91, // mov w8, w0
    0xe8, 0x03, 0x00, 0x2a, // add w0, w8, #1
    0x00, 0x05, 0x00, 0x11, // ldp x29, x30, [sp], #16
    0xfd, 0x7b, 0xc1, 0xa8, // ret
    0xc0, 0x03, 0x5f, 0xd6,
];

fn bench_x86_64_disassembly(c: &mut Criterion) {
    let disasm = X86_64Disassembler::new();

    let mut group = c.benchmark_group("x86_64_disassembly");

    // Benchmark single instruction decode
    group.bench_function("single_instruction", |b| {
        b.iter(|| {
            let _ = disasm.decode_instruction(black_box(&X86_64_CODE[..3]), 0x1000);
        })
    });

    // Benchmark small function
    group.bench_function("small_function", |b| {
        b.iter(|| {
            let _ = disasm.disassemble_block(black_box(X86_64_CODE), 0x1000);
        })
    });

    // Benchmark various sizes for throughput
    for size in [1024, 4096, 16384, 65536] {
        let code = generate_large_x86_64_block(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("throughput", size), &code, |b, code| {
            b.iter(|| {
                let _ = disasm.disassemble_block(black_box(code), 0x1000);
            })
        });
    }

    group.finish();
}

#[cfg(feature = "arm64")]
fn bench_arm64_disassembly(c: &mut Criterion) {
    let disasm = Arm64Disassembler::new();

    let mut group = c.benchmark_group("arm64_disassembly");

    // Benchmark single instruction decode
    group.bench_function("single_instruction", |b| {
        b.iter(|| {
            let _ = disasm.decode_instruction(black_box(&ARM64_CODE[..4]), 0x1000);
        })
    });

    // Benchmark small function
    group.bench_function("small_function", |b| {
        b.iter(|| {
            let _ = disasm.disassemble_block(black_box(ARM64_CODE), 0x1000);
        })
    });

    group.finish();
}

#[cfg(feature = "arm64")]
criterion_group!(benches, bench_x86_64_disassembly, bench_arm64_disassembly);

#[cfg(not(feature = "arm64"))]
criterion_group!(benches, bench_x86_64_disassembly);

criterion_main!(benches);
