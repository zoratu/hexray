# Hexray Fuzz Testing

This directory contains fuzz targets for testing the hexray disassembler project using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and [libFuzzer](https://llvm.org/docs/LibFuzzer.html).

## Quick Start (Docker - Recommended)

Run all fuzzers in Docker containers:

```bash
cd fuzz
./run-fuzzers.sh              # Run all fuzzers for 1 hour each
./run-fuzzers.sh --hours 8    # Run all fuzzers for 8 hours each
./run-fuzzers.sh x86_64       # Run only x86_64 decoder fuzzer
```

Or use docker-compose:

```bash
cd fuzz
docker-compose up --build     # Run all fuzzers in parallel
docker-compose up fuzz-x86_64 # Run only x86_64 fuzzer
```

Monitor and stop:

```bash
docker logs -f hexray-fuzz-x86_64
docker stop $(docker ps -q --filter name=hexray-fuzz)
```

## Manual Setup (Native)

If you prefer not to use Docker, install cargo-fuzz (requires nightly Rust):

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `x86_64_decoder` | Fuzzes the x86-64 instruction decoder with arbitrary byte sequences |
| `arm64_decoder` | Fuzzes the ARM64/AArch64 instruction decoder with arbitrary byte sequences |
| `riscv_decoder` | Fuzzes the RISC-V instruction decoder with arbitrary byte sequences |
| `elf_parser` | Fuzzes the ELF binary format parser |
| `macho_parser` | Fuzzes the Mach-O binary format parser |

## Running Fuzz Targets

### Basic Usage

Run a fuzz target indefinitely:

```bash
# From the repository root
cd fuzz
cargo +nightly fuzz run x86_64_decoder
cargo +nightly fuzz run arm64_decoder
cargo +nightly fuzz run elf_parser
cargo +nightly fuzz run macho_parser
```

### With Time Limit

Run for a specific duration:

```bash
# Run for 60 seconds
cargo +nightly fuzz run x86_64_decoder -- -max_total_time=60
```

### With Job Parallelism

Use multiple CPU cores:

```bash
# Run with 4 parallel jobs
cargo +nightly fuzz run x86_64_decoder -- -jobs=4 -workers=4
```

### Corpus Management

The fuzzer maintains a corpus of interesting inputs in `fuzz/corpus/<target_name>/`.

To minimize the corpus (remove redundant inputs):

```bash
cargo +nightly fuzz cmin x86_64_decoder
```

### Reproducing Crashes

If a crash is found, it will be saved to `fuzz/artifacts/<target_name>/`. To reproduce:

```bash
cargo +nightly fuzz run x86_64_decoder fuzz/artifacts/x86_64_decoder/crash-<hash>
```

## Coverage-Guided Fuzzing Tips

1. **Seed corpus**: Add known-good samples to `fuzz/corpus/<target>/` to give the fuzzer a head start:
   ```bash
   mkdir -p fuzz/corpus/elf_parser
   cp /path/to/sample.elf fuzz/corpus/elf_parser/
   ```

2. **Dictionary files**: Create dictionaries with common tokens for better fuzzing:
   ```bash
   # Create fuzz/dict/elf.dict with ELF magic bytes, section names, etc.
   cargo +nightly fuzz run elf_parser -- -dict=dict/elf.dict
   ```

3. **Memory limits**: Set memory limits to catch memory issues:
   ```bash
   cargo +nightly fuzz run elf_parser -- -rss_limit_mb=2048
   ```

## Continuous Fuzzing

For CI integration, run fuzz tests with a time limit and fail on crashes:

```bash
#!/bin/bash
set -e
cd fuzz
for target in x86_64_decoder arm64_decoder elf_parser macho_parser; do
    echo "Fuzzing $target..."
    cargo +nightly fuzz run "$target" -- -max_total_time=300 || exit 1
done
```

## Troubleshooting

### "error: the option `Z` is only accepted on the nightly compiler"

Make sure you're using nightly Rust:
```bash
rustup install nightly
cargo +nightly fuzz run <target>
```

### "LLVM ERROR: -fsanitize=fuzzer-no-link is not supported on this platform"

This typically occurs on non-Linux platforms. Consider using a Linux VM or Docker container for fuzzing.

### Out of Memory

Increase or disable memory limits:
```bash
cargo +nightly fuzz run elf_parser -- -rss_limit_mb=4096
```

## Writing New Fuzz Targets

To add a new fuzz target:

1. Create a new file in `fuzz/fuzz_targets/`:
   ```rust
   #![no_main]

   use libfuzzer_sys::fuzz_target;

   fuzz_target!(|data: &[u8]| {
       // Your fuzzing code here
       // Should never panic on invalid input
       let _ = your_function(data);
   });
   ```

2. Add the target to `fuzz/Cargo.toml`:
   ```toml
   [[bin]]
   name = "your_target"
   path = "fuzz_targets/your_target.rs"
   test = false
   doc = false
   bench = false
   ```

3. Run the new target:
   ```bash
   cargo +nightly fuzz run your_target
   ```
