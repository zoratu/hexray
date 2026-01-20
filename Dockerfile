# Hexray test environment - x86_64 Linux
FROM rust:slim-bookworm

# Install build dependencies and testing tools
RUN apt-get update && apt-get install -y \
    build-essential \
    binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hexray

# Copy everything - we'll let cargo handle incremental compilation
COPY . .

# Run all tests including CLI, differential, and property-based tests
# Note: Tests are run with increased stack size for property tests
ENV RUST_MIN_STACK=8388608
CMD ["sh", "-c", "echo '=== Running core tests ===' && \
    cargo test -p hexray-core && \
    echo '=== Running disasm tests ===' && \
    cargo test -p hexray-disasm --all-features && \
    echo '=== Running formats tests ===' && \
    cargo test -p hexray-formats && \
    echo '=== Running demangle tests ===' && \
    cargo test -p hexray-demangle && \
    echo '=== Running emulate tests ===' && \
    cargo test -p hexray-emulate && \
    echo '=== Running hexray CLI and integration tests ===' && \
    cargo test -p hexray && \
    echo '=== All tests passed! ==='"]
