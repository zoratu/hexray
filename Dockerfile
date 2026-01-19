# Hexray test environment - x86_64 Linux
FROM rust:slim-bookworm

# Install nightly toolchain for edition2024 support
RUN rustup default nightly

# Install build dependencies and testing tools
RUN apt-get update && apt-get install -y \
    build-essential \
    binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hexray

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/hexray/Cargo.toml crates/hexray/
COPY crates/hexray-core/Cargo.toml crates/hexray-core/
COPY crates/hexray-formats/Cargo.toml crates/hexray-formats/
COPY crates/hexray-disasm/Cargo.toml crates/hexray-disasm/
COPY crates/hexray-analysis/Cargo.toml crates/hexray-analysis/
COPY crates/hexray-demangle/Cargo.toml crates/hexray-demangle/
COPY crates/hexray-emulate/Cargo.toml crates/hexray-emulate/
COPY crates/hexray-signatures/Cargo.toml crates/hexray-signatures/
COPY crates/hexray-types/Cargo.toml crates/hexray-types/

# Create dummy source files to build dependencies
RUN mkdir -p crates/hexray/src crates/hexray-core/src crates/hexray-formats/src \
    crates/hexray-disasm/src crates/hexray-analysis/src crates/hexray-demangle/src \
    crates/hexray-emulate/src crates/hexray-signatures/src crates/hexray-types/src \
    && echo "fn main() {}" > crates/hexray/src/main.rs \
    && echo "// dummy" > crates/hexray-core/src/lib.rs \
    && echo "// dummy" > crates/hexray-formats/src/lib.rs \
    && echo "// dummy" > crates/hexray-disasm/src/lib.rs \
    && echo "// dummy" > crates/hexray-analysis/src/lib.rs \
    && echo "// dummy" > crates/hexray-demangle/src/lib.rs \
    && echo "// dummy" > crates/hexray-emulate/src/lib.rs \
    && echo "// dummy" > crates/hexray-signatures/src/lib.rs \
    && echo "// dummy" > crates/hexray-types/src/lib.rs

# Build dependencies (cached layer)
RUN cargo build --workspace 2>/dev/null || true
RUN cargo build --workspace --release 2>/dev/null || true

# Remove dummy sources
RUN rm -rf crates/*/src

# Copy actual source code
COPY . .

# Run tests for core crates that don't have complex cross-dependencies
CMD ["sh", "-c", "cargo test -p hexray-core && cargo test -p hexray-disasm --all-features && cargo test -p hexray-formats && cargo test -p hexray-demangle && cargo test -p hexray-emulate"]
