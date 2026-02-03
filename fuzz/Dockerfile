FROM rust:latest

# Install nightly toolchain and cargo-fuzz
RUN rustup install nightly && \
    rustup default nightly && \
    cargo install cargo-fuzz

# Install LLVM for libFuzzer
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hexray

# Copy the project
COPY . .

# Build fuzz targets
RUN cd fuzz && cargo fuzz build

# Default command shows available targets
CMD ["cargo", "fuzz", "list"]
