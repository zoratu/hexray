#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 hexray contributors.
#
# Build the CUDA microkernel corpus under tests/corpus/cuda/ on a cloud box.
# - Pins the toolkit to CUDA 13.2 (refuses to run against anything else).
# - Runs `make all` and `make check`.
# - Runs a second build and diffs the two to confirm determinism.
#
# Intended to be run on a Linux box that has the CUDA 13.2 component packages
# (cuda-nvcc-13-2, cuda-nvdisasm-13-2, cuda-cuobjdump-13-2) installed - see
# tests/corpus/cuda/README.md for the apt-repo setup.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS_DIR="${ROOT_DIR}/tests/corpus/cuda"

REQUIRED_CUDA_MAJOR=13
REQUIRED_CUDA_MINOR=2

PATH="/usr/local/cuda-${REQUIRED_CUDA_MAJOR}.${REQUIRED_CUDA_MINOR}/bin:${PATH}"
export PATH

log() { printf '[build-cuda-corpus] %s\n' "$*"; }
die() { printf '[build-cuda-corpus] ERROR: %s\n' "$*" >&2; exit 1; }

# --- toolchain checks -------------------------------------------------------

command -v nvcc      >/dev/null 2>&1 || die "nvcc not found on PATH"
command -v nvdisasm  >/dev/null 2>&1 || die "nvdisasm not found on PATH"

nvcc_version_line="$(nvcc --version | grep -E 'release' || true)"
if [[ -z "${nvcc_version_line}" ]]; then
    die "could not parse nvcc --version output"
fi

if ! grep -qE "release ${REQUIRED_CUDA_MAJOR}\.${REQUIRED_CUDA_MINOR}\b" <<<"${nvcc_version_line}"; then
    die "nvcc version mismatch; need CUDA ${REQUIRED_CUDA_MAJOR}.${REQUIRED_CUDA_MINOR}, got: ${nvcc_version_line}"
fi

log "toolkit OK: ${nvcc_version_line}"

# --- build ------------------------------------------------------------------

cd "${CORPUS_DIR}"

log "clean"
make clean >/dev/null

log "build (pass 1)"
make -j"$(nproc 2>/dev/null || echo 4)" all

log "check"
make check

# --- determinism check ------------------------------------------------------
#
# Copy the first build aside, rebuild from scratch, and diff. nvcc + nvdisasm
# should be reproducible for a fixed toolkit version; if this ever flakes it's
# a signal that something in the build environment is leaking non-determinism.

pass1="$(mktemp -d)"
trap 'rm -rf "${pass1}"' EXIT
cp -a build/. "${pass1}/"

log "build (pass 2, determinism check)"
make clean >/dev/null
make -j"$(nproc 2>/dev/null || echo 4)" all >/dev/null

if ! diff -r "${pass1}" build >/dev/null; then
    log "WARNING: builds differ between passes - investigate before trusting ground truth"
    diff -r "${pass1}" build | head -40 >&2 || true
    exit 2
fi

log "determinism OK: pass1 == pass2"
log "corpus ready at ${CORPUS_DIR}/build/"
