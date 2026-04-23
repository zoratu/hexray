// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// atomic_incr: each active thread atomically increments a global counter.
// Decode-coverage target: ATOM.ADD (global), return-value discard.

extern "C" __global__ void atomic_incr(unsigned int* __restrict__ counter,
                                       int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        atomicAdd(counter, 1u);
    }
}
