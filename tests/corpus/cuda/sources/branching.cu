// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// branching: divergent if/else on threadIdx.x parity.
// Decode-coverage target: predicated branches, convergence points, BSSY/BSYNC.

extern "C" __global__ void branching(const float* __restrict__ in,
                                     float* __restrict__ out,
                                     int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    float v = in[i];
    if ((threadIdx.x & 1) == 0) {
        v = v * 2.0f + 1.0f;
    } else {
        v = v * 0.5f - 1.0f;
    }
    out[i] = v;
}
