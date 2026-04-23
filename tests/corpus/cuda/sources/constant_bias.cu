// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// constant_bias: y[i] = x[i] + bias[i % 16], with bias in __constant__ memory.
// Decode-coverage target: LDC (constant-bank load), modulo indexing.

__constant__ float c_bias[16];

extern "C" __global__ void constant_bias(const float* __restrict__ x,
                                         float* __restrict__ y,
                                         int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        y[i] = x[i] + c_bias[i & 15];
    }
}
