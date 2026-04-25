// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// scalar_mul: in-place x *= s over a float array.
// Decode-coverage target: load-modify-store, scalar broadcast operand.

extern "C" __global__ void scalar_mul(float* __restrict__ x,
                                      float s,
                                      int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        x[i] = x[i] * s;
    }
}
