// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// loop_accumulator: fixed-trip register-accumulated dot stride over a row.
// Decode-coverage target: unrollable for-loop, register accumulator, FFMA.

extern "C" __global__ void loop_accumulator(const float* __restrict__ x,
                                            float* __restrict__ y,
                                            int stride,
                                            int trips) {
    int row = blockIdx.x * blockDim.x + threadIdx.x;
    float acc = 0.0f;
    const float* base = x + row * stride;
    for (int k = 0; k < trips; ++k) {
        acc = acc + base[k] * base[k];
    }
    y[row] = acc;
}
