// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// memcpy_kernel: trivial global-to-global copy (32-bit words).
// Decode-coverage target: straight load/store pair with no compute.

extern "C" __global__ void memcpy_kernel(const unsigned int* __restrict__ src,
                                         unsigned int* __restrict__ dst,
                                         int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        dst[i] = src[i];
    }
}
