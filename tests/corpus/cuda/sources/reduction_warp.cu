// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// reduction_warp: single-warp sum reduction via __shfl_down_sync.
// Decode-coverage target: SHFL.DOWN intrinsics, warp-synchronous idiom.

extern "C" __global__ void reduction_warp(const float* __restrict__ in,
                                          float* __restrict__ out,
                                          int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    float v = (i < n) ? in[i] : 0.0f;
    unsigned mask = 0xffffffffu;
    for (int off = 16; off > 0; off >>= 1) {
        v += __shfl_down_sync(mask, v, off);
    }
    if ((threadIdx.x & 31) == 0) {
        out[blockIdx.x * (blockDim.x / 32) + (threadIdx.x >> 5)] = v;
    }
}
