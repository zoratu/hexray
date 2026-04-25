// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// shared_transpose: 32x32 tile transpose through __shared__ memory.
// Decode-coverage target: STS/LDS, __syncthreads barrier, bank-conflict pad.

#define TILE 32

extern "C" __global__ void shared_transpose(const float* __restrict__ in,
                                            float* __restrict__ out,
                                            int width) {
    __shared__ float tile[TILE][TILE + 1];

    int x = blockIdx.x * TILE + threadIdx.x;
    int y = blockIdx.y * TILE + threadIdx.y;
    if (x < width && y < width) {
        tile[threadIdx.y][threadIdx.x] = in[y * width + x];
    }
    __syncthreads();

    x = blockIdx.y * TILE + threadIdx.x;
    y = blockIdx.x * TILE + threadIdx.y;
    if (x < width && y < width) {
        out[y * width + x] = tile[threadIdx.x][threadIdx.y];
    }
}
