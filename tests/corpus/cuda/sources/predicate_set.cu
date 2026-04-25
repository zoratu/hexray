// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 hexray contributors.
//
// predicate_set: per-warp popcount of (x[i] > threshold) via __ballot_sync.
// Decode-coverage target: VOTE.BALLOT, predicate registers, POPC.

extern "C" __global__ void predicate_set(const float* __restrict__ x,
                                         float threshold,
                                         unsigned int* __restrict__ counts,
                                         int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned mask = 0xffffffffu;
    bool pred = (i < n) && (x[i] > threshold);
    unsigned ballot = __ballot_sync(mask, pred);
    if ((threadIdx.x & 31) == 0) {
        int warp_id = blockIdx.x * (blockDim.x / 32) + (threadIdx.x >> 5);
        counts[warp_id] = __popc(ballot);
    }
}
