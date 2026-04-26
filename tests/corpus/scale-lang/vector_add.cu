// vector_add.cu — the canonical CUDA kernel used by the scale-lang
// interop demo. Identical source compiles to:
//   - an NVIDIA cubin via `scale --cubin -arch=sm_80 vector_add.cu`
//   - an AMDGPU code object via `scale --hsaco -arch=gfx906 vector_add.cu`
//
// `hexray cmp` against both outputs reports kernel-signature
// equivalence: same param count, same per-arg sizes, same kernarg
// total. The vgpr / sgpr counts and basic-block shape will *differ*
// (those depend on the target ISA's codegen), and the comparator
// flags those as informational rather than structural.

extern "C" __global__ void vector_add(const float* a,
                                      const float* b,
                                      float* c,
                                      int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        c[i] = a[i] + b[i];
    }
}
