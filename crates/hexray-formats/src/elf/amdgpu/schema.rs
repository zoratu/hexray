//! Typed AMDGPU kernel resource usage.
//!
//! Mirrors the role of the CUDA `KernelResourceUsage`: a single struct
//! the rest of the toolchain (CFG builder, signature recovery, the
//! `hexray cmp` cross-vendor comparator) can query without caring
//! whether the source is CUDA or AMDGPU.
//!
//! The shape is intentionally similar where the vendors line up
//! (kernarg/param size, entry offset, kernel name) but distinct where
//! they don't (vgprs/sgprs vs CUDA's single `regs`, LDS vs CUDA's
//! shared, scratch vs CUDA's local).

/// AMDGPU per-kernel resource usage decoded from the kernel
/// descriptor and (optionally) the `NT_AMDGPU_METADATA` MessagePack
/// blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmdKernelResourceUsage {
    /// Decoded VGPR count from COMPUTE_PGM_RSRC1[5:0] adjusted for
    /// the wave size and family granule.
    pub vgpr_count: u16,
    /// Decoded SGPR count.
    pub sgpr_count: u16,
    /// User-provided SGPRs (kernel-arg pointer, queue ptr, etc.).
    pub user_sgpr_count: u8,
    /// LDS bytes computed from `granulated_lds_size`.
    pub lds_bytes: u32,
    /// Static private-segment (scratch) bytes.
    pub scratch_bytes: u32,
    /// Kernel-argument buffer size.
    pub kernarg_size: u32,
    /// True when the kernel was emitted in wave32 mode (GFX10+ only).
    pub wave32: bool,
}

impl AmdKernelResourceUsage {
    /// Build a summary from a parsed descriptor + the family major
    /// number (needed to disambiguate VGPR granule).
    pub fn from_descriptor(
        descriptor: &super::descriptor::KernelDescriptor,
        family_major: u8,
    ) -> Self {
        Self {
            vgpr_count: descriptor.vgpr_count(family_major),
            sgpr_count: descriptor.sgpr_count(),
            user_sgpr_count: descriptor.user_sgpr_count(),
            lds_bytes: descriptor
                .group_segment_fixed_size
                .saturating_add(descriptor.dynamic_lds_bytes()),
            scratch_bytes: descriptor.private_segment_fixed_size,
            kernarg_size: descriptor.kernarg_size,
            wave32: descriptor.is_wave32(),
        }
    }
}
