//! GPU container formats that aren't themselves ELFs.
//!
//! The ELF-layer GPU views (CUBIN, AMDGPU code object) live under
//! [`crate::elf`]. This module is for the *outer* containers a GPU
//! toolkit produces when it embeds one-or-more device objects (and
//! sometimes IR sidecars) into a host binary.
//!
//! Currently covers:
//!
//! - [`fatbin::FatbinWrapper`] — the NVIDIA `fatbinary` container
//!   (magic `0xBA55_ED50`) that `nvcc` embeds into a host ELF/PE/Mach-O
//!   binary as the payload of the symbol `__nv_fatbin` or section
//!   `.nv_fatbin`.
//! - [`fatbin::FatbinEntry`] — one SM-specific entry inside a wrapper
//!   (typically a cubin, sometimes a PTX blob).
//! - [`hip_fatbin::HipBundleWrapper`] — the Clang offload bundle
//!   (magic `__CLANG_OFFLOAD_BUNDLE__`) that `hipcc` / `clang -fhip`
//!   embeds into a host binary as the payload of `__hip_fatbin` /
//!   `.hip_fatbin`.
//! - [`hip_fatbin::HipBundleEntry`] — one per-`gfx*` AMDGPU code
//!   object (or the host bundle) inside a HIP wrapper.

pub mod fatbin;
pub mod hip_fatbin;

pub use fatbin::{FatbinEntry, FatbinEntryKind, FatbinError, FatbinWrapper};
pub use hip_fatbin::{HipBundleEntry, HipBundleEntryKind, HipBundleError, HipBundleWrapper};
