//! CUDA container formats that aren't themselves ELFs.
//!
//! The ELF-layer CUDA view (CUBIN) lives under [`crate::elf::cuda`] —
//! a CUBIN is just an EM_CUDA ELF. This module is for the *outer*
//! containers a CUDA toolkit produces when it embeds one-or-more
//! cubins and PTX sidecars into a host binary: "fatbin" wrappers.
//!
//! Currently covers:
//!
//! - [`fatbin::FatbinWrapper`] — the NVIDIA `fatbinary` container
//!   (magic `0xBA55_ED50`) that `nvcc` embeds into a host ELF/PE/Mach-O
//!   binary as the payload of the symbol `__nv_fatbin` or section
//!   `.nv_fatbin`.
//! - [`fatbin::FatbinEntry`] — one SM-specific entry inside a wrapper
//!   (typically a cubin, sometimes a PTX blob).

pub mod fatbin;

pub use fatbin::{FatbinEntry, FatbinEntryKind, FatbinError, FatbinWrapper};
