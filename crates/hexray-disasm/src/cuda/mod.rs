//! NVIDIA CUDA decoders.
//!
//! Currently exposes the SASS (native GPU) decoder for Volta and newer
//! (16-byte fixed-width encoding). PTX decoding, if it ever lands, will
//! live alongside as a peer submodule.
//!
//! See `docs/CUDA.md` in the repository root for the architecture and
//! user-facing guide.

pub mod sass;

pub use sass::SassDisassembler;
