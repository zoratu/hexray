//! NVIDIA CUDA decoders.
//!
//! Currently exposes the SASS (native GPU) decoder. PTX decoding, if it
//! ever lands, will live alongside as a peer submodule.

pub mod sass;

pub use sass::SassDisassembler;
