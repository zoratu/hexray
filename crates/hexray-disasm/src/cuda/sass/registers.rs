//! SASS register naming helpers.
//!
//! Volta+ targets five disjoint register files:
//!
//! - **R** — general-purpose registers. `R0..R254`; `R255` is the zero
//!   register `RZ`. 32-bit each; some instructions consume `R{n}:R{n+1}`
//!   pairs for 64-bit values or 4-wide groups for vector loads.
//! - **P** — predicate registers. `P0..P6`; `P7` is the always-true
//!   alias `PT`.
//! - **UR** — uniform registers (Turing+). `UR0..UR62`; `UR63 = URZ`.
//! - **UP** — uniform predicate registers. `UP0..UP6`; `UP7 = UPT`.
//! - **SR** — special registers (e.g. `SR_TID.X`, `SR_LANEID`). IDs
//!   indexed 0..=254 via `S2R`. `nvdisasm` prints mnemonic names for the
//!   common ones; M3 stubs the table and falls back to `SR<n>`.
//!
//! The design review explicitly pushed back on modelling register pairs
//! or quads as fake register IDs. We don't. Instead the decoder tracks a
//! [`RegisterSpan`] at operand rendering time; the core [`Register`]
//! remains a single-slot 32-bit handle.

use hexray_core::{Architecture, CudaArchitecture, Register, RegisterClass, SmArchitecture};

/// Numeric IDs for each SASS register file. These become the low bits of
/// the core [`Register::id`] field; we stuff the file (R/P/UR/UP/SR)
/// into the upper nibble so the CUDA renderer can dispatch off `class` +
/// an ID offset.
pub mod id {
    /// `RZ` is encoded as register 255 in the R file.
    pub const RZ: u16 = 255;
    /// `PT` is the always-true predicate alias, encoded as index 7 in the
    /// P file.
    pub const PT: u16 = 7;
    /// `URZ` is the uniform-register zero, index 63 of the UR file.
    pub const URZ: u16 = 63;
    /// `UPT` is the always-true uniform predicate, index 7 of the UP file.
    pub const UPT: u16 = 7;
}

/// A span of consecutive general registers, used to model pair/quad
/// operands (e.g. 64-bit load targets, 128-bit vector loads). The
/// decoder uses this internally; the core [`Register`] type always
/// refers to a single slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterSpan {
    /// Starting register index within the R file.
    pub base: u16,
    /// Number of consecutive slots this span covers (1, 2, 4, 8).
    pub width: u8,
}

impl RegisterSpan {
    /// Single-register span.
    pub const fn single(base: u16) -> Self {
        Self { base, width: 1 }
    }

    /// 64-bit pair span, `R{base}:R{base+1}`.
    pub const fn pair(base: u16) -> Self {
        Self { base, width: 2 }
    }

    /// Is this an aligned span for its width? Real SASS requires 64-bit
    /// pairs to be even-aligned and 128-bit quads to be 4-aligned.
    pub fn is_aligned(&self) -> bool {
        match self.width {
            1 => true,
            2 => self.base % 2 == 0,
            4 => self.base % 4 == 0,
            8 => self.base % 8 == 0,
            _ => false,
        }
    }

    /// Canonical `nvdisasm` textual form. A single register is `R{n}`
    /// (or `RZ` when `n == 255`); wider spans are `R{n}:R{n + width - 1}`.
    pub fn canonical_name(&self) -> String {
        if self.width == 1 {
            return canonical_r(self.base);
        }
        let end = self.base.wrapping_add(self.width as u16).wrapping_sub(1);
        format!("R{}:R{}", self.base, end)
    }
}

fn canonical_r(id: u16) -> String {
    if id == id::RZ {
        "RZ".to_string()
    } else {
        format!("R{}", id)
    }
}

fn canonical_p(id: u16) -> String {
    if id == id::PT {
        "PT".to_string()
    } else {
        format!("P{}", id)
    }
}

fn canonical_ur(id: u16) -> String {
    if id == id::URZ {
        "URZ".to_string()
    } else {
        format!("UR{}", id)
    }
}

fn canonical_up(id: u16) -> String {
    if id == id::UPT {
        "UPT".to_string()
    } else {
        format!("UP{}", id)
    }
}

/// Build a core [`Register`] for an SM-scoped general-purpose slot.
pub fn r(sm: SmArchitecture, id: u16) -> Register {
    Register::new(
        Architecture::Cuda(CudaArchitecture::Sass(sm)),
        RegisterClass::General,
        id,
        32,
    )
}

/// Build a core predicate [`Register`].
pub fn p(sm: SmArchitecture, id: u16) -> Register {
    Register::new(
        Architecture::Cuda(CudaArchitecture::Sass(sm)),
        RegisterClass::Predicate,
        id,
        1,
    )
}

/// Build a core uniform-register [`Register`]. Stored in the general
/// class with a distinguishing ID offset so the CUDA renderer can tell
/// uniform from regular.
pub fn ur(sm: SmArchitecture, id: u16) -> Register {
    // Offset uniform-register IDs by 0x1000 so a plain `R{id}` and a
    // `UR{id}` that share a numeric index don't collide in the core
    // representation. The renderer strips the offset before printing.
    Register::new(
        Architecture::Cuda(CudaArchitecture::Sass(sm)),
        RegisterClass::General,
        id | UNIFORM_REG_MARKER,
        32,
    )
}

/// Build a core uniform-predicate [`Register`].
pub fn up(sm: SmArchitecture, id: u16) -> Register {
    Register::new(
        Architecture::Cuda(CudaArchitecture::Sass(sm)),
        RegisterClass::Predicate,
        id | UNIFORM_PRED_MARKER,
        1,
    )
}

/// Build a core special-register [`Register`] (accessed via `S2R`).
pub fn sr(sm: SmArchitecture, id: u16) -> Register {
    Register::new(
        Architecture::Cuda(CudaArchitecture::Sass(sm)),
        RegisterClass::Other,
        id,
        32,
    )
}

/// Marker bit added to uniform-register IDs inside the core [`Register`]
/// to distinguish `UR{n}` from `R{n}`. Consumers that care inspect bit
/// [`UNIFORM_REG_MARKER`]; everyone else sees IDs in the same space.
pub const UNIFORM_REG_MARKER: u16 = 0x1000;

/// Same idea for uniform predicates.
pub const UNIFORM_PRED_MARKER: u16 = 0x1000;

/// Return the canonical `nvdisasm` textual name for a core [`Register`]
/// that was produced by one of the helpers in this module.
pub fn render(reg: &Register) -> String {
    match reg.class {
        RegisterClass::General => {
            let is_uniform = reg.id & UNIFORM_REG_MARKER != 0;
            let raw = reg.id & !UNIFORM_REG_MARKER;
            if is_uniform {
                canonical_ur(raw)
            } else {
                canonical_r(raw)
            }
        }
        RegisterClass::Predicate => {
            let is_uniform = reg.id & UNIFORM_PRED_MARKER != 0;
            let raw = reg.id & !UNIFORM_PRED_MARKER;
            if is_uniform {
                canonical_up(raw)
            } else {
                canonical_p(raw)
            }
        }
        RegisterClass::Other => special_register_name(reg.id),
        _ => format!("?{}", reg.id),
    }
}

/// Mnemonic names for the handful of special registers M3 cares about.
/// Full coverage (all 256 slots) lands in M4/M7 alongside the S2R decoder.
fn special_register_name(id: u16) -> String {
    match id {
        0 => "SR_LANEID".into(),
        1 => "SR_CLOCK".into(),
        2 => "SR_VIRTCFG".into(),
        3 => "SR_VIRTID".into(),
        32 => "SR_TID.X".into(),
        33 => "SR_TID.Y".into(),
        34 => "SR_TID.Z".into(),
        36 => "SR_CTAID.X".into(),
        37 => "SR_CTAID.Y".into(),
        38 => "SR_CTAID.Z".into(),
        40 => "SR_NTID.X".into(),
        41 => "SR_NTID.Y".into(),
        42 => "SR_NTID.Z".into(),
        44 => "SR_NCTAID.X".into(),
        45 => "SR_NCTAID.Y".into(),
        46 => "SR_NCTAID.Z".into(),
        other => format!("SR{}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::SmVariant;

    fn sm80() -> SmArchitecture {
        SmArchitecture::new(8, 0, SmVariant::Base)
    }

    #[test]
    fn rz_and_pt_canonical() {
        let reg = r(sm80(), id::RZ);
        assert_eq!(render(&reg), "RZ");

        let pt = p(sm80(), id::PT);
        assert_eq!(render(&pt), "PT");
    }

    #[test]
    fn regular_general_register_formats_as_r_n() {
        assert_eq!(render(&r(sm80(), 17)), "R17");
    }

    #[test]
    fn uniform_register_distinguishable_from_general() {
        let reg = ur(sm80(), 5);
        let general = r(sm80(), 5);
        assert_ne!(reg.id, general.id); // distinguishable in core IR
        assert_eq!(render(&reg), "UR5");
        assert_eq!(render(&general), "R5");
    }

    #[test]
    fn uniform_zero_aliases_urz() {
        assert_eq!(render(&ur(sm80(), id::URZ)), "URZ");
        assert_eq!(render(&up(sm80(), id::UPT)), "UPT");
    }

    #[test]
    fn special_register_mnemonics() {
        let sm = sm80();
        assert_eq!(render(&sr(sm, 32)), "SR_TID.X");
        assert_eq!(render(&sr(sm, 36)), "SR_CTAID.X");
        assert_eq!(render(&sr(sm, 137)), "SR137"); // unknown falls back
    }

    #[test]
    fn register_span_pair_alignment() {
        assert!(RegisterSpan::pair(0).is_aligned());
        assert!(RegisterSpan::pair(4).is_aligned());
        assert!(!RegisterSpan::pair(1).is_aligned());
        assert!(!RegisterSpan::pair(5).is_aligned());
        assert_eq!(RegisterSpan::pair(4).canonical_name(), "R4:R5");
        assert_eq!(RegisterSpan::single(255).canonical_name(), "RZ");
    }

    #[test]
    fn register_span_quad_and_octet_alignment() {
        assert!(RegisterSpan { base: 4, width: 4 }.is_aligned());
        assert!(!RegisterSpan { base: 5, width: 4 }.is_aligned());
        assert!(RegisterSpan { base: 8, width: 8 }.is_aligned());
        assert!(!RegisterSpan { base: 9, width: 8 }.is_aligned());
        assert!(!RegisterSpan { base: 0, width: 3 }.is_aligned()); // unsupported width
        assert_eq!(RegisterSpan { base: 4, width: 4 }.canonical_name(), "R4:R7");
        assert_eq!(
            RegisterSpan { base: 8, width: 8 }.canonical_name(),
            "R8:R15"
        );
    }

    #[test]
    fn predicate_register_naming_full_range() {
        // P0..P6 + PT.
        for i in 0..7 {
            assert_eq!(render(&p(sm80(), i)), format!("P{i}"));
        }
        assert_eq!(render(&p(sm80(), id::PT)), "PT");
    }

    #[test]
    fn uniform_predicate_naming() {
        for i in 0..7 {
            let reg = up(sm80(), i);
            assert_eq!(render(&reg), format!("UP{i}"));
        }
        assert_eq!(render(&up(sm80(), id::UPT)), "UPT");
    }

    #[test]
    fn uniform_marker_bit_is_set_via_or() {
        // The marker bit must be combined with the raw ID via bitwise OR
        // so the raw ID is recoverable. To distinguish OR from XOR
        // (which would clear the bit when both inputs have it), drive
        // with raw IDs whose marker bit is already set as well as
        // unset — the OR path produces the same result for both,
        // while XOR diverges.
        for raw_id in [0u16, 1, 0x42, UNIFORM_REG_MARKER, UNIFORM_REG_MARKER | 0x1] {
            let stored = ur(sm80(), raw_id).id;
            assert_eq!(
                stored & UNIFORM_REG_MARKER,
                UNIFORM_REG_MARKER,
                "ur({raw_id:#x}) did not set the marker bit"
            );
        }
        for raw_id in [0u16, 5, UNIFORM_PRED_MARKER, UNIFORM_PRED_MARKER | 0x4] {
            let stored = up(sm80(), raw_id).id;
            assert_eq!(
                stored & UNIFORM_PRED_MARKER,
                UNIFORM_PRED_MARKER,
                "up({raw_id:#x}) did not set the marker bit"
            );
        }
    }

    #[test]
    fn register_span_single_aligned_always() {
        // RegisterSpan::single(N) for any N must report aligned. Catches a
        // `1 => true` arm deletion in is_aligned.
        for base in 0..=255u16 {
            assert!(
                RegisterSpan::single(base).is_aligned(),
                "single span at base {base} should be aligned"
            );
        }
    }

    #[test]
    fn special_register_full_table_coverage() {
        let sm = sm80();
        // All named slots in the SR table.
        for (id, want) in &[
            (0u16, "SR_LANEID"),
            (1, "SR_CLOCK"),
            (2, "SR_VIRTCFG"),
            (3, "SR_VIRTID"),
            (32, "SR_TID.X"),
            (33, "SR_TID.Y"),
            (34, "SR_TID.Z"),
            (36, "SR_CTAID.X"),
            (37, "SR_CTAID.Y"),
            (38, "SR_CTAID.Z"),
            (40, "SR_NTID.X"),
            (41, "SR_NTID.Y"),
            (42, "SR_NTID.Z"),
            (44, "SR_NCTAID.X"),
            (45, "SR_NCTAID.Y"),
            (46, "SR_NCTAID.Z"),
        ] {
            assert_eq!(render(&sr(sm, *id)), *want);
        }
    }
}
