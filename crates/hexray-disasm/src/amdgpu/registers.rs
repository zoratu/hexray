//! AMDGPU register-file naming.
//!
//! M10.3 ships skeletal register support: the encoding classifier
//! emits class + opcode placeholder names but doesn't decode operand
//! fields yet. M10.4 lifts SRC0/SRC1/SRC2/VDST decode into real
//! register references using the AMDGPU operand-encoding table:
//!
//! ```text
//!   0..101    SGPRs (S0..S101)
//!   102..127  special — VCC_LO/HI, EXEC_LO/HI, SCC, M0, NULL, ...
//!   128..192  signed inline constants -16..64
//!   193..208  hex inline constants 0.5, 1.0, ...
//!   209..240  misc constants
//!   241..255  unused / reserved
//!   256..511  VGPRs (V0..V255)
//! ```

/// Pretty-print a 9-bit AMDGPU operand ID (`SRC0` field width).
///
/// Returns one of `s{n}`, `v{n}`, `vcc_lo`, `exec`, etc., or
/// `op:0xNNN` for unrecognised IDs.
pub fn operand_name(id: u16) -> String {
    match id {
        0..=101 => format!("s{id}"),
        106 => "vcc_lo".to_string(),
        107 => "vcc_hi".to_string(),
        124 => "m0".to_string(),
        126 => "exec_lo".to_string(),
        127 => "exec_hi".to_string(),
        128..=192 => {
            // Signed inline constants: 128 → 0, 129 → 1, ..., 192 → 64,
            // and 193..=208 are negative half then small floats.
            let signed = (id as i16).wrapping_sub(128);
            format!("{signed}")
        }
        240 => "0.5".to_string(),
        242 => "1.0".to_string(),
        244 => "2.0".to_string(),
        246 => "4.0".to_string(),
        256..=511 => format!("v{}", id.wrapping_sub(256)),
        _ => format!("op:0x{id:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgprs_render_with_s_prefix() {
        assert_eq!(operand_name(0), "s0");
        assert_eq!(operand_name(101), "s101");
    }

    #[test]
    fn vgprs_render_with_v_prefix_offset_by_256() {
        assert_eq!(operand_name(256), "v0");
        assert_eq!(operand_name(257), "v1");
        assert_eq!(operand_name(511), "v255");
    }

    #[test]
    fn special_registers_have_expected_names() {
        assert_eq!(operand_name(106), "vcc_lo");
        assert_eq!(operand_name(107), "vcc_hi");
        assert_eq!(operand_name(124), "m0");
        assert_eq!(operand_name(126), "exec_lo");
        assert_eq!(operand_name(127), "exec_hi");
    }

    #[test]
    fn float_inline_constants_render_with_decimal() {
        // The hex / float inline-constant slots fall outside the
        // signed-integer range and have explicit string forms.
        assert_eq!(operand_name(240), "0.5");
        assert_eq!(operand_name(242), "1.0");
        assert_eq!(operand_name(244), "2.0");
        assert_eq!(operand_name(246), "4.0");
    }

    #[test]
    fn inline_constants_render_signed() {
        assert_eq!(operand_name(128), "0");
        assert_eq!(operand_name(129), "1");
        assert_eq!(operand_name(192), "64");
    }

    #[test]
    fn unknown_id_falls_through_to_hex() {
        assert_eq!(operand_name(220), "op:0xdc");
        // ID 241 is in the gap between the float-constant slots and is
        // not a recognised name, so it must fall through to the hex
        // placeholder rather than borrowing a neighbouring arm.
        assert_eq!(operand_name(241), "op:0xf1");
    }
}
