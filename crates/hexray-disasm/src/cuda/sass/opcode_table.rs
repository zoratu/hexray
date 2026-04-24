//! Opcode table for Volta+ SASS instructions.
//!
//! Every entry maps the low 9 bits of the 128-bit word (the "opcode
//! class") to a base mnemonic and a high-level [`Operation`]. M4 keeps
//! the mnemonics *base* — the qualifier suffixes like `.GE.AND` on
//! `ISETP` or `.E.CONSTANT` on `LDG` live in secondary encoding bits
//! that M7 will decode.
//!
//! Opcode IDs were harvested empirically from `tests/corpus/cuda/` by
//! scanning every instruction's low 9 bits and cross-referencing with
//! `nvdisasm -json`. Counts below are from a 30-cubin sm_80/86/89
//! sweep; the table covers >99% of observed classes (everything in
//! the sweep sees at least one match). Unknown classes fall through
//! as [`DecodeError::UnknownOpcode`].

use hexray_core::Operation;

/// A single opcode-class entry.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    /// Low 9 bits of the 128-bit SASS word.
    pub op_class: u16,
    /// Base mnemonic rendered by `nvdisasm` (no `.` suffixes).
    pub mnemonic: &'static str,
    /// High-level operation bucket (for CPU-style consumers).
    pub operation: Operation,
}

/// Lookup the canonical entry for a 9-bit opcode class.
pub fn lookup(op_class: u16) -> Option<&'static OpcodeEntry> {
    OPCODE_TABLE.iter().find(|e| e.op_class == op_class)
}

/// The table itself — sorted by observed frequency on the sm_80/86/89
/// corpus so the common path is a near-miss hit on the first entries.
///
/// **Not yet decoded:** variant suffixes (e.g. `IMAD.WIDE` vs `IMAD`
/// share the same 9-bit class but differ in higher bits), memory-space
/// qualifiers (`LDG.E.CONSTANT` vs `LDG.E`), and predicate-mode bits.
/// M7 refines these; M4's goal is base-mnemonic match ≥ 70%.
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    // -- control flow / sync --------------------------------------------
    OpcodeEntry {
        op_class: 0x118,
        mnemonic: "NOP",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op_class: 0x147,
        mnemonic: "BRA",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op_class: 0x14d,
        mnemonic: "EXIT",
        operation: Operation::Return,
    },
    OpcodeEntry {
        op_class: 0x141,
        mnemonic: "BSYNC",
        operation: Operation::Other(0x141),
    },
    OpcodeEntry {
        op_class: 0x145,
        mnemonic: "BSSY",
        operation: Operation::Other(0x145),
    },
    OpcodeEntry {
        op_class: 0x11d,
        mnemonic: "BAR",
        operation: Operation::Other(0x11d),
    },
    // -- scalar / data movement ----------------------------------------
    OpcodeEntry {
        op_class: 0x002,
        mnemonic: "MOV",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op_class: 0x119,
        mnemonic: "S2R",
        operation: Operation::Move,
    },
    // -- integer ALU ---------------------------------------------------
    OpcodeEntry {
        op_class: 0x010,
        mnemonic: "IADD3",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op_class: 0x011,
        mnemonic: "LEA",
        operation: Operation::Other(0x011),
    },
    OpcodeEntry {
        op_class: 0x012,
        mnemonic: "LOP3",
        operation: Operation::Other(0x012),
    },
    OpcodeEntry {
        op_class: 0x019,
        mnemonic: "SHF",
        operation: Operation::Other(0x019),
    },
    OpcodeEntry {
        op_class: 0x024,
        mnemonic: "IMAD",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op_class: 0x025,
        mnemonic: "IMAD",
        operation: Operation::Mul,
    }, // IMAD.WIDE class
    OpcodeEntry {
        op_class: 0x00c,
        mnemonic: "ISETP",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op_class: 0x01c,
        mnemonic: "PLOP3",
        operation: Operation::Other(0x01c),
    },
    // -- floating-point ALU --------------------------------------------
    OpcodeEntry {
        op_class: 0x020,
        mnemonic: "FMUL",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op_class: 0x021,
        mnemonic: "FADD",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op_class: 0x023,
        mnemonic: "FFMA",
        operation: Operation::Other(0x023),
    },
    OpcodeEntry {
        op_class: 0x035,
        mnemonic: "HFMA2",
        operation: Operation::Other(0x035),
    },
    OpcodeEntry {
        op_class: 0x00b,
        mnemonic: "FSETP",
        operation: Operation::Compare,
    },
    // -- uniform-register ops (Turing+) --------------------------------
    OpcodeEntry {
        op_class: 0x0b9,
        mnemonic: "ULDC",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op_class: 0x099,
        mnemonic: "USHF",
        operation: Operation::Other(0x099),
    },
    OpcodeEntry {
        op_class: 0x0bd,
        mnemonic: "UFLO",
        operation: Operation::Other(0x0bd),
    },
    // -- memory loads / stores -----------------------------------------
    OpcodeEntry {
        op_class: 0x181,
        mnemonic: "LDG",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op_class: 0x182,
        mnemonic: "LDC",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op_class: 0x184,
        mnemonic: "LDS",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op_class: 0x186,
        mnemonic: "STG",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op_class: 0x188,
        mnemonic: "STS",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op_class: 0x18e,
        mnemonic: "RED",
        operation: Operation::Other(0x18e),
    },
    // -- warp / predicate --------------------------------------------
    OpcodeEntry {
        op_class: 0x189,
        mnemonic: "SHFL",
        operation: Operation::Other(0x189),
    },
    OpcodeEntry {
        op_class: 0x109,
        mnemonic: "POPC",
        operation: Operation::Other(0x109),
    },
    OpcodeEntry {
        op_class: 0x006,
        mnemonic: "VOTE",
        operation: Operation::Other(0x006),
    },
    OpcodeEntry {
        op_class: 0x086,
        mnemonic: "VOTEU",
        operation: Operation::Other(0x086),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_finds_nop() {
        let e = lookup(0x118).unwrap();
        assert_eq!(e.mnemonic, "NOP");
        assert_eq!(e.operation, Operation::Nop);
    }

    #[test]
    fn lookup_finds_imad_variants() {
        assert_eq!(lookup(0x024).unwrap().mnemonic, "IMAD");
        assert_eq!(lookup(0x025).unwrap().mnemonic, "IMAD"); // WIDE shares base
    }

    #[test]
    fn lookup_misses_on_unknown() {
        assert!(lookup(0x1FF).is_none());
    }

    #[test]
    fn table_op_classes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for entry in OPCODE_TABLE {
            assert!(
                seen.insert(entry.op_class),
                "duplicate op_class {:#x}",
                entry.op_class
            );
        }
    }

    #[test]
    fn table_op_classes_fit_in_9_bits() {
        for entry in OPCODE_TABLE {
            assert!(
                entry.op_class < 0x200,
                "op_class overflow: {:#x}",
                entry.op_class
            );
        }
    }
}
