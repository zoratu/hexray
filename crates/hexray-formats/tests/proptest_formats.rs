//! Property-based tests for binary format parsers.
//!
//! These tests verify that format parsers handle arbitrary input safely
//! and produce consistent results.

use proptest::prelude::*;

use hexray_formats::elf::Elf;
use hexray_formats::macho::MachO;
use hexray_formats::pe::Pe;
use hexray_formats::{detect_format, BinaryFormat, BinaryType};

// =============================================================================
// ELF Parser Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// ELF parsing never panics on arbitrary input.
    #[test]
    fn elf_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        // This should not panic - errors are fine
        let _ = Elf::parse(&data);
    }

    /// ELF parsing is deterministic.
    #[test]
    fn elf_parse_is_deterministic(data in prop::collection::vec(any::<u8>(), 64..512)) {
        let result1 = Elf::parse(&data);
        let result2 = Elf::parse(&data);

        match (&result1, &result2) {
            (Ok(_), Ok(_)) => {
                // Both succeeded - check basic properties match
                let elf1 = result1.unwrap();
                let elf2 = result2.unwrap();
                prop_assert_eq!(elf1.entry_point(), elf2.entry_point());
                prop_assert_eq!(elf1.architecture(), elf2.architecture());
            }
            (Err(_), Err(_)) => {
                // Both failed - consistent
            }
            _ => {
                prop_assert!(false, "Results should be consistent");
            }
        }
    }

    /// Valid ELF magic produces successful parse attempt.
    #[test]
    fn elf_magic_handling(
        e_class in 1u8..=2,  // 32-bit or 64-bit
        e_data in 1u8..=2,   // Little or big endian
        rest in prop::collection::vec(any::<u8>(), 52..256)
    ) {
        // Construct minimal ELF header with valid magic
        let mut data = vec![
            0x7F, b'E', b'L', b'F',  // ELF magic
            e_class,                  // 32-bit (1) or 64-bit (2)
            e_data,                   // Little (1) or big (2) endian
            1,                        // ELF version
            0,                        // OS ABI
            0, 0, 0, 0, 0, 0, 0, 0,  // Padding
        ];
        data.extend_from_slice(&rest);

        // Should not panic
        let _ = Elf::parse(&data);
    }

    /// ELF with various section counts doesn't panic.
    #[test]
    fn elf_section_count_handling(
        section_count in 0u16..100,
        data in prop::collection::vec(any::<u8>(), 64..512)
    ) {
        // Modify the section count in what might be an ELF header
        let mut modified = data.clone();
        if modified.len() >= 64 {
            // Section header count is at offset 60 (32-bit) or 60 (64-bit)
            // Just ensure we don't panic on any value
            if modified.len() > 61 {
                modified[60] = (section_count & 0xFF) as u8;
                modified[61] = ((section_count >> 8) & 0xFF) as u8;
            }
        }
        let _ = Elf::parse(&modified);
    }
}

// =============================================================================
// Mach-O Parser Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Mach-O parsing never panics on arbitrary input.
    #[test]
    fn macho_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = MachO::parse(&data);
    }

    /// Mach-O parsing is deterministic.
    #[test]
    fn macho_parse_is_deterministic(data in prop::collection::vec(any::<u8>(), 32..128)) {
        let result1 = MachO::parse(&data);
        let result2 = MachO::parse(&data);

        match (&result1, &result2) {
            (Ok(m1), Ok(m2)) => {
                prop_assert_eq!(m1.entry_point(), m2.entry_point());
                prop_assert_eq!(m1.architecture(), m2.architecture());
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "Results should be consistent"),
        }
    }

    /// Mach-O magic number handling.
    #[test]
    fn macho_magic_handling(
        magic in prop::sample::select(vec![
            0xFEEDFACE_u32, // 32-bit
            0xFEEDFACF,     // 64-bit
        ]),
        rest in prop::collection::vec(any::<u8>(), 28..64)
    ) {
        let magic_bytes = magic.to_le_bytes();
        let mut data = Vec::with_capacity(4 + rest.len());
        data.extend_from_slice(&magic_bytes);
        data.extend_from_slice(&rest);

        let _ = MachO::parse(&data);
    }

    /// Mach-O load command count handling.
    #[test]
    fn macho_load_cmd_count_handling(
        cmd_count in 0u32..100,
        data in prop::collection::vec(any::<u8>(), 32..128)
    ) {
        let mut modified = data.clone();
        if modified.len() >= 20 {
            // ncmds is at offset 16 in mach_header
            let bytes = cmd_count.to_le_bytes();
            modified[16..20].copy_from_slice(&bytes);
        }
        let _ = MachO::parse(&modified);
    }
}

// =============================================================================
// PE Parser Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// PE parsing never panics on arbitrary input.
    #[test]
    fn pe_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Pe::parse(&data);
    }

    /// PE parsing is deterministic.
    #[test]
    fn pe_parse_is_deterministic(data in prop::collection::vec(any::<u8>(), 64..512)) {
        let result1 = Pe::parse(&data);
        let result2 = Pe::parse(&data);

        match (&result1, &result2) {
            (Ok(_), Ok(_)) => {
                let p1 = result1.unwrap();
                let p2 = result2.unwrap();
                prop_assert_eq!(p1.entry_point(), p2.entry_point());
                prop_assert_eq!(p1.architecture(), p2.architecture());
            }
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "Results should be consistent"),
        }
    }

    /// PE DOS header magic handling.
    #[test]
    fn pe_dos_magic_handling(
        pe_offset in 64u32..256,
        rest in prop::collection::vec(any::<u8>(), 256..512)
    ) {
        let mut data = vec![0u8; 512.max(rest.len())];

        // DOS header magic
        data[0] = b'M';
        data[1] = b'Z';

        // PE header offset at 0x3C
        let offset_bytes = pe_offset.to_le_bytes();
        data[0x3C..0x40].copy_from_slice(&offset_bytes);

        // PE signature at offset
        if pe_offset as usize + 4 < data.len() {
            data[pe_offset as usize] = b'P';
            data[pe_offset as usize + 1] = b'E';
            data[pe_offset as usize + 2] = 0;
            data[pe_offset as usize + 3] = 0;
        }

        // Fill rest
        for (i, byte) in rest.iter().enumerate() {
            if pe_offset as usize + 4 + i < data.len() {
                data[pe_offset as usize + 4 + i] = *byte;
            }
        }

        let _ = Pe::parse(&data);
    }

    /// PE section count handling.
    #[test]
    fn pe_section_count_handling(
        section_count in 0u16..100,
        data in prop::collection::vec(any::<u8>(), 256..512)
    ) {
        let mut modified = data.clone();
        // Section count would be at COFF header + 2
        // Just make sure we don't panic on various values
        if modified.len() >= 100 {
            modified[98] = (section_count & 0xFF) as u8;
            modified[99] = ((section_count >> 8) & 0xFF) as u8;
        }
        let _ = Pe::parse(&modified);
    }
}

// =============================================================================
// Format Detection Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// Format detection never panics.
    #[test]
    fn detect_format_never_panics(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = detect_format(&data);
    }

    /// Format detection is deterministic.
    #[test]
    fn detect_format_is_deterministic(data in prop::collection::vec(any::<u8>(), 4..128)) {
        let result1 = detect_format(&data);
        let result2 = detect_format(&data);
        prop_assert_eq!(result1, result2, "Format detection should be deterministic");
    }

    /// ELF magic should be detected as ELF.
    #[test]
    fn elf_magic_detected(rest in prop::collection::vec(any::<u8>(), 12..64)) {
        let mut data = vec![0x7F, b'E', b'L', b'F'];
        data.extend_from_slice(&rest);

        let format = detect_format(&data);
        prop_assert_eq!(
            format,
            BinaryType::Elf,
            "ELF magic should be detected as ELF format"
        );
    }

    /// PE magic should be detected as PE.
    #[test]
    fn pe_magic_detected(rest in prop::collection::vec(any::<u8>(), 60..256)) {
        let mut data = vec![b'M', b'Z'];
        data.extend(vec![0u8; 58]); // Padding to 0x3C

        // PE offset at 0x3C pointing to 0x80
        data.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);

        // Padding to PE signature location
        data.extend(vec![0u8; 0x80 - 64]);

        // PE signature
        data.extend_from_slice(&[b'P', b'E', 0x00, 0x00]);

        // COFF header (at least machine type)
        data.extend_from_slice(&[0x64, 0x86]); // AMD64

        data.extend_from_slice(&rest);

        let format = detect_format(&data);
        prop_assert_eq!(
            format,
            BinaryType::Pe,
            "PE magic should be detected as PE format"
        );
    }
}

// =============================================================================
// BinaryFormat Trait Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Successfully parsed binaries have consistent properties.
    #[test]
    fn parsed_binary_properties_consistent(data in prop::collection::vec(any::<u8>(), 64..512)) {
        // Try all formats
        if let Ok(elf) = Elf::parse(&data) {
            // Check consistency
            let arch = elf.architecture();
            let entry = elf.entry_point();

            // Re-query should give same results
            prop_assert_eq!(elf.architecture(), arch);
            prop_assert_eq!(elf.entry_point(), entry);

            // Sections should be consistent
            let sections1: Vec<_> = elf.executable_sections().collect();
            let sections2: Vec<_> = elf.executable_sections().collect();
            prop_assert_eq!(sections1.len(), sections2.len());
        }

        if let Ok(macho) = MachO::parse(&data) {
            let arch = macho.architecture();
            let entry = macho.entry_point();

            prop_assert_eq!(macho.architecture(), arch);
            prop_assert_eq!(macho.entry_point(), entry);
        }

        if let Ok(pe) = Pe::parse(&data) {
            let arch = pe.architecture();
            let entry = pe.entry_point();

            prop_assert_eq!(pe.architecture(), arch);
            prop_assert_eq!(pe.entry_point(), entry);
        }
    }
}

// =============================================================================
// CUDA Container Properties
// =============================================================================
//
// These cover the new CUDA-specific surfaces that landed under the
// gpu-support work: NvInfo TLV framing, fatbin wrapper parsing, PTX
// sidecar parsing, and the CubinView heuristics. Every property has the
// same shape: feed adversarial input and assert the parser never panics
// and behaves deterministically.

mod cuda {
    use proptest::prelude::*;

    use hexray_formats::{elf::cuda::parse_nv_info, FatbinError, FatbinWrapper, PtxIndex};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// `parse_nv_info` is total — never panics.
        #[test]
        fn nv_info_parse_total(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_nv_info(&bytes);
        }

        /// `parse_nv_info` is deterministic.
        #[test]
        fn nv_info_parse_deterministic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let a = parse_nv_info(&bytes);
            let b = parse_nv_info(&bytes);
            prop_assert_eq!(a.entries.len(), b.entries.len());
            prop_assert_eq!(a.truncated, b.truncated);
        }

        /// Every NvInfo entry's payload range stays inside the input.
        #[test]
        fn nv_info_entry_payloads_in_bounds(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let blob = parse_nv_info(&bytes);
            for entry in &blob.entries {
                let start = entry.payload_offset as usize;
                let end = start.saturating_add(entry.payload_size as usize);
                prop_assert!(end <= bytes.len(),
                    "entry payload out of bounds: {start}..{end} vs {}", bytes.len());
            }
        }

        /// Fatbin parsing is total — every input either parses cleanly or
        /// returns a typed FatbinError; never panics.
        #[test]
        fn fatbin_parse_total(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = FatbinWrapper::parse(&bytes);
        }

        /// When fatbin parsing succeeds, every entry's payload slice is
        /// strictly inside the input buffer.
        #[test]
        fn fatbin_entry_payloads_in_bounds(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            if let Ok(w) = FatbinWrapper::parse(&bytes) {
                for entry in &w.entries {
                    // The entry's payload is a sub-slice of `bytes`.
                    let payload_ptr = entry.payload.as_ptr() as usize;
                    let buffer_start = bytes.as_ptr() as usize;
                    let buffer_end = buffer_start + bytes.len();
                    prop_assert!(payload_ptr >= buffer_start && payload_ptr <= buffer_end);
                    prop_assert!(payload_ptr + entry.payload.len() <= buffer_end);
                }
            }
        }

        /// `FatbinError::Truncated` always fires for inputs shorter than 16 bytes.
        #[test]
        fn fatbin_short_input_truncated(bytes in prop::collection::vec(any::<u8>(), 0..16)) {
            match FatbinWrapper::parse(&bytes) {
                Err(FatbinError::Truncated { needed: 16, have }) => {
                    prop_assert_eq!(have, bytes.len());
                }
                other => prop_assert!(false, "expected Truncated, got {other:?}"),
            }
        }

        /// PTX parsing is total over arbitrary UTF-8.
        #[test]
        fn ptx_parse_total(text in any::<String>()) {
            let _ = PtxIndex::parse(&text);
        }

        /// PTX parsing of NUL-delimited byte streams is total.
        #[test]
        fn ptx_nul_delimited_total(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = PtxIndex::from_nul_delimited_bytes(&bytes);
        }

        /// PTX function spans always lie within the parsed text.
        #[test]
        fn ptx_function_spans_in_bounds(text in any::<String>()) {
            let idx = PtxIndex::parse(&text);
            let len = idx.raw.len();
            for f in &idx.functions {
                prop_assert!(f.body_start <= f.body_end);
                prop_assert!(f.body_end <= len);
                prop_assert!(f.header.start <= f.header.end);
                prop_assert!(f.header.end <= len);
            }
        }
    }
}
