//! Self-check for the synthetic analysis fixture.
//!
//! The database acceleration tests treat the fixture layout as ground truth, so
//! the generator itself is verified here: the ELF structure, the symbol table,
//! the call encodings, the declared sizes and the entropy variants must all
//! agree with the returned [`FixtureLayout`].

#[path = "common/analysis_fixture.rs"]
mod analysis_fixture;

use hexray_core::{Symbol, SymbolBinding, SymbolKind};
use hexray_formats::elf::{ElfType, Machine};
use hexray_formats::{BinaryFormat, Elf, Section};

use analysis_fixture::{
    write_analysis_fixture, write_analysis_fixture_with_entropy, FixtureLayout,
    MIN_FUNCTIONS_PER_SECTION,
};

fn fixture_files(high_entropy: bool) -> (tempfile::TempDir, FixtureLayout, Vec<u8>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("analysis_fixture.elf");
    let layout = write_analysis_fixture_with_entropy(&path, 32, high_entropy)
        .expect("write analysis fixture");
    let bytes = std::fs::read(&path).expect("read analysis fixture");
    (dir, layout, bytes)
}

fn section<'e>(elf: &'e Elf<'_>, name: &str) -> &'e dyn Section {
    elf.sections()
        .find(|section| section.name() == name)
        .unwrap_or_else(|| panic!("fixture is missing the {name} section"))
}

fn symbol_at<'e>(elf: &'e Elf<'_>, address: u64) -> &'e Symbol {
    elf.symbols()
        .find(|symbol| symbol.address == address)
        .unwrap_or_else(|| panic!("fixture has no symbol at {address:#x}"))
}

/// Decode the `call rel32` at `call_site` and return its absolute target.
fn call_target(elf: &Elf<'_>, call_site: u64) -> u64 {
    let bytes = elf
        .bytes_at(call_site, 6)
        .unwrap_or_else(|| panic!("no bytes at {call_site:#x}"));
    assert_eq!(bytes[0], 0xE8, "expected a call at {call_site:#x}");
    assert_eq!(bytes[5], 0xC3, "the call body at {call_site:#x} must end in ret");
    let displacement = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    (call_site as i64 + 5 + i64::from(displacement)) as u64
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

#[test]
fn layout_matches_the_parsed_elf() {
    let (_dir, layout, bytes) = fixture_files(false);
    let elf = Elf::parse(&bytes).expect("parse fixture");

    assert_eq!(elf.header.file_type, ElfType::Executable);
    assert_eq!(elf.header.machine, Machine::X86_64);
    assert_eq!(elf.entry_point(), Some(layout.entry));

    let text = section(&elf, ".text");
    assert!(text.is_executable());
    assert!(text.is_allocated());
    assert!(!text.is_writable());
    assert_eq!(text.virtual_address(), layout.text_start);
    assert_eq!(text.size(), layout.text_end - layout.text_start);
    assert_eq!(text.data().len() as u64, text.size());

    let packed = section(&elf, ".packed");
    assert!(packed.is_executable());
    assert!(packed.is_allocated());
    assert_eq!(packed.virtual_address(), layout.packed_start);
    assert_eq!(packed.size(), layout.packed_end - layout.packed_start);
    assert_eq!(packed.data().len() as u64, packed.size());
    assert_eq!(layout.packed_start, layout.text_end, "sections must be adjacent");

    let rodata = section(&elf, ".rodata");
    assert!(rodata.is_allocated());
    assert!(!rodata.is_executable());
    assert_eq!(rodata.virtual_address(), layout.rodata_start);
    assert_eq!(rodata.data().len() as u64, rodata.size());

    let names: Vec<&str> = elf.sections().map(|section| section.name()).collect();
    for expected in [".text", ".packed", ".rodata", ".symtab", ".strtab", ".shstrtab"] {
        assert!(
            names.contains(&expected),
            "missing section {expected}: {names:?}"
        );
    }

    assert_eq!(layout.text_functions.len(), 32);
    assert_eq!(layout.packed_functions.len(), 32);
    assert_eq!(layout.callers.len(), 4);
    assert_eq!(layout.helper, layout.text_start);
    assert_eq!(layout.cross_section_caller, layout.text_start + 5 * 6);
    assert_eq!(layout.boundary_spanning.0, layout.text_end - 6);
    assert_eq!(layout.boundary_spanning.1, 6 + 16);
    assert_eq!(layout.sections.len(), 3);
}

#[test]
fn every_function_symbol_and_body_matches_the_layout() {
    let (_dir, layout, bytes) = fixture_files(false);
    let elf = Elf::parse(&bytes).expect("parse fixture");

    let functions: Vec<&Symbol> = elf
        .symbols()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .collect();
    assert_eq!(
        functions.len(),
        2 * 32,
        "functions_per_section = 32 must produce 2 * 32 sized functions"
    );
    assert!(functions.iter().all(|symbol| symbol.size > 0));

    let text_bytes = section(&elf, ".text").data();
    for (index, (name, address, size)) in layout.text_functions.iter().enumerate() {
        let symbol = symbol_at(&elf, *address);
        assert_eq!(&symbol.name, name);
        assert_eq!(symbol.kind, SymbolKind::Function);
        assert_eq!(symbol.binding, SymbolBinding::Global);
        assert_eq!(symbol.size, *size);
        assert_eq!(symbol.section_index, Some(1));

        let offset = (*address - layout.text_start) as usize;
        let is_call = layout.callers.contains(address) || *address == layout.cross_section_caller;
        let expected_opcode = if is_call { 0xE8 } else { 0xB8 };
        assert_eq!(text_bytes[offset], expected_opcode, "{name}: wrong body");
        assert_eq!(text_bytes[offset + 5], 0xC3, "{name}: body must end in ret");

        let expected_size = if index + 1 == layout.text_functions.len() {
            6 + 16
        } else {
            6
        };
        assert_eq!(*size, expected_size, "{name}");
    }

    let packed_bytes = section(&elf, ".packed").data();
    for (name, address, size) in &layout.packed_functions {
        let symbol = symbol_at(&elf, *address);
        assert_eq!(&symbol.name, name);
        assert_eq!(symbol.kind, SymbolKind::Function);
        assert_eq!(symbol.binding, SymbolBinding::Global);
        assert_eq!(symbol.size, *size);
        assert_eq!(*size, 6);
        assert_eq!(symbol.section_index, Some(2));

        let offset = (*address - layout.packed_start) as usize;
        assert_eq!(packed_bytes[offset], 0xB8, "{name}: wrong body");
        assert_eq!(packed_bytes[offset + 5], 0xC3, "{name}: body must end in ret");
    }

    for caller in &layout.callers {
        assert_eq!(call_target(&elf, *caller), layout.helper);
    }
    assert_eq!(
        call_target(&elf, layout.cross_section_caller),
        layout.packed_start,
        "the cross-section caller must call into .packed"
    );
    assert_eq!(layout.packed_functions.first().map(|row| row.1), Some(layout.packed_start));
    assert_eq!(
        layout.boundary_spanning.0 + layout.boundary_spanning.1,
        layout.text_end + 16,
        "the boundary function must over-declare into .packed"
    );
}

#[test]
fn packed_padding_entropy_switches_with_the_variant() {
    let (_high_dir, high_layout, high_bytes) = fixture_files(true);
    let (_low_dir, low_layout, low_bytes) = fixture_files(false);
    let high_elf = Elf::parse(&high_bytes).expect("parse high-entropy fixture");
    let low_elf = Elf::parse(&low_bytes).expect("parse low-entropy fixture");

    let high = section(&high_elf, ".packed").data();
    let low = section(&low_elf, ".packed").data();
    assert!(high.len() >= 4096);
    assert!(low.len() >= 4096);
    let high_entropy = shannon_entropy(high);
    let low_entropy = shannon_entropy(low);
    assert!(
        high_entropy >= 7.5,
        "high-entropy padding must reach 7.5 bits/byte, got {high_entropy}"
    );
    assert!(
        low_entropy < 7.5,
        "low-entropy padding must stay below 7.5 bits/byte, got {low_entropy}"
    );

    // Function bodies are intact in both variants: only the padding changes.
    for (layout, packed) in [(&high_layout, high), (&low_layout, low)] {
        for (name, address, _) in &layout.packed_functions {
            let offset = (*address - layout.packed_start) as usize;
            assert_eq!(packed[offset], 0xB8, "{name}: body was overwritten");
            assert_eq!(packed[offset + 5], 0xC3, "{name}: body was overwritten");
        }
    }

    let body_bytes = (low_layout.packed_functions.len() as u64 * 6) as usize;
    assert!(
        low[body_bytes..].iter().all(|byte| *byte == 0),
        "low-entropy padding must be zero-filled"
    );
}

#[test]
fn generator_rejects_layouts_without_room_for_every_role() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("tiny.elf");
    let error = write_analysis_fixture(&path, 1).expect_err("count 1 must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains(&MIN_FUNCTIONS_PER_SECTION.to_string()));
    assert!(!path.exists(), "a rejected layout must not write a file");
}
