//! Regressions from the pre-release fuzz soak on 2026-06-05/06.
//!
//! Each test loads a small input that triggered a bug in the
//! `elf_structured` libfuzzer target and asserts the parser now
//! handles it cleanly (no OOM, no panic, no runaway symbol count).
//! Inputs live in `fuzz/corpus/elf_structured/soak-*` so the
//! libfuzzer-driven CI keeps re-exercising them too.

use hexray_formats::elf::Elf;
use hexray_formats::BinaryFormat;

/// 748-byte ELF with `sh_entsize=1` on multiple symbol-table
/// sections. Before the parse_symbols entsize-floor guard, the inner
/// loop advanced one byte at a time and materialised 20.5 M synthetic
/// symbols (1.88 GB RSS) before the OS killed the process. The fix
/// requires `sh_entsize >= sizeof(SymbolEntry)`, so the corrupted
/// table is rejected and `Elf::symbols` yields 0.
#[test]
fn parse_does_not_oom_on_corrupted_syment_stride() {
    let bytes = include_bytes!(
        "../../../fuzz/corpus/elf_structured/\
         soak-2026-06-05-oom-bounded-syment-stride"
    );

    // Parse should succeed (or fail cleanly — either is acceptable).
    let Ok(elf) = Elf::parse(bytes) else { return };

    // The pre-fix output reported 20_515_840 symbols from this 748-byte
    // file. Anything north of 1 K from this input means the stride
    // guard regressed.
    let count = elf.symbols().count();
    assert!(
        count < 1_000,
        "symbol count {} suggests sh_entsize stride guard regressed",
        count
    );
}
