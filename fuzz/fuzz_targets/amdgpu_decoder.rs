#![no_main]

use hexray_core::GfxArchitecture;
use hexray_disasm::amdgpu::AmdgpuDisassembler;
use hexray_disasm::Disassembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Cycle through both family bands so neither encoding-prefix
    // path goes unfuzzed.
    for target in [
        GfxArchitecture::new(9, 0, 6),   // gfx906
        GfxArchitecture::new(10, 3, 0),  // gfx1030
        GfxArchitecture::new(11, 0, 0),  // gfx1100
    ] {
        let d = AmdgpuDisassembler::for_target(target);
        // Single-instruction decode (32 or 64 bits).
        let _ = d.decode_instruction(data, 0x1000);

        // Block decode must never desync — every result entry spans
        // either 4 or 8 bytes of input plus a possible trailing
        // truncation error.
        let results = d.disassemble_block(data, 0x1000);
        let mut consumed = 0usize;
        for r in &results {
            match r {
                Ok(instr) => {
                    assert!(
                        instr.size == 4 || instr.size == 8,
                        "instr size = {}",
                        instr.size
                    );
                    consumed += instr.size;
                }
                Err(_) => {
                    let remaining = data.len() - consumed;
                    consumed += remaining.min(4);
                }
            }
        }
        assert_eq!(consumed, data.len());
    }
});
