#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_disasm::cuda::SassDisassembler;
use hexray_disasm::traits::Disassembler;

fuzz_target!(|data: &[u8]| {
    // SASS instructions are fixed 16 bytes on Volta+.
    if data.len() < 16 {
        return;
    }

    let d = SassDisassembler::ampere();

    // Single-instruction decode.
    let _ = d.decode_instruction(&data[..16], 0x1000);

    // Block decode — must NEVER desync from the 16-byte stride.
    let results = d.disassemble_block(data, 0x1000);
    let expected_full_slots = data.len() / 16;
    let expected_total = expected_full_slots + (data.len() % 16 != 0) as usize;
    assert_eq!(
        results.len(),
        expected_total,
        "SASS block walker desynced: got {} results for {} input bytes",
        results.len(),
        data.len()
    );

    // Every Ok result must carry exactly 16 bytes and an aligned address.
    for (i, r) in results.iter().enumerate() {
        if let Ok(ins) = r {
            assert_eq!(ins.size, 16);
            assert_eq!(ins.bytes.len(), 16);
            assert_eq!(ins.address, 0x1000 + (i as u64) * 16);
        }
    }
});
