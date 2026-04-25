#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::Elf;

fuzz_target!(|data: &[u8]| {
    // First parse as a generic ELF; if that succeeds, attempt to view it
    // as a CUDA CUBIN. Both must be panic-safe on adversarial input.
    let Ok(elf) = Elf::parse(data) else { return };
    let Ok(view) = elf.cubin_view() else { return };

    // Touch every public accessor — these used to panic on truncated
    // section/symbol tables before the .nv.info alignment fix landed.
    let _ = view.kernels().len();
    let _ = view.entry_kernels().count();
    let _ = view.memory_regions().len();
    let _ = view.module_info().is_some();
    let _ = view.diagnostics().len();
    let _ = view.ptx_sidecar().is_some();

    for k in view.kernels() {
        let _ = k.name;
        let _ = k.code.len();
        let _ = k.size;
        let _ = k.confidence;
        let _ = k.resource_usage();
        if let Some(blob) = &k.nv_info {
            for entry in &blob.entries {
                let _ = blob.payload(entry);
            }
        }
    }
});
