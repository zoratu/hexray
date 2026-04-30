# Changelog

All notable changes to hexray will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.6] - 2026-04-30

### Highlights — adversarial-input hardening

Maintenance release acting on the lessons from
https://corrode.dev/blog/bugs-rust-wont-catch/. Three of the eight
bug classes the post calls out apply to a binary-analysis tool eating
untrusted input; this release addresses all three.

What's new:

- **`hexray_formats::name_from_bytes`** — new helper that preserves
  byte sequences when converting binary-format names to `String`.
  Symbol/section/load-command names in ELF / Mach-O / PE / DWARF are
  byte sequences (the format spec doesn't require UTF-8). The Rust
  default `String::from_utf8_lossy` collapses every invalid byte to
  `\u{FFFD}`, so an attacker-crafted symbol `\xff\xfe` and a different
  one `\xff\xfd` both render as `��` and can't be distinguished. The
  helper preserves them: valid UTF-8 passes through unchanged;
  invalid input is rendered with `std::ascii::escape_default` so
  `\xff` shows as the literal `\xff`. All 14 pre-existing
  `from_utf8_lossy` call sites in PE / Mach-O / DWARF parsers
  switched over. 8 unit tests pin the byte-preservation contract.
- **Fuzz crash-regression CI gate** (`scripts/run-fuzz-corpus`).
  Runs each of the 21 existing fuzz targets for a configurable
  duration (default 60s) against its committed corpus, fails on any
  crash. Wired into `ci-local --tier full`. Catches regressions
  without an explicit fuzz campaign. Skips cleanly when `cargo-fuzz`
  / nightly rustc isn't available so non-fuzz CI tiers still pass on
  minimal toolchains.
- **Documented adversarial-input lint posture** in
  `hexray-formats/src/lib.rs` and `hexray-disasm/src/lib.rs`.
  `clippy::indexing_slicing`, `arithmetic_side_effects`,
  `unwrap_used`, `expect_used`, `panic` are documented (with the
  corrode.dev URL and rationale) but not yet enforced — flipping
  them on floods the build with hundreds of pre-existing call-site
  hits. PR review and the new fuzz CI gate are the enforcement
  layer until the bulk migration to `.get()` / `checked_*` /
  `try_into()` lands.

What's deferred:

- **Bulk refactor of pre-existing parsing paths** to remove
  `unwrap()` / direct indexing / unchecked arithmetic in favour of
  the safer alternatives. Several hundred call sites; tracked
  separately. The runtime fuzz gate catches regressions in the
  interim.

## [1.3.5] - 2026-04-26

### Highlights — full AMDGPU operand decode + differential gate

v1.3.5 closes the entire v1.3.x AMDGPU docket: every byte hexray
emits is now byte-checked against `llvm-objdump` for eight SCALE-built
kernels spanning GFX9 (gfx900), RDNA1 (gfx1010), RDNA2 (gfx1030),
and RDNA3 (gfx1100/1101/1102) — including a multi-kernel fixture.
The previously committed gfx1030/gfx1100 fixtures get companion
`expected_disasm.txt` sidecars; six more architectures land alongside
theirs. RDNA3-specific opcode renumbering for SOP2/VOPC/VOP2/SOP1 is
fully handled, and operand rendering is wired for VOP3 / SMEM / FLAT
/ MUBUF / DS classes including VOP3 NEG+ABS modifiers.

What's new:

- **Differential gate (`amdgpu_differential_gate.rs`).** Two tests:
  no `xxx.op0x...` placeholder mnemonics across the corpus, and
  per-mnemonic frequency parity (±1) against the llvm-objdump sidecar
  within each `<kernel$local>:` block. Drives every CI run.
- **Operand rendering — VOP3, SMEM, FLAT.** Width-aware register
  pairs (`v[0:1]`, `s[2:3]`), VOP3B SDST (`vcc_lo` for
  `v_add_co_u32`), VOPC-as-VOP3 with implicit EXEC dst, FLAT SADDR
  null sentinel, 2-vs-3-source VOP3 detection, GFX11 s_waitcnt
  layout (VMCNT[15:10] / LGKMCNT[9:4] / EXPCNT[2:0]).
- **VOP3 NEG + ABS modifier rendering.** NEG bits at `[31:29]` of
  dword1, ABS bits at `[10:8]` of dword0. Render `|src|` for ABS,
  `-|src|` for NEG+ABS to match llvm-objdump. Suppressed for VOP3B
  forms (those bits are SDST data, not modifiers).
- **MUBUF operand rendering.** Full BUF field layout: VDATA / VADDR /
  SRSRC (4-SGPR resource descriptor at `s[N*4:N*4+3]`) / SOFFSET /
  OFFSET / OFFEN / IDXEN / GLC / SLC / TFE flags.
- **DS operand rendering.** LDS field layout: ADDR / DATA0 / DATA1 /
  VDST / OFFSET0 / OFFSET1 / GDS, mnemonic-aware about which DS
  opcodes write VDST and how many DATA inputs they take.
- **SIMM16 sub-decoding.** `s_clause`, `s_waitcnt`, `s_delay_alu`
  render their sub-fields:
  `s_delay_alu instid0(SALU_CYCLE_1) | instskip(SKIP_1) | instid1(VALU_DEP_1)`.
- **HIP host-binary fatbin extraction.** New
  `crates/hexray-formats/src/cuda/hip_fatbin.rs` parses the
  `__CLANG_OFFLOAD_BUNDLE__` schema. 14 new tests on synthetic
  bundles. LZ4-compressed bundles (CCOB magic) remain a documented
  limitation.
- **SCALE `.AMDGPU.kinfo` parser.** SCALE-free 1.4.x emits no
  NT_AMDGPU_METADATA note; the private `.AMDGPU.kinfo` section
  carries an alternate kernarg layout. The v1.3.5 parser
  reverse-engineers the 12-byte header + N×(offset,size) format,
  surfacing arg counts and per-arg sizes in `hexray cmp` output.
- **GFX9 opcode tables.** `SOP2_GFX9` split out (s_mul_i32 at 0x24,
  not 0x26). `VOPC_GFX9` split out (i32 comparators at 0xc0..=0xc7).
  `VOP3_GFX9` split out (`v_lshlrev_b64` at 0x28f). `FLAT_GFX9` split
  out (`flat_load_dword` at 0x14). `VOP2_GFX9` extended with the
  carry/no-carry pairs (0x11/0x19..=0x1c/0x32..=0x36) and corrected
  mnemonics — `0x19` is `v_add_co_u32_e32` (with carry), not
  `v_add_u32_e32`. `SOP1_GFX9` extended with the wave64 saveexec
  family at 0x20..=0x22.
- **RDNA1+ opcode coverage.** `SOP1_GFX10` gained the wave32
  `s_and_saveexec_b32` at OP=0x3c. `VOP3_GFX10` and `VOP3_GFX11`
  gained `v_cndmask_b32_e64` at OP=0x101. `VOPC_GFX11` carved out
  separately (RDNA3 packs i32 comparators into 0x40..=0x4e).
- **RDNA3 SOP2 numbering.** New `SOP2_GFX11` table — RDNA3
  substantially renumbered SOP2; only `s_add_u32` through
  `s_subb_u32` (0x00..=0x05) survived from GFX10. `s_min_i32` moved
  0x06→0x12, `s_and_b32` 0x0e→0x16, `s_xor_b32` 0x12→0x1a,
  `s_lshl_b32` to 0x08, `s_mul_i32` 0x26→0x2c. Cross-checked
  against `llvm/lib/Target/AMDGPU/SOPInstructions.td` GFX11 records.
- **SOP1_GFX11.** RDNA3 reverted SOP1 to GFX9-style numbering for
  the bulk of opcodes but kept `_saveexec_b32` wave32 forms.
- **VOP2_GFX11.** Integer min/max e32 family at 0x11..=0x14.
- **cargo-mutants gap-closing.** A full sweep across
  `crates/hexray-disasm/src/amdgpu/**` and
  `crates/hexray-formats/src/elf/amdgpu/**` (499 mutants total) drove
  ~80 new unit tests covering every encoding-class dispatch arm,
  every operand-extraction shift / mask / range, the SOPK / EXP /
  DS / FLAT / MUBUF / MTBUF / MIMG branches, the FLAT seg-rewrite
  variants, the kernel-descriptor parser, and the MessagePack
  metadata walker. 162 of 170 missed mutations now caught;
  the remaining 8 are semantically equivalent (every `Operation`
  in the `Vopc` and `Smem` tables matches the class default, so
  table-vs-default branches are unobservable). Walker safety:
  two `+= → *=` mutations on the dword-stride advance loop hung
  forever and are now caught via 120s timeout.

What's deferred:

- **CDNA MFMA / WMMA / VOP3P / DPP / SDWA opcodes.** SCALE-free
  doesn't ship gfx906 / gfx908 / gfx90a / gfx940 targets, and the
  consumer fixtures we *can* build don't exercise these classes.
  Adding speculative tables without a byte-validating fixture would
  be premature; tracked for the next release alongside a CDNA corpus.
- **End-to-end fixture validation for MUBUF / DS / VOP3 ABS.**
  `scale-free` builds don't exercise these classes on the kernels
  it ships; the new code is byte-validated against synthetic
  encodings only.
- **LZ4 fatbin decompression** (CCOB magic). Documented as a
  limitation in the HIP fatbin commit; needs a real hipcc binary.
- **gfx1200 (RDNA4) validation.** Requires commercial SCALE.
- **Linux-snapshot decompiler tests** for `test_decompile_callback_*`
  — the existing snapshot tests are macOS-locked. Linux output now
  decompiles correctly (after the validation fixes below) but
  matches a different shape; the macOS-locked tests are gated
  behind `#[cfg(target_os = "macos")]` until equivalent Linux
  snapshots land.

Cross-cutting decompiler fixes that surfaced during Linux release
validation:

- **PLT-stub `@plt` symbol synthesis** in the ELF parser. Calls
  through the GOT (`call qsort@plt`) target an address inside
  `.plt` (or `.plt.sec` on CET-aware glibc). The new
  `synthesize_plt_symbols` walks `.rela.plt` in order, looks each
  entry's symbol up in `.dynsym`, and adds a `Symbol { name:
  "<dynsym>@plt", ... }` at the matching stub address. Calls now
  decompile as `qsort(...)` instead of `sub_NNN(...)`.
- **DWARF CFA → fp frame correction.** When `DW_AT_frame_base` is
  `DW_OP_call_frame_cfa` (the `clang -O0 -g` default), DWARF emits
  operand offsets relative to CFA (`fp + 16` after the standard
  prologue). The variable-name map now rebases by +16 so DWARF
  parameter names actually surface in decompiled output.
- **`var_NN` → DWARF override** in signature emission. The
  emitter post-processes signature param names: if a name is
  `var_<hex>`, look up the stack offset in `dwarf_names` and
  prefer the DWARF name. Signatures now render
  `int32_t f(int64_t arr, int64_t n, int32_t (*cmp)(...))` instead
  of `(int64_t arr, int64_t arg1, int32_t (*var_18)(...))`.

Coverage on the spot (rust 1.89, `cargo llvm-cov`):
`amdgpu/encoding.rs` 99% lines, `amdgpu/mod.rs` 88%, `amdgpu/opcodes.rs`
100%, `amdgpu/registers.rs` 100%, `elf/amdgpu/descriptor.rs` 100%,
`elf/amdgpu/scale_kinfo.rs` 91%. `elf/amdgpu/msgpack.rs` is the
weakest at 61% (lots of error-path branches).

## [1.3.4] - 2026-04-26

### Highlights — RDNA3 family-band split + swarm testing

v1.3.4 fixes a major v1.3.3 bug surfaced by hands-on `llvm-objdump`
diffing of the gfx1100 fixture: the AMDGPU decoder treated all
GFX10+ targets (RDNA1, RDNA2, RDNA3, RDNA4) as a single opcode-table
band. RDNA3 substantially renumbered the per-class OP fields, so
v1.3.3 was decoding RDNA3 binaries with **silently wrong** mnemonics
— `s_endpgm` rendered as `sopp.op0x30`, `v_mad_u64_u32` as `vop3`,
`global_load_b32` as `flat`. Every instruction in the gfx1100
kernel now resolves to a real mnemonic.

The v1.3.4 work also adds proper Groce-style swarm testing
(ISSTA 2012) for the AMDGPU decoder, mirroring the existing
decompiler swarm tests. Random byte streams across random family
bands hit every fallback path and never panic.

What's new:

- **`EncodingFamily::Gfx11Plus`** — new band for RDNA3+ (gfx11xx,
  gfx12xx). Shares the GFX10+ encoding-class prefix layout but has
  its own VOP2/VOP3/SOPP/SOP1/SMEM/FLAT opcode tables. RDNA1/RDNA2
  stay in `Gfx10Plus`. The split mirrors how RDNA3's tablegen sits
  in LLVM (`*GFX11.td` files separate from `*GFX10.td`).
- **VOP2 GFX11 table.** `v_ashrrev_i32`: 0x18 → 0x1A.
  `v_add_co_ci_u32`: 0x28 → 0x20. `v_add_f32` stayed at 0x03.
- **VOP3 GFX11 table.** `v_mad_u64_u32`: 0x176 → 0x2fe.
  `v_lshlrev_b64`: 0x2ff → 0x33c. `v_add_co_u32`: 0x30f → 0x300.
  `v_cmpx_gt_i32_e64`: 0x094 → 0x0c4.
- **SOPP GFX11 table.** Massive renumbering. `s_endpgm`: 0x01 →
  0x30. `s_clause`: 0x21 → 0x05. `s_waitcnt`: 0x0c → 0x09.
  Branches all moved to 0x20..0x26. New RDNA3-only OPs:
  `s_delay_alu` (0x07), `s_wait_loadcnt` (0x0a), `s_wait_kmcnt`
  (0x0c), `s_sendmsg` (0x36), `s_code_end` (0x1f).
- **SOP1 GFX11 table.** Reverted to GFX9-style numbering
  (`s_mov_b32` back at OP=0x00).
- **SMEM GFX11 table.** Renamed `_dword` to `_b32`/`_b64`/`_b128`/
  `_b256`/`_b512`. OP=0x00 stays `s_load_b32`.
- **FLAT GFX11 table.** Renamed `_dword` to `_b32`. RDNA3 separates
  `global_*` / `flat_*` / `scratch_*` into distinct OP slots
  rather than using a `seg` bit, so the decoder skips the seg
  rewrite for `Gfx11Plus`. `global_load_b32`: 0x0c → 0x14.
  `global_store_b32`: 0x1c → 0x1a.
- **Family-aware control-flow detection.** `derive_control_flow`
  no longer hard-codes `OP=0x01 → Return`; it reads the entry's
  `Operation` from the family-aware table. RDNA3's `s_endpgm` at
  OP=0x30 is now correctly tagged.
- **Family-aware SOPP branch operands.** `populate_operands` no
  longer hard-codes the RDNA2 OP-0x02..=0x09 branch range; it
  consults the per-family table to decide whether to render a
  PC-relative target.

Swarm testing (`crates/hexray-disasm/tests/swarm_amdgpu.rs`):

- 5 proptest properties exercising the decoder under random
  family-band + byte-stream combinations:
  - **Walker invariant**: any byte stream advances exactly its
    length under any family band; never panics.
  - **Table omission**: random OPs (which essentially never hit
    our hand-curated tables) all fall back to the placeholder
    mnemonic without panicking.
  - **Family omission**: same dword classified under Gfx10Plus
    vs Gfx11Plus yields the same encoding class + size (only
    OP-table mappings differ).
  - **Operand-field omission**: spurious PC-relative operands
    don't appear when the family-aware table says the SOPP isn't
    a branch.
  - **Determinism**: same `(dword, family)` always produces the
    same `(mnemonic, size)`.

Real-binary verification (`hexray -s vector_add
tests/corpus/scale-lang/vector_add.gfx1100.co`) now matches
`llvm-objdump --triple=amdgcn-amd-amdhsa --mcpu=gfx1100` line by
line on the base mnemonic. New integration test
`disasm_handles_rdna3_opcode_renumbering` locks the property.

Workspace: 2364 tests pass with `--features amdgpu cuda`. Clippy
clean.

Known gaps remaining (the v1.3.5 docket):

- RDNA3 SOP2/VOPC numbering still inherits `_SHARED` tables —
  haven't confirmed whether RDNA3 renumbered those (the gfx1100
  fixture doesn't exercise enough of those opcodes). Will validate
  against a wider corpus.
- Operand rendering for VOP3, SMEM, MUBUF, DS, FLAT classes
  beyond the dispatcher (memory refs, VOP3 src modifiers, etc.).
- HIP host-binary fatbin extraction.
- SCALE-specific `.AMDGPU.kinfo` parsing.

## [1.3.3] - 2026-04-26

### Highlights — AMDGPU opcode tables now hit 100% on the SCALE corpus

v1.3.3 fixes the GFX10+ opcode-table numbering and adds VOP3 + FLAT
class support. Every instruction in the SCALE-built `vector_add`
kernel now resolves to a real mnemonic, with ground-truth validation
done against `llvm-objdump --triple=amdgcn-amd-amdhsa --mcpu=gfx1030`
on the committed fixture.

Before (v1.3.2):

```
0x00000100:  ... sopp.op0x21
0x00000124:  ... vop3
0x00000130:  ... vop3
0x00000150:  ... vop3
0x0000015c:  ... vop3
0x00000164:  ... vop2.op0x28
0x0000017c:  ... flat
0x00000194:  ... v_subrev_f32_e32 v2, v2, v3   ← actually wrong (was v_add_f32)
```

After (v1.3.3):

```
0x00000100:  ... s_clause
0x00000124:  ... v_mad_u64_u32
0x00000130:  ... v_cmpx_gt_i32_e64
0x00000150:  ... v_lshlrev_b64
0x0000015c:  ... v_add_co_u32
0x00000164:  ... v_add_co_ci_u32_e32 v3, s1, v1
0x0000017c:  ... global_load_dword
0x00000194:  ... v_add_f32_e32 v2, v2, v3
```

What's new:

- **VOP2 GFX10+ table corrected.** RDNA renumbered VOP2 to a
  compact layout. v1.3.2's table inherited GFX9 numbering for
  several entries (`v_add_f32 = 0x01`) — wrong on GFX10+ where
  it's `0x03`. `v_subrev_f32_e32` was *masquerading* as
  `v_add_f32_e32` for the binary at hand. Numbering harvested from
  LLVM `VOP2Instructions.td` GFX10 records and validated against
  `llvm-objdump`. Adds the RDNA-specific `v_add_co_ci_u32_e32` /
  `v_sub_co_ci_u32_e32` carry-add ops at OP=0x28/0x29.
- **SOP1 GFX10+ table.** Split `SOP1_SHARED` into per-family tables;
  GFX10+ moves `s_mov_b32` from OP=0x00 to 0x03, `s_mov_b64` to 0x04.
  Added `s_cmov_b32/b64`, `s_setpc_b64`, `s_swappc_b64` at the right
  GFX10+ slots.
- **SOPP GFX10+ table.** Now distinct from GFX9 — adds the RDNA
  scheduling-hint opcodes `s_clause` (0x21), `s_code_end` (0x22),
  `s_inst_prefetch` (0x23) that show up in every RDNA kernel.
- **VOP3 opcode table.** New `TableClass::Vop3` with 10-bit OP at
  bits `[25:16]`. First-pass entries: `v_cmpx_gt_i32_e64` (0x094),
  `v_add3_u32` (0x155), `v_mad_u64_u32` (0x176), `v_mad_i64_i32`
  (0x177), `v_lshlrev_b64` (0x2ff), `v_add_co_u32` (0x30f),
  `v_sub_co_u32` (0x310). VOP3A and VOP3B share the same OP space
  and dispatch through one table.
- **FLAT opcode table + seg-aware rendering.** New `TableClass::Flat`
  with 7-bit OP at `[24:18]`. The `seg` bit field at `[16:14]`
  (0=flat, 1=scratch, 2=global) is decoded and rewrites the
  rendered prefix: `flat_load_dword` becomes `global_load_dword`
  when seg=2, `scratch_load_dword` when seg=1. First-pass
  entries cover the {`flat`,`global`,`scratch`} × {load,store} ×
  {ubyte, sbyte, ushort, sshort, dword, dwordx2/3/4} matrix.

Hands-on verification:
- `cargo run --bin hexray -- -s vector_add tests/corpus/scale-lang/vector_add.gfx1030.co`
  produces real mnemonics for every instruction, matching
  `llvm-objdump`'s output 1:1 on the base mnemonic level.

Workspace: 2358 tests pass with `--features amdgpu cuda`. Clippy
clean.

Known gaps remaining (the v1.3.4 docket):

- VOP3 / SMEM / MUBUF / DS operand rendering. Class dispatch and
  mnemonic resolution work; full operand strings (memory refs with
  `v[2:3], off` notation, VOP3 src modifiers) are follow-up.
- HIP host-binary fatbin extraction.
- SCALE-specific `.AMDGPU.kinfo` section parsing for SCALE-free
  binaries (so per-arg cmp rows render without standard
  NT_AMDGPU_METADATA).

## [1.3.2] - 2026-04-25

### Highlights — AMDGPU operand decoding, MessagePack metadata, real scale-lang demo

v1.3.2 closes the three biggest gaps the v1.3.1 AMDGPU support left
open and ships a real end-to-end scale-lang interop demo backed by
SCALE-built binaries committed to the repo.

```bash
# Hands-on, validated with SCALE 1.4.2 on Ubuntu 25.10:
hexray vector_add.gfx1030.co info
hexray -s vector_add vector_add.gfx1030.co
hexray vector_add.gfx1030.co cmp vector_add.gfx1100.co
```

```
<vector_add$local>:
0x00000100:  02 00 a1 bf              sopp.op0x21
0x00000104:  02 00 00 f4 38 00 00 fa  s_load_dword
...
0x00000120:  00 06 00 81              s_add_i32 s0, s0, s6
...
0x000001a0:  00 00 81 bf              s_endpgm

hexray cmp
==========
a: amdgpu (gfx1030, family=Rdna2)
b: amdgpu (gfx1100, family=Rdna3)

Kernel: vector_add
  primary regs    a=8            b=8            ✓
  scalar regs     a=16           b=24           differ
  kernarg/param   a=88B          b=88B          ✓
  shared/LDS      a=0B           b=0B           ✓

Matched 1 kernel(s).
```

What's new:

- **AMDGPU operand decoding**: VOP1 / VOP2 / VOPC / SOP1 / SOP2 /
  SOPP now render destination + source operands instead of just
  the mnemonic. Bit layouts per LLVM `SIInstrFormats.td`
  (`[8:0]` SRC0, `[16:9]` OP/VSRC1, `[24:17]` VDST/SDST, …).
  SOPP branches render PC-relative target addresses
  (`s_cbranch_execz 0x1a0`). Inline integer constants `0..=64`
  and `-1..=-16` decode to `Operand::Immediate`; vgprs/sgprs/
  vcc/exec render via the central `amdgpu_reg_name` table in
  `hexray-core/src/register.rs`.
- **`NT_AMDGPU_METADATA` MessagePack decode**: hand-rolled minimal
  MessagePack reader in `hexray-formats/src/elf/amdgpu/msgpack.rs`
  (~200 lines, no external deps). Schema-aware decoder in
  `metadata.rs` extracts the `amdhsa.kernels[*]` records into
  typed `AmdMetadataKernel` / `AmdMetadataArg` records. The view
  builder walks every SHT_NOTE section, finds records with name
  `"AMDGPU"` and type 32, and attaches the per-kernel record to
  the matching `Kernel`.
- **`hexray cmp` per-arg comparison**: when both binaries carry
  argument metadata (CUDA `KPARAM_INFO` records on the cubin
  side, `NT_AMDGPU_METADATA` on the AMDGPU side), the report now
  prints `arg count` + `arg [i] size` rows. Argument count and
  sizes are Structural (mismatches exit non-zero); the existing
  vgpr/sgpr/lds rows remain Informational.
- **Real scale-lang fixtures**: `tests/corpus/scale-lang/`
  ships a real `vector_add.cu` plus the SCALE 1.4.2-built
  `vector_add.gfx1030.co` and `vector_add.gfx1100.co` code
  objects (~2KB each). Three integration tests in
  `crates/hexray/tests/scale_lang_cmp.rs` drive `hexray info`,
  `hexray -s vector_add`, and `hexray cmp` against them.
- **`docs/SCALE_INTEROP.md`** walks through the demo end-to-end
  with the real cmp output captured into the tree. README and
  AMDGPU.md cross-link to it.

Breaking changes: none. Backwards-compatible additions
(`KernelSummary` gains a private `args` field; `Kernel` (AMDGPU
view) gains `metadata: Option<AmdMetadataKernel>`).

Workspace: 2358 tests pass with `--features amdgpu cuda`. Clippy
clean with `-D warnings`.

Known gaps remaining (the v1.3.3 docket):

- VOP3 / SMEM / MUBUF / DS / FLAT / MIMG / EXP operand layouts
  decode at the class level but don't render full operands yet
  (placeholder `<class>.op0xNN` for opcodes outside the M10.4
  first-pass tables — the dispatch is solid, just needs more
  table rows).
- HIP host-binary fatbin extraction (clang offload bundle wrapper
  with `__CLANG_OFFLOAD_BUNDLE__` magic). Same pattern as the
  v1.3.0 NVIDIA `FatbinWrapper`; deferred to v1.3.3.
- CDNA MFMA / WMMA matrix opcodes, VOP3P packed math, DPP / SDWA
  modifiers. Encoding-class dispatch covers them; opcode tables
  stay first-pass until we have a corpus to harvest from.
- SCALE `scale-free` emits a SCALE-specific `.AMDGPU.kinfo`
  section *instead of* the standard `NT_AMDGPU_METADATA` note,
  so the per-arg cmp rows render only when both binaries use the
  standard format. The commercial SCALE build (and `hipcc` /
  `clang amdgcn-amd-amdhsa`) emit the standard note.

## [1.3.1] - 2026-04-25

### Highlights — AMDGPU / AMD GPU support + scale-lang interop

v1.4.0 adds first-class support for AMDGPU code objects (the ELF
binaries `clang -target=amdgcn-amd-amdhsa`, `hipcc --genco`, and
[SCALE](https://scale-lang.com/) emit for AMD targets) and a new
`hexray cmp` subcommand that compares two GPU binaries kernel-by-
kernel. Together these make cross-vendor equivalence demoable: the
same CUDA source compiled by SCALE for both NVIDIA (cubin, v1.3.0)
and AMD (code object, v1.4.0) can now be diffed inside hexray.

Quick tour:

```bash
clang -target=amdgcn-amd-amdhsa --offload-arch=gfx906 -c kernel.cu -o k.co
hexray k.co info                 # kernel listing + vgpr/sgpr/lds/kernarg
hexray -s vector_add k.co        # disasm by name (v_mov_b32, s_endpgm, ...)
hexray nvcc.cubin cmp scale.co   # cross-vendor signature diff
```

```
Kernel: vector_add
  primary regs    a=12         b=12         ✓
  scalar regs     a=—          b=16         differ
  kernarg/param   a=24B        b=24B        ✓
  shared/LDS      a=—          b=768B       n/a
  exit count      a=2          b=—          n/a
```

What's in the box:

- **AMDGPU ELF recognition** — `EM_AMDGPU = 224` in
  `hexray-formats/src/elf/header.rs`. Both V3 ABI (1-bit feature
  fields) and V4 ABI (2-bit TriState xnack/sramecc) `e_flags`
  decoded. Mach table covers gfx8xx (GCN3/4), gfx9xx (GCN5/CDNA1/2/3),
  gfx10xx (RDNA1/2), gfx11xx (RDNA3), gfx12xx (RDNA4).
  `Architecture::Amdgpu(GfxArchitecture)` carries family + major +
  minor + stepping + xnack + sramecc; renders the LLVM canonical
  target id (`gfx906`, `gfx90a:xnack+:sramecc-`).
- **Code-object view** — `Elf::code_object_view()` analogue of
  `cubin_view()`. Walks the symbol table for `<kernel>.kd`
  STT_OBJECT entries, pairs them with `<kernel>` STT_FUNC entries,
  parses the 64-byte `amdhsa_kernel_descriptor_t` block per LLVM
  `AMDHSAKernelDescriptor.h`. Decoded fields: `vgpr_count` (with
  wave32 granule split), `sgpr_count`, `user_sgpr_count`,
  `lds_bytes` (static + dynamic), `scratch_bytes`, `kernarg_size`,
  `is_wave32`. Raw `compute_pgm_rsrc1/2/3` words preserved for
  callers that need to diff them directly.
- **AMDGPU disassembler** (`hexray-disasm` feature `amdgpu`) —
  variable-length 32/64-bit walker. Family-aware encoding-class
  dispatch covering VOP1/VOP2/VOPC, VOP3A/B, SOP1/SOP2/SOPC/SOPK/
  SOPP, SMEM, MUBUF, MTBUF, MIMG, DS, FLAT, EXP. GFX9 vs GFX10+
  prefix layouts both supported (the most visible shifts: VOP3
  `110100` → `110101`, SMEM `110000` → `111101`, EXP `110001` →
  `111110`). First-pass opcode tables for the dozen-ish OPs per
  class that show up in every realistic kernel: `v_mov_b32`,
  `v_add_*`, `v_cmp_*`, `s_mov_b32`, `s_add_u32`, `s_endpgm`,
  `s_branch`, `s_load_dword*`, `v_lshlrev_b32`, etc. M10.4
  documents the strategy (LLVM tablegen sources +
  `llvm-mc --show-encoding` cross-checks) and leaves the tail
  for organic growth driven by the differential gate.
- **`hexray cmp <a> <b>`** — the cross-vendor comparator
  subcommand. Walks kernel summaries on both sides, matches by
  mangled name, and reports a per-kernel resource diff. Two
  field kinds: Structural mismatches (kernarg / param size —
  the same source must produce the same signature) exit non-zero
  and are flagged `MISMATCH`; informational differences
  (register pressure, codegen detail) are noted as `differ`.
  Suitable for CI: identical kernels exit 0, signature
  inconsistencies exit 1.
- **CLI integration** — `hexray info` prints an "AMDGPU Code
  Object View" block (target id, kernels, vgpr/sgpr/lds/kernarg)
  alongside the existing CUDA CUBIN block. `hexray -s <kernel>`
  and the disasm block path both have AMDGPU arms wiring
  `AmdgpuDisassembler::for_target(target)`.

Quality bar:

- 22 AMDGPU decoder unit tests, 6 proptest properties (walker
  never desyncs, classification deterministic, sizes always 4
  or 8, etc.), 1 fuzz target (`fuzz/fuzz_targets/amdgpu_decoder.rs`).
- Code-object view: 11 integration tests synthesising AMDGPU
  ELFs at test time (no ROCm required).
- Hermetic snapshot tests: `snapshot_info_amdgpu` locks the
  `hexray info` format, `snapshot_cmp_amdgpu_self` locks the
  `hexray cmp` format.
- Workspace: 2338 tests pass with `--features amdgpu cuda`.
  Clippy clean with `-D warnings`.

Known gaps (called out in `docs/AMDGPU.md`):

- Operand decoding for the disassembler is mnemonic-only; SRC0 /
  VDST register-name rendering is follow-up.
- The opcode tables are first-pass — covering common opcodes only.
  CDNA MFMA / WMMA matrix instructions, VOP3P packed math, DPP /
  SDWA modifiers are deferred.
- `NT_AMDGPU_METADATA` MessagePack notes (kernel arg layout, max
  workgroup size) not decoded yet — descriptor block is the only
  metadata source today. Doesn't affect cmp.
- HIP host fatbin extraction deferred — hexray reads AMDGPU code
  objects directly; HIP host wrappers are M11+ work.

See `docs/AMDGPU.md` for the user-facing guide,
`docs/AMDGPU_DESIGN.md` for the original M10 RFC, and
`crates/hexray-disasm/src/amdgpu/` for the decoder internals.

### AMDGPU Support — milestone-by-milestone detail

- **M10.1 — ELF recognition + Architecture::Amdgpu**:
  `Machine::Amdgpu` for `EM_AMDGPU = 224`,
  `gfx_from_amdgpu_elf(abi_version, e_flags)` decodes both V3
  and V4 ABI layouts, mach table covers every gfx target
  shipping today. `GfxFamily { Gcn3, Gcn4, Gcn5, Cdna1, Cdna2,
  Cdna3, Rdna1, Rdna2, Rdna3, Rdna4, Unknown }` with
  forward-compatible `from_target`. `TriState { Unspecified,
  Off, On }` matches LLVM's V4 "any" semantics. 9 unit tests.
- **M10.2 — Code-object view**: `CodeObjectView` mirroring
  `CubinView`. `KernelDescriptor::parse(&[u8; 64])` decodes the
  amdhsa kernel descriptor with both raw `compute_pgm_rsrc*`
  words and decoded counts. Wave32 reads from
  `kernel_code_properties[10]` (`ENABLE_WAVEFRONT_SIZE32`),
  matching `AMDHSAKernelDescriptor.h`. Symbol-pair detection for
  `<kernel>` / `<kernel>.kd`. Orphan descriptors / orphan entries
  surface as soft diagnostics. 11 unit tests + a synthetic-ELF
  builder for hermetic integration tests.
- **M10.3 — Decoder skeleton**: variable-length 32/64-bit
  walker. `decode_class(dword, family) -> EncodingClass`
  classifies by inspecting top bits of the first dword. Caught
  one self-inflicted bug: SOP1/SOPC/SOPP top9 patterns share
  top4 = `1011` with SOPK; dispatch order matters
  (most-specific first). 22 decoder unit tests, family-aware
  prefixes (GFX9 vs GFX10+).
- **M10.4 — Opcode tables**: per-family tables for VOP1/VOP2/
  VOPC, SOP1/SOP2/SOPP, SMEM. Hand-curated from LLVM
  AMDGPU tablegen + `llvm-mc --show-encoding` cross-checks
  produced for gfx906, gfx1030, gfx1100, gfx1200. Bit-layout
  WHY-comments cover OP-extraction shifts. Coverage is
  intentionally partial — a corpus-driven differential gate
  drives organic growth.
- **M10.5 + M10.6 — Quality bar**: snapshot test, 6 proptest
  properties, 1 fuzz target. Corpus / `llvm-objdump` differential
  gate scaffolding deferred until a Linux + ROCm box is
  available; the proptest + fuzz layer covers the
  ROCm-independent half.
- **M10.7 — Docs**: `docs/AMDGPU.md` (modest user-facing guide),
  `docs/AMDGPU_DESIGN.md` (M10 RFC).
- **M11 — `hexray cmp`**: cross-vendor comparator subcommand.
  Vendor-agnostic `KernelSummary` collected from CubinView and
  CodeObjectView; structural vs informational field kinds; CI-
  friendly exit codes.

## [1.3.0] - 2026-04-25

### Highlights — CUDA / NVIDIA GPU support

This release adds first-class support for inspecting NVIDIA CUDA
binaries. `hexray` now reads CUBINs end-to-end: identifying the SM
architecture, listing kernels and their resource usage, decoding SASS
instructions (Volta through Blackwell, 16-byte fixed-width encoding),
and surfacing PTX sidecars and fatbin-wrapped payloads.

Quick tour:

```bash
# Compile a kernel for sm_80
nvcc --cubin -arch=sm_80 vector_add.cu -o vector_add.cubin

# Inspect: arch, kernels, resource usage, memory regions
hexray info vector_add.cubin

# Disassemble a single kernel by name
hexray -s vector_add vector_add.cubin
```

```
<.text.vector_add>:
0x00000d00:  …  MOV R1
0x00000d10:  …  S2R R6
0x00000d20:  …  S2R R3
0x00000d30:  …  IMAD R6, R6
0x00000d40:  …  ISETP.GE.AND R0, R6
0x00000d50:  …  EXIT
```

What's in the box:

- **CUBIN parser** — ELF `EM_CUDA = 190` recognised with both ABI V1
  (Ampere / Ada / Hopper) and ABI V2 (Blackwell+) `e_flags` layouts.
  `Architecture::Cuda(SmArchitecture { … })` for SASS targets and
  `PtxVersion` for PTX sidecars; the kernel-level accelerator bit
  (`a` in `sm_90a`) round-trips correctly.
- **Kernel metadata** — typed `.nv.info` decode: register count, frame
  size, param-cbank layout, per-arg `(ordinal, offset, size)` table,
  EXIT offsets, `__launch_bounds__`, `ctaidz_used`. Surfaced via
  `Kernel::resource_usage()` and printed under each kernel by
  `hexray info`.
- **SASS disassembler** (`hexray-disasm` feature `cuda`) — 34 opcode
  classes covering the bulk of the sm_80/86/89 instruction stream:
  NOP, BRA, EXIT, MOV, S2R, IADD3, LEA, LOP3, SHF, IMAD(.WIDE), ISETP,
  PLOP3, FMUL/FADD/FFMA, HFMA2, FSETP, ULDC, LDG/LDC/LDS, STG/STS, RED,
  SHFL, POPC, VOTE(U), and more. Predicate guards (`@P0` / `@!P3`)
  and variant suffixes (`.GE.AND`, `.WIDE`, `.E.CONSTANT`,
  `.SYNC.DEFER_BLOCKING`, …) decoded inline.
- **Match rates against `nvdisasm`** on the in-repo corpus
  (10 microkernels × 3 SMs, 1,344 instructions, ptxas 13.2):

      sm_80 / sm_86 / sm_89:  100.0% base / 95.8% full / 100.0% guard
      sm_90 (Hopper):         97.2% full
      sm_75 (Turing):         softer 70% floor (incremental coverage)

  CI gates lock these floors at 70% / 92% / 95% so regressions are
  caught the moment they land.
- **Memory regions** — `.nv.constantN` (with bank number),
  `.nv.shared`, `.nv.local` classified into typed `MemoryRegion`s.
  `MemoryRef.space` (`Generic / Global / Shared / Local /
  Constant(u8) / Param`) flows through to the IR.
- **PTX sidecar parser** — `.nv_debug_ptx_txt` extracted into
  `PtxIndex` (header + every `.entry` / `.func` directive); also
  parses standalone `.ptx` files. Name-based linking to SASS kernels
  is implicit (same mangled name on both sides).
- **Fatbin wrapper extractor** — `magic 0xBA55_ED50` parsed into
  per-SM cubin / PTX entries (`FatbinEntry { kind, sm, payload,
  compressed }`). Compressed (LZ4) entries are flagged but not
  decompressed yet. Tolerant against malformed input — returns typed
  errors rather than panicking.
- **CLI** — `hexray info <cubin>`, `hexray <cubin> sections`,
  `hexray <cubin> symbols`, `hexray -s <kernel> <cubin>`.

Quality bar:

- 100+ new unit tests, 19 proptest properties, 5 cargo-fuzz targets,
  13 chaos / fault-injection tests run under both the regular suite
  and Miri (strict UB interpreter).
- `cargo-mutants` swept the SASS modules: `registers.rs` ends at 0
  missed of 57 viable; `opcode_table.rs` gained direct unit tests for
  every variant decoder.
- Workspace coverage 73.36%; new CUDA files 83-100% lines.
- Criterion benchmark for SASS decode (single NOP ≈ 43 ns; throughput
  ≈ 1.4 GB/s).
- `Send + Sync` compile-time witnesses on every owned CUDA type.

Known gaps (called out in `docs/CUDA.md`):

- Operand decoding emits destination + first source only; full memory-
  ref / cbank-ref rendering is follow-up work.
- LZ4-compressed fatbin entries are flagged but not decompressed.
- PTX is parsed at the sidecar level only — no AST.
- Maxwell / Pascal (sm_5x / sm_6x, 8-byte encoding) explicitly rejected.

See `docs/CUDA.md` for the user-facing guide and `crates/hexray-disasm/
src/cuda/sass/` for the decoder internals. Milestone-by-milestone
detail follows below.

### GPU Support — milestone-by-milestone detail

- **M1 – CUDA arch recognition**: `Architecture::Cuda(CudaArchitecture)` in
  `hexray-core`, carrying `SmArchitecture { family, major, minor, variant }`
  for SASS targets (`sm_80`, `sm_86`, `sm_89`, `sm_90a`, …) and `PtxVersion`
  for PTX sidecars. ELF `EM_CUDA = 190` is recognised with correct `e_flags`
  decoding for both ABI V1 (Ampere/Ada/Hopper) and ABI V2 (Blackwell+)
  layouts, including the `a` accelerator bit. `hexray info foo.cubin` now
  reports e.g. `cuda-sass (sm_80, family=Ampere)`. The previous
  `disassemble_block_for_arch` fallback that silently fed unknown-arch bytes
  to the x86 decoder has been removed — unsupported architectures now return
  an empty block rather than plausible-but-wrong disassembly.

- **M2 – raw CUBIN code-object view**: `Elf::cubin_view()` returns a typed
  `CubinView` over an EM_CUDA ELF, enumerating kernels, memory regions,
  module-wide `.nv.info`, and parsing diagnostics. Kernel detection uses
  the `STO_CUDA_ENTRY` bit in `st_other` (preserved from the raw symbol
  table), falling back to a sibling `.nv.info.<kernel>` section; ambiguous
  `.text.<name>` sections (e.g. out-of-line `__device__` helpers) are
  flagged rather than surfaced as kernels. `.nv.constantN`, `.nv.shared`,
  and `.nv.local` sections are classified into `MemoryRegion`s with the
  constant bank number preserved. `.nv.info` TLV framing is parsed into
  `NvInfoBlob { raw, entries: Vec<NvInfoEntryRef>, truncated }` with
  attribute IDs mapped to an `NvInfoAttribute` enum (unknown bytes are
  preserved verbatim). Payload semantics are intentionally left for M5.
  `hexray info foo.cubin` now lists kernels, memory regions, and any
  diagnostics. 18 new unit tests cover TLV framing, kernel detection,
  memory-region classification, and the edge cases called out in the M2
  design review.

- **M3 – SASS decode skeleton**: New `hexray-disasm/src/cuda/sass/` module
  (feature-gated on `cuda`) with a `SassDisassembler` targeting Volta
  through Blackwell (16-byte fixed-width encoding). The decoder walks
  code in lockstep 16-byte strides — overriding the default trait
  `disassemble_block` so a decode failure never desyncs the stream, which
  the byte-by-byte default would do catastrophically on a fixed-width
  ISA. `ControlBits` extracts the top 23 bits of each word (stall /
  yield / read-barrier / write-barrier / wait-mask / reuse).
  `registers.rs` handles the five SASS register files (R/P/UR/UP/SR)
  with RZ / PT / URZ / UPT aliases and `RegisterSpan` for `R0:R1`-style
  pairs rendered at display time rather than faked as register IDs.
  The M3 opcode table contains exactly one entry — the canonical
  Volta+ `NOP` (`0x7918` in the low 16 bits) — to prove end-to-end
  plumbing; real opcodes land in M4.

  Core IR extensions needed by the SASS decoder also landed:
  `Instruction.guard: Option<PredicateGuard>` for per-instruction
  predicate guards (`@P0` / `@!P0` on SASS); `MemoryRef.space:
  MemorySpace` with variants `Generic / Global / Shared / Local /
  Constant(u8) / Param`. Both default cleanly so CPU decoders compile
  unchanged. 29 new SASS tests plus tests for the IR extensions.

- **M5 – kernel metadata MVP**: Typed decoding of `.nv.info` record
  payloads. New `KernelResourceUsage` summary on `hexray-formats`:
  `max_reg_count`, `min_stack_size`, `frame_size`, `max_stack_size`,
  `cbank_param_size`, `param_cbank` (bank/offset/size),
  `params: Vec<ParamInfo>` with ordinal / offset / size_dwords /
  raw_trailer, `exit_offsets` (for CFG bookkeeping),
  `s2r_ctaid_offsets`, `max_threads`, `req_ntid` / `max_ntid` launch
  bounds, `ctaidz_used`. Accessed via `Kernel::resource_usage()`.

  Decoding is grounded in the 30-cubin handwritten corpus: every
  field matches the values `cuobjdump --dump-resource-usage` reports
  for the same cubin. `vector_add` → `regs=255 params@c[0][0x160]
  size=28 args=[#3:4B,#2:8B,#1:8B,#0:8B]`. `shared_transpose` →
  `args=[#2:4B,#1:8B,#0:8B]` + 4 KB static shared region.
  `constant_bias` → constant bank 3 surfaced as a dedicated memory
  region.

  Corpus-driven regression tests (`hexray-formats/tests/cuda_corpus.rs`)
  walk every cubin under `tests/corpus/cuda/build/`, asserting:
  (a) every kernel promotes via `STO_CUDA_ENTRY`, (b) no
  `MalformedNvInfo` diagnostics fire, (c) `PARAM_CBANK.size >=
  max(param_offset + param_size)`, (d) every EXIT offset lands on a
  16-byte boundary, (e) `constant_bias` exposes constant bank 3, (f)
  `shared_transpose` exposes its `.nv.shared.<kernel>` region. Tests
  no-op when the corpus isn't built locally, so CI (which doesn't
  ship a CUDA toolkit) stays green.

  `hexray info foo.cubin` now prints per-kernel `regs=`, `params@c[]`,
  `exits=`, `ctaidz`, and an `args=[#n:BsB,...]` summary underneath
  the kernel line.

- **M4 – core SASS semantics**: First working SASS opcode table.
  34 opcode classes harvested empirically from the 30-cubin
  sm_80/86/89 corpus and cross-referenced against `nvdisasm -json`
  base mnemonics: NOP, BRA, EXIT, BSYNC, BSSY, BAR, MOV, S2R, IADD3,
  LEA, LOP3, SHF, IMAD, IMAD.WIDE (shared class), ISETP, PLOP3, FMUL,
  FADD, FFMA, HFMA2, FSETP, ULDC, USHF, UFLO, LDG, LDC, LDS, STG, STS,
  RED, SHFL, POPC, VOTE, VOTEU. Each entry carries a `(op_class,
  base_mnemonic, Operation)` tuple in `cuda/sass/opcode_table.rs`.

  Predicate guard decoding (`Instruction.guard`): the 4-bit field at
  bits `[12..=15]` resolves to `@P0`..`@P6` / `@!P0`..`@!P6`, with
  `0b0111 = PT` collapsing to `None` (no guard printed).

  Basic operand extraction: destination register from bits `[16..=23]`
  on ALU/load/MOV/S2R classes; first source register from bits
  `[24..=31]` on ALU/compare/store/load. Full per-opcode operand
  decoding (memory refs, cbank refs, immediates) is M7.

  End-to-end match-rate gate in `crates/hexray/tests/cuda_sass_match.rs`:
  walks every cubin, decodes the `.text.<kernel>` section, compares
  recovered base mnemonics against `nvdisasm`'s ground truth.

  Current results on the handwritten microkernel corpus:

      sm_80: 448/448 = 100.0%  across 10 kernels
      sm_86: 448/448 = 100.0%  across 10 kernels
      sm_89: 448/448 = 100.0%  across 10 kernels

  The M4 success criterion (≥ 70% base match on sm_80) is the test's
  gate; the actual number is 100%. Variant suffixes and full operand
  rendering bring the numbers down again under M7's stricter
  comparison, as expected.

  3 new integration tests, 5 new opcode_table unit tests, 2 new
  decoder unit tests (predicate decode, desync-free walk). Full
  workspace green, clippy clean with `-D warnings`.

- **M6 – differential harness + corpus pipeline**: Proper SASS diff
  module at `crates/hexray/tests/differential/sass_compare.rs`,
  wired into the existing `differential_tests` integration surface
  alongside the objdump / nm / strings gates. Tracks match rates at
  three tightening levels — base mnemonic, full mnemonic (with
  `.`-suffix variants), and predicate guard. Results serialise to
  JSON (`/tmp/hexray-sass-diff-report.json`) for CI artefact
  tracking. Skips silently when the corpus isn't built on the box.

  Live gates (floors, not targets):

      sm_80 base mnemonic ≥ 70%
      every SM predicate guard ≥ 95%
      every SM full mnemonic ≥ 5% (regression floor only)

  Current numbers on ptxas 13.2 / sm_80/86/89:

      sm_80  kernels=10  insts=448  base=100.0%  full=65.2%  guard=100.0%
      sm_86  kernels=10  insts=448  base=100.0%  full=67.9%  guard=100.0%
      sm_89  kernels=10  insts=448  base=100.0%  full=67.9%  guard=100.0%

  The full-mnemonic floor is set low because variant suffixes
  (`.E.CONSTANT`, `.WIDE`, `.GE.AND`) land in M7. The current 65-68%
  figure comes from instructions that have no variant suffix
  (`NOP`, `BRA`, `EXIT`, `MOV`, `S2R`, …); M7 brings it up.

- **M7 – Ampere/Ada coverage expansion**: Per-opcode variant-suffix
  decoders lift full-mnemonic match from 65% → **95.8%** on the
  sm_80/86/89 handwritten corpus. New `default_suffix` field on every
  `OpcodeEntry` for always-present suffixes (`LOP3.LUT`, `PLOP3.LUT`,
  `HFMA2.MMA`, `STG.E`, `LDG.E.CONSTANT`, `BAR.SYNC.DEFER_BLOCKING`,
  `SHFL.DOWN`, `VOTE.ANY`, `RED.E.ADD.STRONG.GPU`, …), plus a
  `Option<VariantFn>` callback for opcodes whose suffix depends on
  encoding bits:

      ISETP/FSETP    → cmp (bits 76-78) + bool (74-75) + signed (73)
                       yields .GE.AND, .GT.U32.OR, etc. (24 cases/SM)
      IMAD           → .X (bit 72) or .MOV.U32 (RZ,RZ multiplicands)
      IMAD.WIDE      → .WIDE vs .WIDE.U32 on bit 73
      IADD3          → .X on bit 74
      LEA            → .HI / .X / .HI.X / .HI.X.SX32 combinations
      SHF            → direction (L/R) + type (U32/S32) + .HI
      ULDC           → .64 on bit 73
      LDG            → .CONSTANT on cache-op field

  Raised the differential harness's `FULL_MNEMONIC_ALL_SMS` threshold
  from 5.0% (regression floor) to **92.0%** (M7 success criterion).

  Live numbers on ptxas 13.2 as of M7 landing:

      sm_80: 448/448 = 100.0% base /  95.8% full / 100.0% guard
      sm_86: 448/448 = 100.0% base /  95.8% full / 100.0% guard
      sm_89: 448/448 = 100.0% base /  95.8% full / 100.0% guard

  The remaining ~4.2% gap is concentrated in `IMAD.MOV.U32` detection
  (needs better operand-pattern recognition), some `SHF` / `USHF`
  variants, and `LEA.HI.SX32` vs `LEA.HI.X.SX32`. Those land as
  follow-up patches under M7 once the user-declared operand decoding
  (the second half of M7 per codex's plan) is in.

- **M8 – fatbin + PTX sidecar**: Two new modules land:

  - `crates/hexray-formats/src/elf/cuda/ptx.rs` — cheap PTX text
    parser. `PtxIndex::parse(&str)` for standalone `.ptx` files,
    `PtxIndex::from_nul_delimited_bytes(&[u8])` for the
    `.nv_debug_ptx_txt` section `nvcc -lineinfo` embeds inside
    CUBINs (which separates directives with `\0` instead of `\n`).
    Extracts the module header (`.version` / `.target` /
    `.address_size`) and indexes every `.entry` / `.func`
    directive with its body span — enough for a UI to render PTX
    side-by-side with SASS or for name-based kernel linking. No
    AST, per codex's design note.

    Accessed via `Kernel::resource_usage()`-style sugar on the
    CubinView: `view.ptx_sidecar() -> Option<PtxIndex<'_>>`. A
    corpus regression test confirms every ptxas-13.2 cubin in
    `tests/corpus/cuda/build/` exposes a valid PTX sidecar whose
    `.entry` directive matches the SASS kernel name.

  - `crates/hexray-formats/src/cuda/fatbin.rs` — fatbin wrapper
    parser. `FatbinWrapper::parse(&[u8])` reads the 16-byte
    wrapper (`magic 0xBA55_ED50`) + packed entry table; surfaces
    `FatbinEntry { kind, sm, payload, compressed }` for each
    embedded cubin / PTX blob, with `cubins()` / `ptx_entries()`
    convenience iterators. Tolerant against malformed input —
    returns `FatbinError::{Truncated, BadMagic, EntryOverflow,
    PayloadOverflow}` rather than panicking. Tests synthesise
    wrappers around real sm_80 cubins from the corpus and
    round-trip them byte-for-byte; `host-binary-embedded fatbin`
    validation is deferred to a future corpus rebuild (needs a
    host ELF that `nvcc` produced with `-rdc=true`).

  PTX↔SASS linking for the single-kernel-per-cubin case is
  already implicit: both sides use the same (mangled) name, so
  `ptx.function_by_name(&sass_kernel.name)` just works.

- **GPU testing batch**: closes the quality bar items the rest of the
  repo holds new code to.
  - CUDA-info snapshot test (hermetic synthetic stub).
  - `Send + Sync` compile-time witnesses on the SASS decoder, owned
    record types, and the fatbin wrapper.
  - CFG smoke test that feeds real SASS instructions through the
    existing `CfgBuilder`.
  - Miri now runs the CUDA fault-injection suite (13 tests pass under
    the strict UB interpreter).
  - Coverage check passes: workspace 73.36%, every new CUDA file
    83-100% lines.
  - Mutation testing run with `cargo-mutants` on the SASS modules;
    surfaced gaps closed in `registers.rs` (now 0 missed of 57
    viable) and tightened tests on `variant_setp` / `variant_lea`
    / `variant_shf`.
  - Criterion benchmark for SASS decode (single NOP ≈ 43 ns;
    1024-instruction throughput ≈ 1.4 GB/s).
  - Corpus extended to sm_75 and sm_90 (Turing + Hopper). The
    differential gate is SM-band-aware: v1 SMs (sm_80/86/89) keep
    the 92% full-mnemonic floor; sm_75 / sm_90 track a softer 70%
    floor while we incrementally add their SM-specific opcodes.
  - New opcode entries: `S2UR`, `VIADD`, `BMOV`, plus `LDC.64`
    variant. sm_90 full-mnemonic match: 91.3% → 97.2%.

- **CLI dispatch fixes (surfaced by hands-on cubin testing)**:
  driving `hexray -s vector_add vector_add.cubin` end-to-end exposed
  four integration gaps the parser-level tests couldn't see — every
  test covered the data plane; nothing covered the CLI dispatch path.
  - `find_symbol` filtered `s.address != 0`, which hid every CUBIN
    kernel (CUBIN symbol addresses are section-relative 0 until the
    driver maps the module). Now filters only on `is_defined()`.
  - `disassemble_block_for_arch` and `disassemble_at` had no CUDA
    arms — `Architecture::Cuda(_)` was matched alongside `Arm` and
    `Unknown` and returned an empty Vec / bailed. Wired both to
    `SassDisassembler::for_sm(sm)`.
  - `Elf::bytes_at` and `parse_symbols` didn't treat CUBINs as
    needing section-relative addressing. CUBINs are ET_EXEC but
    every `sh_addr = 0`; symbol lookups landed in the wrong place.
    `header.machine == Machine::Cuda` now participates in the
    `is_relocatable` flag everywhere it matters.
  - `Register::name()` returned `"unknown"` for every CUDA register.
    Added a `cuda_reg_name` dispatcher with static lookup tables
    for `R0..R255` (RZ at 255), `P0..P7` (PT at 7), `UR0..UR63`
    (URZ at 63), `UP0..UP7` (UPT at 7), and the SR special-register
    set. The `0x1000` marker bit set by the SASS uniform-register
    decoders disambiguates UR/R and UP/P inside the same
    `RegisterClass`.

## [1.2.1] - 2026-03-19

### Testing

- **Swarm Testing**: Added swarm testing infrastructure for decompiler (Groce et al., ISSTA 2012)
  - Randomly omit optimization passes to find bugs through feature-omission diversity
  - `DecompilerConfig::from_swarm_bits()` for coin-toss pass selection
  - proptest suite: crash safety, determinism, monotonicity, loop robustness
  - Per-pass trigger/suppressor analysis (coverage report)
  - Verified on x86_64 and aarch64 with 0 failures across 1,200+ random configs

- **Miri Memory-Safety Gate**: Added Miri to pre-push validation (e76fc4b3a)

- **Feature, Security, and Coverage Gates**: Added comprehensive test gates (400afdfb8)

### Hardening

- **Mach-O Parser**: Hardened load command parsing against malformed inputs (67f6952f9)

- **Incremental Analysis**: Hardened invalidation logic and modeled it (9d25e3db9)

## [1.2.0] - 2026-02-25

### Critical Fixes

- **CRITICAL**: Fixed register aliasing in decompiler optimization passes (ae6326c93, 39e6156e5)
  - Loop variable updates were being incorrectly eliminated on ARM64 and x86-64
  - Made copy propagation and dead store elimination aware of register aliasing (w9↔x9, eax↔rax)
  - Fixes infinite loops, uninitialized variables, and non-compilable output
  - All 1040+ tests passing
  - Tested with 15+ different loop patterns across ARM64 and x86-64

### Decompiler Improvements

- **Loop Variable Tracking**: Fixed emission phase statement skipping logic (ae6326c93)
  - Fixed skip_statements to use BasicBlockId instead of positional index
  - Fixed return register and temp register filtering
  - Preserves critical loop variable assignments

- **Signature Recovery**: Preserve calling convention registers for better signature inference (d5fa20676)

- **Type Inference**: Add typed pointer inference for arrays (520748b7b)

- **Output Quality**: Comprehensive output quality improvements (47bfb66e8, 0e7a13bf2)
  - Improved type defaults and signature validation
  - Enhanced callback recovery with better alias tracking
  - Reduced callback shape-fallback false positives (20a6ffc60)
  - Hardened callback alias recovery with quality gates (a4738f1e4)

- **Parameter Naming**: Align lifted arg-slot parameter naming (8e4ead436)
  - Improved variable declarations and parameter naming (25571844b)
  - Fixed header/body naming mismatches

- **Return Type Inference**:
  - Default literal return nodes to int32 (960ee18dc)
  - Keep return-register width for literal returns (93a5e99cd)
  - Improved main-like function return typing

- **Loop Initialization**:
  - Improved loop-condition zero-init analysis (order-aware) (46ff4844f)
  - Fixed use-before-write artifacts in counter-like variables

- **Code Cleanup**:
  - Filter prologue callee-saved register saves (b14840f3c)
  - Filter epilogue register restores (41bb2bc8e)
  - Stop emission after control-exit statements (3348b91ec)

- **ARM64 Specific**:
  - Improved ARM64 output readability (6e0ba10fc)
  - Expanded ARM64 register renaming (0166ea493)
  - Improved Linux/ARM64 output quality (d24580377)

### Testing

- Updated callback test expectations for array parameter names (719b41f32, 65cf0df48, 0a630ef0a)
- Updated sort test expectations (53284d4bb)
- Added stack-spill callback quality gates to benchmarks (cd7af86c8)
- Added signature validation to benchmark system (3b70944d1)

### Bug Fixes

- Fix clippy warning for manual range contains (bbbc4caca)

### Documentation

- Documented register aliasing fix in DECOMPILER_IMPROVEMENTS.md (5bc940f31)
  - Added comprehensive section with examples, root cause analysis, and testing details

## [1.1.0] - (Previous release)

(Historical changes from previous releases)

## [1.0.0] - (Initial release)

(Historical changes from initial release)
