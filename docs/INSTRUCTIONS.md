# Supported Instructions

## x86_64

### Data Movement
| Instruction | Description |
|-------------|-------------|
| `mov` | Move data |
| `movzx` | Move with zero-extend |
| `movsx` | Move with sign-extend |
| `movsxd` | Move with sign-extend (dword to qword) |
| `lea` | Load effective address |
| `push` | Push to stack |
| `pop` | Pop from stack |
| `xchg` | Exchange |
| `cmov*` | Conditional move (all variants) |

### Arithmetic
| Instruction | Description |
|-------------|-------------|
| `add` | Add |
| `sub` | Subtract |
| `imul` | Signed multiply |
| `mul` | Unsigned multiply |
| `idiv` | Signed divide |
| `div` | Unsigned divide |
| `inc` | Increment |
| `dec` | Decrement |
| `neg` | Negate |
| `adc` | Add with carry |
| `sbb` | Subtract with borrow |

### Logical / Bitwise
| Instruction | Description |
|-------------|-------------|
| `and` | Bitwise AND |
| `or` | Bitwise OR |
| `xor` | Bitwise XOR |
| `not` | Bitwise NOT |
| `shl` | Shift left |
| `shr` | Shift right (logical) |
| `sar` | Shift right (arithmetic) |
| `rol` | Rotate left |
| `ror` | Rotate right |
| `rcl` | Rotate through carry left |
| `rcr` | Rotate through carry right |
| `bt` | Bit test |
| `bts` | Bit test and set |
| `btr` | Bit test and reset |
| `btc` | Bit test and complement |
| `bsf` | Bit scan forward |
| `bsr` | Bit scan reverse |

### BMI1/BMI2 Bit Manipulation
| Instruction | Description |
|-------------|-------------|
| `andn` | AND NOT |
| `bextr` | Bit field extract |
| `blsi` | Extract lowest set bit |
| `blsmsk` | Get mask up to lowest set bit |
| `blsr` | Reset lowest set bit |
| `bzhi` | Zero high bits starting at position |
| `pdep` | Parallel bits deposit |
| `pext` | Parallel bits extract |
| `mulx` | Unsigned multiply without flags |
| `rorx` | Rotate right without flags |
| `sarx` | Shift arithmetic right without flags |
| `shrx` | Shift right without flags |
| `shlx` | Shift left without flags |

### Bit Count Instructions
| Instruction | Description |
|-------------|-------------|
| `popcnt` | Population count (count 1 bits) |
| `lzcnt` | Leading zero count |
| `tzcnt` | Trailing zero count |

### Comparison / Test
| Instruction | Description |
|-------------|-------------|
| `cmp` | Compare |
| `test` | Bitwise test |
| `setcc` | Set byte on condition (all variants) |

### Control Flow
| Instruction | Description |
|-------------|-------------|
| `jmp` | Unconditional jump |
| `je/jz` | Jump if equal/zero |
| `jne/jnz` | Jump if not equal/not zero |
| `jl/jnge` | Jump if less |
| `jle/jng` | Jump if less or equal |
| `jg/jnle` | Jump if greater |
| `jge/jnl` | Jump if greater or equal |
| `ja/jnbe` | Jump if above (unsigned) |
| `jae/jnb` | Jump if above or equal |
| `jb/jnae` | Jump if below (unsigned) |
| `jbe/jna` | Jump if below or equal |
| `js` | Jump if sign |
| `jns` | Jump if not sign |
| `jo` | Jump if overflow |
| `jno` | Jump if not overflow |
| `jp` | Jump if parity |
| `jnp` | Jump if not parity |
| `call` | Call procedure |
| `ret` | Return |
| `syscall` | System call |

### String Operations
| Instruction | Description |
|-------------|-------------|
| `movsb/w/d/q` | Move string |
| `stosb/w/d/q` | Store string |
| `lodsb/w/d/q` | Load string |
| `cmpsb/w/d/q` | Compare strings |
| `scasb/w/d/q` | Scan string |
| `rep` | Repeat prefix |
| `repe/repz` | Repeat while equal |
| `repne/repnz` | Repeat while not equal |

### SSE/AVX (VEX prefix)
| Instruction | Description |
|-------------|-------------|
| `movaps/movapd` | Move aligned packed |
| `movups/movupd` | Move unaligned packed |
| `movss/movsd` | Move scalar |
| `movdqa/movdqu` | Move double quadword |
| `addps/addpd/addss/addsd` | Add packed/scalar |
| `subps/subpd/subss/subsd` | Subtract packed/scalar |
| `mulps/mulpd/mulss/mulsd` | Multiply packed/scalar |
| `divps/divpd/divss/divsd` | Divide packed/scalar |
| `sqrtps/sqrtpd/sqrtss/sqrtsd` | Square root |
| `minps/maxps/minpd/maxpd` | Min/max packed |
| `andps/andpd/orps/orpd` | Bitwise packed |
| `xorps/xorpd` | XOR packed |
| `cmpps/cmppd/cmpss/cmpsd` | Compare packed/scalar |
| `pand/pandn/por/pxor` | Integer SIMD bitwise |
| `paddb/w/d/q` | Integer add |
| `psubb/w/d/q` | Integer subtract |
| `pmullw/pmulld` | Integer multiply |
| `psllw/d/q` | Packed shift left |
| `psrlw/d/q` | Packed shift right logical |
| `psraw/d/q` | Packed shift right arithmetic |
| `punpcklbw/wd/dq` | Unpack low |
| `punpckhbw/wd/dq` | Unpack high |
| `pshufb/pshufd/pshufhw/pshuflw` | Shuffle |
| `palignr` | Packed align right |
| `pblendw/pblendvb` | Blend |
| `vpermilps/vpermilpd` | Permute in-lane |
| `vperm2f128` | Permute 128-bit lanes |
| `vbroadcast*` | Broadcast |
| `vextract*` | Extract |
| `vinsert*` | Insert |

### VEX 0F38 (FMA, AVX2, AES-NI)
| Instruction | Description |
|-------------|-------------|
| `vfmadd*/vfmsub*/vfnmadd*/vfnmsub*` | Fused multiply-add variants |
| `aesenc/aesenclast` | AES encrypt round |
| `aesdec/aesdeclast` | AES decrypt round |
| `aesimc` | AES inverse mix columns |
| `aeskeygenassist` | AES key generation |
| `pclmulqdq/vpclmulqdq` | Carry-less multiply |
| `sha1*/sha256*` | SHA hash operations |

### AVX-512 (EVEX prefix)
| Instruction | Description |
|-------------|-------------|
| `vmovaps/vmovapd` (512-bit) | Move aligned |
| `vmovups/vmovupd` (512-bit) | Move unaligned |
| `vaddps/vaddpd` (512-bit) | Add |
| `vsubps/vsubpd` (512-bit) | Subtract |
| `vmulps/vmulpd` (512-bit) | Multiply |
| `vdivps/vdivpd` (512-bit) | Divide |
| `vfmadd*` (512-bit) | Fused multiply-add |
| `kmov*` | Mask register moves |
| `kand/kandn/kor/kxor/knot` | Mask operations |
| Masking support | {k1}-{k7} write masks |
| Zeroing support | {z} zero masking |
| Broadcast support | {1to8}, {1to16} |

---

## ARM64 (AArch64)

### Data Movement
| Instruction | Description |
|-------------|-------------|
| `mov` | Move |
| `movz` | Move wide with zero |
| `movn` | Move wide with NOT |
| `movk` | Move wide with keep |
| `ldr` | Load register |
| `ldp` | Load pair |
| `str` | Store register |
| `stp` | Store pair |
| `ldrb/ldrh/ldrsb/ldrsh/ldrsw` | Load byte/half/signed |
| `strb/strh` | Store byte/half |
| `ldur/stur` | Unscaled offset load/store |
| `adr` | PC-relative address |
| `adrp` | PC-relative address (page) |

### Arithmetic
| Instruction | Description |
|-------------|-------------|
| `add` | Add |
| `adds` | Add and set flags |
| `sub` | Subtract |
| `subs` | Subtract and set flags |
| `mul` | Multiply |
| `madd` | Multiply-add |
| `msub` | Multiply-subtract |
| `smull/umull` | Signed/unsigned multiply long |
| `smaddl/umaddl` | Multiply-add long |
| `sdiv` | Signed divide |
| `udiv` | Unsigned divide |
| `neg` | Negate |
| `adc/sbc` | Add/subtract with carry |

### Logical
| Instruction | Description |
|-------------|-------------|
| `and` | Bitwise AND |
| `ands` | Bitwise AND and set flags |
| `orr` | Bitwise OR |
| `eor` | Bitwise XOR |
| `bic` | Bit clear |
| `orn` | OR NOT |
| `eon` | XOR NOT |
| `mvn` | Bitwise NOT |
| `lsl` | Logical shift left |
| `lsr` | Logical shift right |
| `asr` | Arithmetic shift right |
| `ror` | Rotate right |
| `ubfm/sbfm/bfm` | Bit field move |
| `ubfx/sbfx/bfi/bfxil` | Bit field extract/insert |
| `cls/clz` | Count leading sign/zeros |
| `rbit/rev/rev16/rev32` | Reverse bits/bytes |

### Comparison
| Instruction | Description |
|-------------|-------------|
| `cmp` | Compare |
| `cmn` | Compare negative |
| `tst` | Test bits |
| `ccmp/ccmn` | Conditional compare |

### Control Flow
| Instruction | Description |
|-------------|-------------|
| `b` | Branch |
| `b.eq/ne/lt/le/gt/ge` | Conditional branch |
| `b.hi/hs/lo/ls` | Unsigned conditional branch |
| `b.mi/pl/vs/vc` | Negative/positive/overflow branch |
| `bl` | Branch with link |
| `blr` | Branch with link to register |
| `br` | Branch to register |
| `ret` | Return |
| `cbz/cbnz` | Compare and branch if zero/not zero |
| `tbz/tbnz` | Test bit and branch |
| `svc` | Supervisor call |

### Conditional
| Instruction | Description |
|-------------|-------------|
| `csel` | Conditional select |
| `csinc/csinv/csneg` | Conditional select variants |
| `cset/csetm` | Conditional set |
| `cinc/cinv/cneg` | Conditional increment/invert/negate |

### Atomic Operations
| Instruction | Description |
|-------------|-------------|
| `ldxr/ldxrb/ldxrh` | Load exclusive |
| `stxr/stxrb/stxrh` | Store exclusive |
| `ldxp/stxp` | Load/store exclusive pair |
| `ldaxr/stlxr` | Load-acquire/store-release exclusive |
| `cas/casa/casl/casal` | Compare and swap |
| `casp/caspa/caspl/caspal` | Compare and swap pair |
| `ldadd/ldadda/ldaddl/ldaddal` | Atomic add |
| `ldclr/ldset/ldeor` | Atomic clear/set/xor |
| `ldsmaxl/ldsminl/ldumaxl/lduminl` | Atomic max/min |
| `swp/swpa/swpl/swpal` | Atomic swap |
| `dmb/dsb/isb` | Memory barriers |

### NEON SIMD
| Instruction | Description |
|-------------|-------------|
| `ld1/ld2/ld3/ld4` | Structure load |
| `st1/st2/st3/st4` | Structure store |
| `add/sub` (vector) | Vector add/subtract |
| `mul/mla/mls` (vector) | Vector multiply |
| `and/orr/eor/bic` (vector) | Vector bitwise |
| `shl/sshl/ushl` | Vector shift |
| `sshr/ushr` | Vector shift right |
| `saddl/uaddl/ssubl/usubl` | Widening add/subtract |
| `addv/saddlv/uaddlv` | Reduce add |
| `smaxv/sminv/umaxv/uminv` | Reduce max/min |
| `dup/ins/mov` (vector) | Duplicate/insert/move |
| `tbl/tbx` | Table lookup |
| `zip1/zip2/uzp1/uzp2` | Interleave/deinterleave |
| `trn1/trn2` | Transpose |
| `fcmp/fcmpe` | Floating compare |
| `fadd/fsub/fmul/fdiv` | Floating arithmetic |
| `fmla/fmls/fmadd/fmsub` | Floating multiply-accumulate |
| `fcvt*/scvtf/ucvtf` | Floating conversion |
| `fabs/fneg/fsqrt` | Floating unary |
| `frint*/frintn/frintp/frintm` | Floating round |

### Crypto Extensions
| Instruction | Description |
|-------------|-------------|
| `aese/aesd` | AES encrypt/decrypt round |
| `aesmc/aesimc` | AES mix columns |
| `sha1c/sha1h/sha1m/sha1p/sha1su0/sha1su1` | SHA1 operations |
| `sha256h/sha256h2/sha256su0/sha256su1` | SHA256 operations |
| `pmull/pmull2` | Polynomial multiply long |

### SVE/SVE2 (Scalable Vector Extension)
| Instruction | Description |
|-------------|-------------|
| `cntb/cnth/cntw/cntd` | Count elements |
| `dup` (scalar to vector) | Broadcast scalar |
| `add/sub/mul` (predicated) | Predicated arithmetic |
| `ptrue/pfalse` | Predicate initialization |
| `ld1b/ld1h/ld1w/ld1d` | Contiguous load |
| `st1b/st1h/st1w/st1d` | Contiguous store |
| `sqabs/sqneg` | Saturating absolute/negate |
| `sqdmulh/sqrdmulh` | Saturating doubling multiply high |
| `saba/uaba` | Absolute difference accumulate |
| `bdep/bext/bgrp` | Bit manipulation |
| `aese/aesd/aesmc/aesimc` | SVE2 AES |
| `sm4e/sm4ekey` | SVE2 SM4 |
| `rax1` | SVE2 SHA3 rotate |
| `histcnt/histseg` | Histogram |
| `match/nmatch` | Character match |

---

## RISC-V

### RV64I Base Integer Instructions

#### Data Movement
| Instruction | Description |
|-------------|-------------|
| `lui` | Load upper immediate |
| `auipc` | Add upper immediate to PC |
| `ld/lw/lh/lb` | Load (double/word/half/byte) |
| `lwu/lhu/lbu` | Load unsigned |
| `sd/sw/sh/sb` | Store |

#### Arithmetic
| Instruction | Description |
|-------------|-------------|
| `add/addi` | Add |
| `addw/addiw` | Add word (32-bit) |
| `sub/subw` | Subtract |
| `slt/slti` | Set less than |
| `sltu/sltiu` | Set less than unsigned |

#### Logical
| Instruction | Description |
|-------------|-------------|
| `and/andi` | Bitwise AND |
| `or/ori` | Bitwise OR |
| `xor/xori` | Bitwise XOR |
| `sll/slli` | Shift left logical |
| `srl/srli` | Shift right logical |
| `sra/srai` | Shift right arithmetic |
| `sllw/srlw/sraw` | Word shifts |

#### Control Flow
| Instruction | Description |
|-------------|-------------|
| `jal` | Jump and link |
| `jalr` | Jump and link register |
| `beq/bne` | Branch if equal/not equal |
| `blt/bge` | Branch if less/greater-equal |
| `bltu/bgeu` | Unsigned branch |
| `ecall` | Environment call |
| `ebreak` | Environment break |

### M Extension (Multiply/Divide)
| Instruction | Description |
|-------------|-------------|
| `mul/mulh/mulhsu/mulhu` | Multiply |
| `mulw` | Multiply word |
| `div/divu` | Divide |
| `divw/divuw` | Divide word |
| `rem/remu` | Remainder |
| `remw/remuw` | Remainder word |

### A Extension (Atomics)
| Instruction | Description |
|-------------|-------------|
| `lr.w/lr.d` | Load reserved |
| `sc.w/sc.d` | Store conditional |
| `amoswap.w/d` | Atomic swap |
| `amoadd.w/d` | Atomic add |
| `amoxor.w/d` | Atomic XOR |
| `amoand.w/d` | Atomic AND |
| `amoor.w/d` | Atomic OR |
| `amomin.w/d` | Atomic min (signed) |
| `amomax.w/d` | Atomic max (signed) |
| `amominu.w/d` | Atomic min (unsigned) |
| `amomaxu.w/d` | Atomic max (unsigned) |

### RVC (Compressed) Extension

16-bit compressed instructions are automatically expanded:

| Compressed | Expands To |
|------------|------------|
| `c.addi` | `addi` |
| `c.addiw` | `addiw` |
| `c.addi16sp` | `addi sp, sp, imm` |
| `c.addi4spn` | `addi rd, sp, imm` |
| `c.li` | `addi rd, x0, imm` |
| `c.lui` | `lui rd, imm` |
| `c.mv` | `add rd, x0, rs` |
| `c.add` | `add rd, rd, rs` |
| `c.sub` | `sub rd, rd, rs` |
| `c.and/or/xor` | `and/or/xor rd, rd, rs` |
| `c.andi` | `andi rd, rd, imm` |
| `c.slli` | `slli rd, rd, imm` |
| `c.srli/srai` | `srli/srai rd, rd, imm` |
| `c.j` | `jal x0, offset` |
| `c.jal` | `jal ra, offset` |
| `c.jr` | `jalr x0, rs, 0` |
| `c.jalr` | `jalr ra, rs, 0` |
| `c.beqz/bnez` | `beq/bne rs, x0, offset` |
| `c.lw/ld` | `lw/ld rd, offset(rs)` |
| `c.lwsp/ldsp` | `lw/ld rd, offset(sp)` |
| `c.sw/sd` | `sw/sd rs, offset(rs')` |
| `c.swsp/sdsp` | `sw/sd rs, offset(sp)` |
| `c.nop` | `addi x0, x0, 0` |
| `c.ebreak` | `ebreak` |

---

## CUDA SASS

NVIDIA SASS (Volta and newer, 16-byte fixed-width encoding). Recognised
on `EM_CUDA` ELFs (cubins) when the `hexray-disasm` crate is built with
the `cuda` feature. `nvdisasm`-style mnemonics with variant suffixes
(`.GE.AND`, `.WIDE`, `.E.CONSTANT`, …) decoded inline; per-instruction
predicate guards (`@P0` / `@!P3`) printed when present.

### Control Flow
| Instruction | Description |
|-------------|-------------|
| `NOP` | No operation |
| `BRA` | Unconditional / predicated branch |
| `EXIT` | Kernel exit |
| `BSYNC` | Convergence barrier sync |
| `BSSY` | Convergence barrier set |
| `BAR` | Barrier (default `.SYNC.DEFER_BLOCKING`) |

### Data Movement
| Instruction | Description |
|-------------|-------------|
| `MOV` | Move register / immediate |
| `S2R` | Read special register (`SR_TID`, `SR_CTAID`, …) |
| `S2UR` | Read special register into uniform datapath |
| `BMOV` | Barrier move (default `.32.CLEAR`) |

### Integer Arithmetic
| Instruction | Description |
|-------------|-------------|
| `IADD3` | 3-input integer add (`.X` for carry-in chains) |
| `LEA` | Load effective address (`.HI` / `.X` / `.HI.X.SX32`) |
| `IMAD` | Multiply-add (`.X`, `.MOV.U32` recognised) |
| `IMAD.WIDE` | 32×32→64 multiply-add (`.WIDE` / `.WIDE.U32`) |
| `VIADD` | Vector integer add |

### Bitwise / Shift
| Instruction | Description |
|-------------|-------------|
| `LOP3` | 3-input bitwise op (always `.LUT`) |
| `PLOP3` | 3-input predicate logic (always `.LUT`) |
| `SHF` | Funnel shift (direction L/R, type U32/S32, optional `.HI`) |
| `USHF` | Uniform funnel shift |

### Compare / Predicate
| Instruction | Description |
|-------------|-------------|
| `ISETP` | Integer compare-and-set-predicate (24 cmp/bool/signed combos) |
| `FSETP` | Float compare-and-set-predicate |

### Floating Point
| Instruction | Description |
|-------------|-------------|
| `FMUL` | FP32 multiply |
| `FADD` | FP32 add |
| `FFMA` | FP32 fused multiply-add |
| `HFMA2` | FP16×2 fused multiply-add (always `.MMA`) |

### Uniform Datapath
| Instruction | Description |
|-------------|-------------|
| `ULDC` | Uniform load constant (`.64` recognised) |
| `UFLO` | Uniform find-leading-one (always `.U32`) |

### Memory
| Instruction | Description |
|-------------|-------------|
| `LDG` | Load global (default `.E`; `.CONSTANT` recognised) |
| `LDC` | Load constant bank |
| `LDS` | Load shared |
| `STG` | Store global (default `.E`) |
| `STS` | Store shared |
| `RED` | Atomic reduce (default `.E.ADD.STRONG.GPU`) |

### Warp Operations
| Instruction | Description |
|-------------|-------------|
| `SHFL` | Warp shuffle (default `.DOWN`) |
| `POPC` | Population count |
| `VOTE` | Warp vote (default `.ANY`) |
| `VOTEU` | Uniform warp vote (default `.ANY`) |

### Coverage notes

- ~36 opcode classes → 95.8% full-mnemonic match against `nvdisasm`
  on the in-repo sm_80/86/89 corpus (10 microkernels × 3 SMs,
  1,344 instructions). Base-mnemonic match is 100%.
- Operand decoding in v1.3.0 emits destination + first source only;
  full memory-ref / cbank-ref rendering is follow-up work.
- Maxwell / Pascal (sm_5x / sm_6x, 8-byte encoding) explicitly
  rejected — Volta's 16-byte encoding is the supported floor.
- See [`CUDA.md`](CUDA.md) for the user-facing CUBIN walkthrough and
  the per-SM match-rate table.
