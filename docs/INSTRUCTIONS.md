# Supported Instructions

## x86_64

### Data Movement
| Instruction | Description |
|-------------|-------------|
| `mov` | Move data |
| `movzx` | Move with zero-extend |
| `movsx` | Move with sign-extend |
| `lea` | Load effective address |
| `push` | Push to stack |
| `pop` | Pop from stack |
| `xchg` | Exchange |

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

### Comparison / Test
| Instruction | Description |
|-------------|-------------|
| `cmp` | Compare |
| `test` | Bitwise test |

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
| `call` | Call procedure |
| `ret` | Return |
| `syscall` | System call |

### String Operations
| Instruction | Description |
|-------------|-------------|
| `rep movsb` | Repeat move string byte |
| `rep stosb` | Repeat store string byte |

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
| `sdiv` | Signed divide |
| `udiv` | Unsigned divide |
| `neg` | Negate |

### Logical
| Instruction | Description |
|-------------|-------------|
| `and` | Bitwise AND |
| `ands` | Bitwise AND and set flags |
| `orr` | Bitwise OR |
| `eor` | Bitwise XOR |
| `bic` | Bit clear |
| `mvn` | Bitwise NOT |
| `lsl` | Logical shift left |
| `lsr` | Logical shift right |
| `asr` | Arithmetic shift right |
| `ror` | Rotate right |

### Comparison
| Instruction | Description |
|-------------|-------------|
| `cmp` | Compare |
| `cmn` | Compare negative |
| `tst` | Test bits |

### Control Flow
| Instruction | Description |
|-------------|-------------|
| `b` | Branch |
| `b.eq` | Branch if equal |
| `b.ne` | Branch if not equal |
| `b.lt` | Branch if less than |
| `b.le` | Branch if less or equal |
| `b.gt` | Branch if greater than |
| `b.ge` | Branch if greater or equal |
| `b.hi` | Branch if higher (unsigned) |
| `b.hs` | Branch if higher or same |
| `b.lo` | Branch if lower (unsigned) |
| `b.ls` | Branch if lower or same |
| `bl` | Branch with link |
| `blr` | Branch with link to register |
| `br` | Branch to register |
| `ret` | Return |
| `cbz` | Compare and branch if zero |
| `cbnz` | Compare and branch if not zero |
| `tbz` | Test bit and branch if zero |
| `tbnz` | Test bit and branch if not zero |
| `svc` | Supervisor call |

### Conditional
| Instruction | Description |
|-------------|-------------|
| `csel` | Conditional select |
| `csinc` | Conditional select increment |
| `cset` | Conditional set |

---

## RISC-V

### RV64I Base Integer Instructions

#### Data Movement
| Instruction | Description |
|-------------|-------------|
| `lui` | Load upper immediate |
| `auipc` | Add upper immediate to PC |
| `ld` | Load doubleword |
| `lw` | Load word |
| `lh` | Load halfword |
| `lb` | Load byte |
| `sd` | Store doubleword |
| `sw` | Store word |
| `sh` | Store halfword |
| `sb` | Store byte |

#### Arithmetic
| Instruction | Description |
|-------------|-------------|
| `add` | Add |
| `addi` | Add immediate |
| `sub` | Subtract |
| `mul` | Multiply |
| `div` | Divide |
| `rem` | Remainder |

#### Logical
| Instruction | Description |
|-------------|-------------|
| `and` | Bitwise AND |
| `andi` | Bitwise AND immediate |
| `or` | Bitwise OR |
| `ori` | Bitwise OR immediate |
| `xor` | Bitwise XOR |
| `xori` | Bitwise XOR immediate |
| `sll` | Shift left logical |
| `srl` | Shift right logical |
| `sra` | Shift right arithmetic |

#### Comparison
| Instruction | Description |
|-------------|-------------|
| `slt` | Set less than |
| `slti` | Set less than immediate |
| `sltu` | Set less than unsigned |
| `sltiu` | Set less than immediate unsigned |

#### Control Flow
| Instruction | Description |
|-------------|-------------|
| `jal` | Jump and link |
| `jalr` | Jump and link register |
| `beq` | Branch if equal |
| `bne` | Branch if not equal |
| `blt` | Branch if less than |
| `bge` | Branch if greater or equal |
| `bltu` | Branch if less than unsigned |
| `bgeu` | Branch if greater or equal unsigned |
| `ecall` | Environment call |
| `ebreak` | Environment break |

### RVC (Compressed) Extension

16-bit compressed instructions are automatically expanded to their 32-bit equivalents:

| Compressed | Expands To |
|------------|------------|
| `c.addi` | `addi` |
| `c.li` | `addi x, x0, imm` |
| `c.mv` | `add` |
| `c.j` | `jal x0, offset` |
| `c.jr` | `jalr x0, rs, 0` |
| `c.jalr` | `jalr ra, rs, 0` |
| `c.beqz` | `beq rs, x0, offset` |
| `c.bnez` | `bne rs, x0, offset` |
| `c.lw` | `lw` |
| `c.sw` | `sw` |
| `c.ret` | `jalr x0, ra, 0` |
