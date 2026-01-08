#!/usr/bin/env python3
"""Create a minimal ELF64 executable for testing."""
import struct

# ELF64 header (64 bytes)
ELF_MAGIC = b'\x7fELF'
EI_CLASS_64 = 2
EI_DATA_LE = 1
EI_VERSION = 1
EI_OSABI_SYSV = 0

ET_EXEC = 2
EM_X86_64 = 62
EV_CURRENT = 1

# Program header
PT_LOAD = 1
PF_R = 4
PF_X = 1

# Simple x86_64 code: 
#   push rbp
#   mov rbp, rsp
#   mov eax, 42
#   pop rbp
#   ret
code = bytes([
    0x55,               # push rbp
    0x48, 0x89, 0xe5,   # mov rbp, rsp
    0xb8, 0x2a, 0x00, 0x00, 0x00,  # mov eax, 42
    0x5d,               # pop rbp
    0xc3,               # ret
])

# Sizes
ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
CODE_OFFSET = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE
ENTRY_POINT = 0x401000

# Build ELF header
elf_header = bytearray(64)
# e_ident
elf_header[0:4] = ELF_MAGIC
elf_header[4] = EI_CLASS_64
elf_header[5] = EI_DATA_LE
elf_header[6] = EI_VERSION
elf_header[7] = EI_OSABI_SYSV
# e_type
struct.pack_into('<H', elf_header, 16, ET_EXEC)
# e_machine
struct.pack_into('<H', elf_header, 18, EM_X86_64)
# e_version
struct.pack_into('<I', elf_header, 20, EV_CURRENT)
# e_entry
struct.pack_into('<Q', elf_header, 24, ENTRY_POINT)
# e_phoff
struct.pack_into('<Q', elf_header, 32, ELF_HEADER_SIZE)
# e_shoff (no sections)
struct.pack_into('<Q', elf_header, 40, 0)
# e_flags
struct.pack_into('<I', elf_header, 48, 0)
# e_ehsize
struct.pack_into('<H', elf_header, 52, ELF_HEADER_SIZE)
# e_phentsize
struct.pack_into('<H', elf_header, 54, PROGRAM_HEADER_SIZE)
# e_phnum
struct.pack_into('<H', elf_header, 56, 1)
# e_shentsize
struct.pack_into('<H', elf_header, 58, 0)
# e_shnum
struct.pack_into('<H', elf_header, 60, 0)
# e_shstrndx
struct.pack_into('<H', elf_header, 62, 0)

# Build program header
program_header = bytearray(56)
# p_type
struct.pack_into('<I', program_header, 0, PT_LOAD)
# p_flags
struct.pack_into('<I', program_header, 4, PF_R | PF_X)
# p_offset
struct.pack_into('<Q', program_header, 8, CODE_OFFSET)
# p_vaddr
struct.pack_into('<Q', program_header, 16, ENTRY_POINT)
# p_paddr
struct.pack_into('<Q', program_header, 24, ENTRY_POINT)
# p_filesz
struct.pack_into('<Q', program_header, 32, len(code))
# p_memsz
struct.pack_into('<Q', program_header, 40, len(code))
# p_align
struct.pack_into('<Q', program_header, 48, 0x1000)

# Write the file
with open('tests/fixtures/elf/simple_x86_64', 'wb') as f:
    f.write(elf_header)
    f.write(program_header)
    f.write(code)

print("Created tests/fixtures/elf/simple_x86_64")
print(f"Entry point: {hex(ENTRY_POINT)}")
print(f"Code size: {len(code)} bytes")
