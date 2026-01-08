#!/usr/bin/env python3
"""Create an ELF64 executable with symbol table for testing."""
import struct

# ELF constants
ELF_MAGIC = b'\x7fELF'
EI_CLASS_64 = 2
EI_DATA_LE = 1
EI_VERSION = 1
EI_OSABI_SYSV = 0

ET_EXEC = 2
EM_X86_64 = 62
EV_CURRENT = 1

PT_LOAD = 1
PF_R = 4
PF_W = 2
PF_X = 1

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3

SHF_ALLOC = 2
SHF_EXECINSTR = 4

STB_GLOBAL = 1
STT_FUNC = 2
STT_NOTYPE = 0

# Code for multiple functions
# _start:
#   call main
#   mov rdi, rax
#   mov rax, 60      ; exit syscall
#   syscall
# Call offset: main is at byte 15, call ends at byte 5, so offset = 15 - 5 = 10 = 0x0a
_start_code = bytes([
    0xe8, 0x0a, 0x00, 0x00, 0x00,  # call main (offset = 10)
    0x48, 0x89, 0xc7,              # mov rdi, rax
    0xb8, 0x3c, 0x00, 0x00, 0x00,  # mov rax, 60
    0x0f, 0x05,                    # syscall
])

# main:
#   push rbp
#   mov rbp, rsp
#   call helper
#   add eax, 10
#   pop rbp
#   ret
# Call offset: helper is at byte 29, call ends at byte 24 (15+9), so offset = 29 - 24 = 5
main_code = bytes([
    0x55,                          # push rbp
    0x48, 0x89, 0xe5,              # mov rbp, rsp
    0xe8, 0x05, 0x00, 0x00, 0x00,  # call helper (offset = 5)
    0x83, 0xc0, 0x0a,              # add eax, 10
    0x5d,                          # pop rbp
    0xc3,                          # ret
])

# helper:
#   push rbp
#   mov rbp, rsp
#   mov eax, 42
#   pop rbp
#   ret
helper_code = bytes([
    0x55,                          # push rbp
    0x48, 0x89, 0xe5,              # mov rbp, rsp
    0xb8, 0x2a, 0x00, 0x00, 0x00,  # mov eax, 42
    0x5d,                          # pop rbp
    0xc3,                          # ret
])

code = _start_code + main_code + helper_code

# String table: \0 + ".text\0" + ".symtab\0" + ".strtab\0" + ".shstrtab\0" + "_start\0" + "main\0" + "helper\0"
shstrtab = b'\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00'
strtab = b'\x00_start\x00main\x00helper\x00'

# Symbol offsets in strtab
SYM_START_NAME = 1   # "_start"
SYM_MAIN_NAME = 8    # "main"
SYM_HELPER_NAME = 13 # "helper"

# Section name offsets in shstrtab
SHNAME_TEXT = 1
SHNAME_SYMTAB = 7
SHNAME_STRTAB = 15
SHNAME_SHSTRTAB = 23

# Layout
ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
SECTION_HEADER_SIZE = 64
SYMBOL_SIZE = 24

BASE_ADDR = 0x401000
CODE_VADDR = BASE_ADDR

# Calculate offsets
code_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE
code_size = len(code)

# Align to 8 bytes
def align8(n):
    return (n + 7) & ~7

strtab_offset = align8(code_offset + code_size)
strtab_size = len(strtab)

symtab_offset = align8(strtab_offset + strtab_size)
num_symbols = 4  # null + _start + main + helper
symtab_size = num_symbols * SYMBOL_SIZE

shstrtab_offset = align8(symtab_offset + symtab_size)
shstrtab_size = len(shstrtab)

section_headers_offset = align8(shstrtab_offset + shstrtab_size)
num_sections = 5  # null + .text + .symtab + .strtab + .shstrtab

# Function addresses
_start_addr = CODE_VADDR
main_addr = CODE_VADDR + len(_start_code)
helper_addr = CODE_VADDR + len(_start_code) + len(main_code)

# Build ELF header
elf_header = bytearray(64)
elf_header[0:4] = ELF_MAGIC
elf_header[4] = EI_CLASS_64
elf_header[5] = EI_DATA_LE
elf_header[6] = EI_VERSION
elf_header[7] = EI_OSABI_SYSV
struct.pack_into('<H', elf_header, 16, ET_EXEC)
struct.pack_into('<H', elf_header, 18, EM_X86_64)
struct.pack_into('<I', elf_header, 20, EV_CURRENT)
struct.pack_into('<Q', elf_header, 24, _start_addr)  # e_entry
struct.pack_into('<Q', elf_header, 32, ELF_HEADER_SIZE)  # e_phoff
struct.pack_into('<Q', elf_header, 40, section_headers_offset)  # e_shoff
struct.pack_into('<I', elf_header, 48, 0)  # e_flags
struct.pack_into('<H', elf_header, 52, ELF_HEADER_SIZE)  # e_ehsize
struct.pack_into('<H', elf_header, 54, PROGRAM_HEADER_SIZE)  # e_phentsize
struct.pack_into('<H', elf_header, 56, 1)  # e_phnum
struct.pack_into('<H', elf_header, 58, SECTION_HEADER_SIZE)  # e_shentsize
struct.pack_into('<H', elf_header, 60, num_sections)  # e_shnum
struct.pack_into('<H', elf_header, 62, 4)  # e_shstrndx (index of .shstrtab)

# Build program header
program_header = bytearray(56)
struct.pack_into('<I', program_header, 0, PT_LOAD)
struct.pack_into('<I', program_header, 4, PF_R | PF_X)
struct.pack_into('<Q', program_header, 8, code_offset)
struct.pack_into('<Q', program_header, 16, CODE_VADDR)
struct.pack_into('<Q', program_header, 24, CODE_VADDR)
struct.pack_into('<Q', program_header, 32, code_size)
struct.pack_into('<Q', program_header, 40, code_size)
struct.pack_into('<Q', program_header, 48, 0x1000)

# Build symbol table entries
def make_symbol(name_idx, value, size, bind, typ, section_idx):
    sym = bytearray(SYMBOL_SIZE)
    struct.pack_into('<I', sym, 0, name_idx)  # st_name
    sym[4] = (bind << 4) | typ  # st_info
    sym[5] = 0  # st_other
    struct.pack_into('<H', sym, 6, section_idx)  # st_shndx
    struct.pack_into('<Q', sym, 8, value)  # st_value
    struct.pack_into('<Q', sym, 16, size)  # st_size
    return bytes(sym)

symtab = bytearray()
symtab += make_symbol(0, 0, 0, 0, STT_NOTYPE, 0)  # null symbol
symtab += make_symbol(SYM_START_NAME, _start_addr, len(_start_code), STB_GLOBAL, STT_FUNC, 1)
symtab += make_symbol(SYM_MAIN_NAME, main_addr, len(main_code), STB_GLOBAL, STT_FUNC, 1)
symtab += make_symbol(SYM_HELPER_NAME, helper_addr, len(helper_code), STB_GLOBAL, STT_FUNC, 1)

# Build section headers
def make_section_header(name, typ, flags, addr, offset, size, link=0, info=0, addralign=1, entsize=0):
    sh = bytearray(SECTION_HEADER_SIZE)
    struct.pack_into('<I', sh, 0, name)  # sh_name
    struct.pack_into('<I', sh, 4, typ)  # sh_type
    struct.pack_into('<Q', sh, 8, flags)  # sh_flags
    struct.pack_into('<Q', sh, 16, addr)  # sh_addr
    struct.pack_into('<Q', sh, 24, offset)  # sh_offset
    struct.pack_into('<Q', sh, 32, size)  # sh_size
    struct.pack_into('<I', sh, 40, link)  # sh_link
    struct.pack_into('<I', sh, 44, info)  # sh_info
    struct.pack_into('<Q', sh, 48, addralign)  # sh_addralign
    struct.pack_into('<Q', sh, 56, entsize)  # sh_entsize
    return bytes(sh)

section_headers = bytearray()
# Null section
section_headers += make_section_header(0, SHT_NULL, 0, 0, 0, 0)
# .text section
section_headers += make_section_header(SHNAME_TEXT, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                                        CODE_VADDR, code_offset, code_size, addralign=16)
# .symtab section (link=3 for .strtab, info=1 for first global symbol)
section_headers += make_section_header(SHNAME_SYMTAB, SHT_SYMTAB, 0,
                                        0, symtab_offset, symtab_size,
                                        link=3, info=1, addralign=8, entsize=SYMBOL_SIZE)
# .strtab section
section_headers += make_section_header(SHNAME_STRTAB, SHT_STRTAB, 0,
                                        0, strtab_offset, strtab_size)
# .shstrtab section
section_headers += make_section_header(SHNAME_SHSTRTAB, SHT_STRTAB, 0,
                                        0, shstrtab_offset, shstrtab_size)

# Build the file
output = bytearray()
output += elf_header
output += program_header

# Pad to code offset
while len(output) < code_offset:
    output += b'\x00'
output += code

# Pad to strtab offset
while len(output) < strtab_offset:
    output += b'\x00'
output += strtab

# Pad to symtab offset
while len(output) < symtab_offset:
    output += b'\x00'
output += symtab

# Pad to shstrtab offset
while len(output) < shstrtab_offset:
    output += b'\x00'
output += shstrtab

# Pad to section headers offset
while len(output) < section_headers_offset:
    output += b'\x00'
output += section_headers

# Write the file
with open('tests/fixtures/elf/test_with_symbols', 'wb') as f:
    f.write(output)

print("Created tests/fixtures/elf/test_with_symbols")
print(f"Entry point: {hex(_start_addr)}")
print(f"Symbols:")
print(f"  _start:  {hex(_start_addr)} ({len(_start_code)} bytes)")
print(f"  main:    {hex(main_addr)} ({len(main_code)} bytes)")
print(f"  helper:  {hex(helper_addr)} ({len(helper_code)} bytes)")
