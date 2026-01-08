#!/usr/bin/env python3
"""Create a more complex PE64 executable for testing decompilation and type inference."""
import struct

# Constants
DOS_MAGIC = 0x5A4D
PE_SIGNATURE = 0x00004550
PE32PLUS_MAGIC = 0x020b

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000

IMAGE_SUBSYSTEM_CONSOLE = 3

# More complex x86_64 code demonstrating various patterns:
#
# main:
#   push rbp
#   mov rbp, rsp
#   sub rsp, 0x20           ; allocate stack space
#   mov dword ptr [rbp-4], 10   ; int x = 10
#   mov dword ptr [rbp-8], 20   ; int y = 20
#   mov eax, [rbp-4]        ; load x
#   add eax, [rbp-8]        ; x + y
#   mov [rbp-0xc], eax      ; int z = x + y
#   cmp eax, 30             ; if (z == 30)
#   jne else_branch
#   mov eax, 1              ; return 1
#   jmp done
# else_branch:
#   mov eax, 0              ; return 0
# done:
#   add rsp, 0x20
#   pop rbp
#   ret
#
# helper:
#   push rbp
#   mov rbp, rsp
#   mov eax, edi            ; return first arg
#   imul eax, esi           ; * second arg
#   pop rbp
#   ret

code = bytes([
    # main: (at offset 0)
    0x55,                           # 0x00: push rbp
    0x48, 0x89, 0xE5,               # 0x01: mov rbp, rsp
    0x48, 0x83, 0xEC, 0x20,         # 0x04: sub rsp, 0x20

    0xC7, 0x45, 0xFC, 0x0A, 0x00, 0x00, 0x00,  # 0x08: mov dword ptr [rbp-4], 10
    0xC7, 0x45, 0xF8, 0x14, 0x00, 0x00, 0x00,  # 0x0F: mov dword ptr [rbp-8], 20

    0x8B, 0x45, 0xFC,               # 0x16: mov eax, [rbp-4]
    0x03, 0x45, 0xF8,               # 0x19: add eax, [rbp-8]
    0x89, 0x45, 0xF4,               # 0x1C: mov [rbp-0xc], eax

    0x83, 0xF8, 0x1E,               # 0x1F: cmp eax, 30
    0x75, 0x07,                     # 0x22: jne else_branch (skip 7 bytes)

    0xB8, 0x01, 0x00, 0x00, 0x00,   # 0x24: mov eax, 1
    0xEB, 0x05,                     # 0x29: jmp done

    # else_branch: (at offset 0x2B)
    0xB8, 0x00, 0x00, 0x00, 0x00,   # 0x2B: mov eax, 0

    # done: (at offset 0x30)
    0x48, 0x83, 0xC4, 0x20,         # 0x30: add rsp, 0x20
    0x5D,                           # 0x34: pop rbp
    0xC3,                           # 0x35: ret

    # Padding between functions
    0x90, 0x90,                     # 0x36-0x37: nop nop (alignment)

    # helper: (at offset 0x38)
    0x55,                           # 0x38: push rbp
    0x48, 0x89, 0xE5,               # 0x39: mov rbp, rsp
    0x89, 0xF8,                     # 0x3C: mov eax, edi
    0x0F, 0xAF, 0xC6,               # 0x3E: imul eax, esi
    0x5D,                           # 0x41: pop rbp
    0xC3,                           # 0x42: ret
])

# Pad to 512 bytes
code_padded = code + b'\x00' * (512 - len(code))

# Build DOS header (64 bytes)
dos_header = bytearray(64)
struct.pack_into('<H', dos_header, 0, DOS_MAGIC)  # e_magic = "MZ"
struct.pack_into('<I', dos_header, 60, 64)  # e_lfanew = offset to PE header

# PE signature (4 bytes)
pe_sig = struct.pack('<I', PE_SIGNATURE)

# COFF header (20 bytes)
coff_header = bytearray(20)
struct.pack_into('<H', coff_header, 0, IMAGE_FILE_MACHINE_AMD64)  # Machine
struct.pack_into('<H', coff_header, 2, 1)  # NumberOfSections
struct.pack_into('<I', coff_header, 4, 0)  # TimeDateStamp
struct.pack_into('<I', coff_header, 8, 0)  # PointerToSymbolTable
struct.pack_into('<I', coff_header, 12, 0)  # NumberOfSymbols
struct.pack_into('<H', coff_header, 16, 112 + 16 * 8)  # SizeOfOptionalHeader (PE32+ with 16 data dirs)
struct.pack_into('<H', coff_header, 18, IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

# Optional header PE32+ (112 bytes standard + data directories)
opt_header = bytearray(112 + 16 * 8)  # 16 data directories
struct.pack_into('<H', opt_header, 0, PE32PLUS_MAGIC)  # Magic
opt_header[2] = 14  # MajorLinkerVersion
opt_header[3] = 0   # MinorLinkerVersion
struct.pack_into('<I', opt_header, 4, len(code_padded))  # SizeOfCode
struct.pack_into('<I', opt_header, 8, 0)  # SizeOfInitializedData
struct.pack_into('<I', opt_header, 12, 0)  # SizeOfUninitializedData
struct.pack_into('<I', opt_header, 16, 0x1000)  # AddressOfEntryPoint (RVA) - main
struct.pack_into('<I', opt_header, 20, 0x1000)  # BaseOfCode
struct.pack_into('<Q', opt_header, 24, 0x140000000)  # ImageBase
struct.pack_into('<I', opt_header, 32, 0x1000)  # SectionAlignment
struct.pack_into('<I', opt_header, 36, 0x200)  # FileAlignment
struct.pack_into('<H', opt_header, 40, 6)  # MajorOperatingSystemVersion
struct.pack_into('<H', opt_header, 42, 0)  # MinorOperatingSystemVersion
struct.pack_into('<H', opt_header, 44, 0)  # MajorImageVersion
struct.pack_into('<H', opt_header, 46, 0)  # MinorImageVersion
struct.pack_into('<H', opt_header, 48, 6)  # MajorSubsystemVersion
struct.pack_into('<H', opt_header, 50, 0)  # MinorSubsystemVersion
struct.pack_into('<I', opt_header, 52, 0)  # Win32VersionValue
struct.pack_into('<I', opt_header, 56, 0x3000)  # SizeOfImage
struct.pack_into('<I', opt_header, 60, 0x200)  # SizeOfHeaders
struct.pack_into('<I', opt_header, 64, 0)  # CheckSum
struct.pack_into('<H', opt_header, 68, IMAGE_SUBSYSTEM_CONSOLE)  # Subsystem
struct.pack_into('<H', opt_header, 70, 0)  # DllCharacteristics
struct.pack_into('<Q', opt_header, 72, 0x100000)  # SizeOfStackReserve
struct.pack_into('<Q', opt_header, 80, 0x1000)  # SizeOfStackCommit
struct.pack_into('<Q', opt_header, 88, 0x100000)  # SizeOfHeapReserve
struct.pack_into('<Q', opt_header, 96, 0x1000)  # SizeOfHeapCommit
struct.pack_into('<I', opt_header, 104, 0)  # LoaderFlags
struct.pack_into('<I', opt_header, 108, 16)  # NumberOfRvaAndSizes
# Data directories are all zero (no imports, exports, etc.)

# Section header for .text (40 bytes)
text_section = bytearray(40)
text_section[0:6] = b'.text\x00'  # Name
struct.pack_into('<I', text_section, 8, len(code_padded))  # VirtualSize
struct.pack_into('<I', text_section, 12, 0x1000)  # VirtualAddress
struct.pack_into('<I', text_section, 16, len(code_padded))  # SizeOfRawData
struct.pack_into('<I', text_section, 20, 0x200)  # PointerToRawData
struct.pack_into('<I', text_section, 24, 0)  # PointerToRelocations
struct.pack_into('<I', text_section, 28, 0)  # PointerToLinenumbers
struct.pack_into('<H', text_section, 32, 0)  # NumberOfRelocations
struct.pack_into('<H', text_section, 34, 0)  # NumberOfLinenumbers
struct.pack_into('<I', text_section, 36, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

# Calculate sizes
headers_size = len(dos_header) + len(pe_sig) + len(coff_header) + len(opt_header) + len(text_section)
# Pad to FileAlignment (0x200)
headers_padded_size = ((headers_size + 0x1FF) // 0x200) * 0x200
padding_size = headers_padded_size - headers_size

# Build final PE
import os
os.makedirs('tests/fixtures/pe', exist_ok=True)

with open('tests/fixtures/pe/complex_x64.exe', 'wb') as f:
    f.write(dos_header)
    f.write(pe_sig)
    f.write(coff_header)
    f.write(opt_header)
    f.write(text_section)
    f.write(b'\x00' * padding_size)  # Padding to FileAlignment
    f.write(code_padded)

print("Created tests/fixtures/pe/complex_x64.exe")
print(f"Entry point (main): 0x140001000")
print(f"Helper function:    0x140001038")
print(f"Image base: 0x140000000")
print(f"Code size: {len(code)} bytes")
print()
print("Functions:")
print("  main:   0x140001000 - stack frame, local vars, conditionals")
print("  helper: 0x140001038 - simple multiply function")
