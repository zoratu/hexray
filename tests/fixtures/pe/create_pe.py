#!/usr/bin/env python3
"""Create a minimal PE64 executable for testing."""
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

# Simple x86_64 code that returns 42
# main:
#   xor eax, eax
#   mov al, 42
#   ret
code = bytes([
    0x31, 0xC0,              # xor eax, eax
    0xB0, 0x2A,              # mov al, 42
    0xC3,                    # ret
])

# Padding to align code
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
struct.pack_into('<I', opt_header, 16, 0x1000)  # AddressOfEntryPoint (RVA)
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

with open('tests/fixtures/pe/simple_x64.exe', 'wb') as f:
    f.write(dos_header)
    f.write(pe_sig)
    f.write(coff_header)
    f.write(opt_header)
    f.write(text_section)
    f.write(b'\x00' * padding_size)  # Padding to FileAlignment
    f.write(code_padded)

print("Created tests/fixtures/pe/simple_x64.exe")
print(f"Entry point: 0x140001000")
print(f"Image base: 0x140000000")
print(f"Code size: {len(code)} bytes")
