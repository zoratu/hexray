# Binary Exploration Guide

A practical guide to exploring compiled binaries using hexray. Whether you're debugging, competing in CTFs, analyzing malware, or simply curious about how software works, this guide will help you understand and navigate binary code.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Understanding Binary Structure](#understanding-binary-structure)
3. [Finding What You're Looking For](#finding-what-youre-looking-for)
4. [Practical Scenarios](#practical-scenarios)
5. [Advanced Techniques](#advanced-techniques)

---

## Getting Started

### Basic Workflow

Every binary exploration follows a similar pattern:

```
1. Identify the binary format (ELF, Mach-O, PE)
2. Find entry points (main, exported functions)
3. Locate interesting code (strings, symbols, patterns)
4. Understand control flow (CFG, call graph)
5. Decompile for deeper understanding
```

### First Look at a Binary

```bash
# Get basic information
hexray /path/to/binary info

# List sections (where code and data live)
hexray /path/to/binary sections

# List symbols (function and variable names)
hexray /path/to/binary symbols
```

**Example output:**
```
$ hexray /bin/ls info
Format: Mach-O 64-bit
Architecture: ARM64
Entry point: 0x100003a40
Sections: 8
Symbols: 142
```

### Disassembly vs Decompilation

- **Disassembly**: Shows raw assembly instructions - exact but hard to read
- **Decompilation**: Reconstructs C-like code - easier to understand but approximated

```bash
# Disassemble a function
hexray /bin/ls -s _main

# Decompile a function (much more readable)
hexray /bin/ls decompile _main
```

---

## Understanding Binary Structure

### Sections

Binaries are divided into sections with different purposes:

| Section | Purpose | Typical Contents |
|---------|---------|------------------|
| `.text` | Executable code | Functions, instructions |
| `.data` | Initialized data | Global variables |
| `.rodata` | Read-only data | String constants |
| `.bss` | Uninitialized data | Zero-initialized globals |

```bash
# Find the code section
hexray binary sections | grep -i text

# Disassemble from the start of .text
hexray binary -a 0x1000 -c 100
```

### Symbols

Symbols are names attached to addresses. They're invaluable for navigation:

```bash
# List all symbols
hexray binary symbols

# List only functions
hexray binary symbols --functions

# Find a specific symbol
hexray binary symbols | grep -i "error"
```

### Strings

Embedded strings often reveal program behavior:

```bash
# Extract strings
hexray binary strings

# Find strings with minimum length
hexray binary strings --min-length 10

# Search for specific patterns
hexray binary strings | grep -i "password\|license\|error"
```

---

## Finding What You're Looking For

### Strategy 1: Start from Strings

Strings are breadcrumbs that lead to interesting code:

```bash
# Find error messages
$ hexray app strings | grep -i "error"
0x100004a20: "License validation failed"
0x100004a50: "Invalid serial number"

# Find cross-references to that string
$ hexray app xrefs 0x100004a20
References TO 0x100004a20:
  0x100001234: lea rdi, [rip + 0x37ec]  ; CODE
```

Now you know address `0x100001234` references the error message. Decompile the containing function:

```bash
hexray app decompile 0x100001234
```

### Strategy 2: Start from Symbols

Function names tell you what code does:

```bash
# Find validation-related functions
$ hexray app symbols | grep -i "valid\|check\|verify"
0x100001000  FUNC  _validateLicense
0x100001200  FUNC  _checkSerial
0x100001400  FUNC  _verifySignature

# Decompile the interesting one
$ hexray app decompile _validateLicense
```

### Strategy 3: Follow the Call Graph

Understand how functions relate to each other:

```bash
# Build call graph for main
hexray app callgraph _main

# Export as DOT for visualization
hexray app callgraph _main --format dot > callgraph.dot
dot -Tpng callgraph.dot -o callgraph.png
```

### Strategy 4: Cross-References

Find where values are used:

```bash
# Build xref database
hexray app xrefs

# Find what calls a function
hexray app xrefs _validateLicense

# Find what references an address
hexray app xrefs 0x100004000
```

---

## Practical Scenarios

### Scenario 1: Debugging a Crash

**Goal**: Find why an application crashes with "Segmentation fault"

```bash
# 1. Find the crash address from debugger/crash log
#    Let's say it's 0x100001234

# 2. Disassemble around the crash
hexray app -a 0x100001220 -c 30

# 3. Decompile the function containing the crash
hexray app decompile 0x100001234

# 4. Look at the control flow
hexray app cfg 0x100001234
```

**What to look for:**
- Null pointer dereferences (`if (ptr != NULL)` checks missing)
- Array bounds violations
- Use-after-free patterns

### Scenario 2: CTF Reverse Engineering

**Goal**: Find the flag in a CTF challenge binary

```bash
# 1. Look for obvious strings
hexray challenge strings | grep -i "flag\|ctf\|secret"

# 2. Find comparison functions
hexray challenge symbols | grep -i "check\|compare\|verify"

# 3. Decompile the main logic
hexray challenge decompile _main --follow

# 4. Look for XOR patterns (common obfuscation)
hexray challenge -a 0x1000 -c 5000 | grep -i "xor"
```

**Common CTF patterns:**
- XOR with a key
- Character-by-character comparison
- Custom encoding schemes
- Anti-debugging checks

### Scenario 3: Malware Analysis

**Goal**: Understand what a suspicious binary does

> **Warning**: Always analyze malware in an isolated environment (VM with no network)

```bash
# 1. Get basic info without executing
hexray malware.exe info

# 2. Look for imports (what OS functions it uses)
hexray malware.exe symbols | grep -i "extern\|import"

# 3. Find suspicious strings
hexray malware.exe strings | grep -iE \
  "http://|https://|\.exe|cmd\.exe|powershell|registry"

# 4. Look for encryption/encoding
hexray malware.exe symbols | grep -iE \
  "crypt|encode|decode|base64|aes|xor"

# 5. Find the entry point behavior
hexray malware.exe decompile --follow
```

**Red flags to look for:**
- Network addresses and URLs
- File system operations
- Process injection APIs
- Registry modifications
- Encoded/encrypted strings

### Scenario 4: Understanding a Library

**Goal**: Learn how a library implements a feature

```bash
# 1. List exported functions
hexray library.so symbols --functions | head -20

# 2. Find the function you're interested in
hexray library.so symbols | grep -i "compress"

# 3. Decompile with type information
hexray library.so decompile _compress --types auto

# 4. Follow internal calls
hexray library.so decompile _compress --follow --depth 2
```

### Scenario 5: Firmware Analysis

**Goal**: Analyze embedded device firmware (routers, IoT, industrial controllers)

> **Note**: First extract the firmware filesystem using tools like `binwalk`, `jefferson`, or `ubi_reader`

```bash
# 1. Identify architecture and format
hexray firmware.bin info
# Common architectures: ARM, MIPS (big/little endian), RISC-V

# 2. If it's a raw binary, find the load address from vectors or strings
hexray firmware.bin strings | grep -i "version\|copyright\|build"

# 3. For extracted ELF binaries, get an overview
hexray httpd info
hexray httpd sections
hexray httpd symbols --functions | head -30

# 4. Find command handlers and CGI endpoints
hexray httpd symbols | grep -iE "cgi|handler|cmd|api|route"
hexray httpd strings | grep -iE "\.cgi|/api/|/cgi-bin/"

# 5. Look for authentication functions
hexray httpd symbols | grep -iE "auth|login|password|session|token"
hexray httpd decompile check_auth

# 6. Find hardcoded credentials (common in firmware)
hexray httpd strings | grep -iE "admin|root|password|secret|key"
hexray httpd strings | grep -E "^[a-zA-Z0-9]{8,32}$"  # potential passwords

# 7. Analyze network protocol handlers
hexray httpd symbols | grep -iE "recv|send|socket|packet|parse"
hexray httpd xrefs recv  # find what processes received data

# 8. Look for dangerous functions (potential vulnerabilities)
hexray httpd symbols | grep -iE "strcpy|sprintf|gets|system|popen|exec"
hexray httpd xrefs system  # find command injection points
```

**Common vulnerability patterns in firmware:**
```c
// Command injection - user input passed to system()
sprintf(cmd, "ping %s", user_input);
system(cmd);

// Buffer overflow - no bounds checking
char buf[64];
strcpy(buf, user_input);

// Hardcoded backdoor
if (strcmp(password, "superSecretAdmin") == 0)
    grant_access();
```

**Firmware-specific tips:**
- MIPS firmware often uses `jalr $t9` for function calls - follow `$t9` loads
- ARM firmware may have Thumb/ARM mode switches - watch for `bx` instructions
- Look for NVRAM access functions (`nvram_get`, `nvram_set`) for config data
- Web servers often use string tables for HTML - xref these to find handlers
- Check `/etc/passwd`, `/etc/shadow` equivalent strings for default accounts

---

## Advanced Techniques

### Using Control Flow Graphs

CFGs show how code branches and loops:

```bash
# Generate CFG
hexray app cfg _parseInput

# Export for visualization
hexray app cfg _parseInput --format dot > cfg.dot
```

**Reading a CFG:**
- Nodes = Basic blocks (sequential instructions)
- Edges = Control flow (jumps, branches)
- Back edges = Loops
- Multiple successors = Conditional branches

### Data Flow Analysis

Track where values come from and go:

```bash
# Trace a value backward (where did it come from?)
hexray app trace backward -a 0x1234 -r rdi _function

# Trace a value forward (where does it go?)
hexray app trace forward -a 0x1234 -r rax _function
```

### Type Recovery

Better types = more readable decompilation:

```bash
# Use builtin type libraries
hexray app decompile _main --types auto

# See available type libraries
hexray types builtin

# Load specific types
hexray app decompile _main --types posix,libc
```

### Signature Recognition

Identify standard library functions even without symbols:

```bash
# Scan for known function patterns
hexray stripped_binary signatures scan

# Lower confidence threshold for more matches
hexray stripped_binary signatures scan -c 0.3
```

### Working with Stripped Binaries

When symbols are removed:

```bash
# Find function boundaries by prologue patterns
hexray stripped -a 0x1000 -c 10000 | grep "push rbp"

# Use string references to name functions
hexray stripped xrefs 0x4050  # address of "Error: %s"

# Look for characteristic instruction sequences
hexray stripped -a 0x1000 -c 10000 | grep "syscall\|int 0x80"
```

---

## Tips and Tricks

### Efficient Exploration

1. **Start broad, then narrow**: Get the big picture before diving into details
2. **Follow strings**: They're the easiest way to find relevant code
3. **Use call graphs**: Understand relationships between functions
4. **Cross-reference everything**: If you find something interesting, see who uses it

### Reading Decompiled Code

1. **Don't expect perfection**: Decompilation is approximate
2. **Watch for patterns**:
   - `if (x == 0) goto fail` = early return pattern
   - Nested loops with counters = array processing
3. **Rename variables mentally**: `v1` might be `counter`, `a1` might be `buffer`

### Common Patterns

**Validation checks:**
```c
if (validate(input) == 0) {
    // success path
} else {
    error("Validation failed");
}
```

**String comparison:**
```c
for (i = 0; i < len; i++) {
    if (input[i] != expected[i])
        return 0;  // fail
}
return 1;  // success
```

**XOR encoding:**
```c
for (i = 0; i < len; i++) {
    output[i] = input[i] ^ key[i % key_len];
}
```

---

## Command Reference

| Task | Command |
|------|---------|
| Basic info | `hexray binary info` |
| List sections | `hexray binary sections` |
| List symbols | `hexray binary symbols` |
| Extract strings | `hexray binary strings` |
| Disassemble | `hexray binary -a ADDR -c COUNT` |
| Decompile | `hexray binary decompile SYMBOL` |
| Control flow | `hexray binary cfg SYMBOL` |
| Call graph | `hexray binary callgraph SYMBOL` |
| Cross-refs | `hexray binary xrefs [TARGET]` |
| Data flow | `hexray binary trace backward -a ADDR -r REG FUNC` |

---

## Further Reading

- [Intel x86-64 Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [ARM Architecture Reference](https://developer.arm.com/documentation/ddi0487/latest)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Reverse Engineering for Beginners](https://beginners.re/)
