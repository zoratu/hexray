# Decompiler Improvement Roadmap

Based on analysis of system binaries across macOS ARM64, Linux x86_64, and Linux ARM64.

## Critical Issues

### 1. Control Flow Structuring

**Problem**: Complex nested loops and conditional structures produce unreachable blocks and gotos after return statements.

**Examples**:
- `_bubble_sort` shows `bb2:`, `bb5:`, `bb6:` after the main return
- Nested loops flatten incorrectly with `goto bb3;` statements

**Root Cause**: The structurer doesn't properly handle all reducible control flow patterns.

**Suggested Fix**:
- Implement proper interval analysis for loop nesting
- Add post-dominator analysis for branch merging
- Handle "early exit" patterns in nested loops

---

### 2. x86_64 Function Signature Detection

**Problem**: x86_64 functions incorrectly show 6+ arguments when the function only uses 2.

**Example**:
```c
// Expected: int64_t _bubble_sort(void* ptr, int32_t n)
// Actual:   int64_t _bubble_sort(void* ptr, void* ptr2, int64_t arg2, int32_t arg3, int64_t arg4, int32_t arg5)
```

**Root Cause**: The ABI analyzer assumes all registers (rdi, rsi, rdx, rcx, r8, r9) are arguments if they're accessed.

**Suggested Fix**:
- Track actual usage patterns before first write
- Use def-use analysis to determine true arguments
- Check if register is used before being defined

---

### 3. Global Data Naming

**Problem**: Global variables shown as `data_XXXXXX` with raw addresses.

**Example**:
```c
if (*(uint32_t*)(&data_1d4e78) != *(uint64_t*)(16))
```

**Root Cause**: No symbol resolution for data sections.

**Suggested Fix**:
- Parse data sections and create symbolic names
- Use relocation info to find referenced globals
- Apply type information from debug info when available

---

### 4. RIP-Relative Addressing (x86_64)

**Problem**: Shows raw offsets like `rip + 0x1aea8f` instead of symbolic names.

**Root Cause**: RIP-relative addressing not being resolved to data symbols.

**Suggested Fix**:
- Calculate actual target address from current IP
- Look up symbol at target address
- Use section name + offset if no symbol

---

### 5. Condition Code Handling

**Problem**: Raw flag references like `ZF`, `SF^OF|ZF` instead of proper conditions.

**Example**:
```c
if (SF^OF|ZF > 0) {
```

**Root Cause**: Flag-based conditions not being merged with preceding comparisons.

**Suggested Fix**:
- Track flag-setting instructions (CMP, TEST, SUB)
- Merge condition checks with original comparison
- Convert to readable expressions like `x < y`

---

### 6. Code Duplication in Output

**Problem**: Massive code duplication where the same pattern repeats 20+ times.

**Example**: In glibc `abort()`, the same 10-line block repeats ~20 times.

**Root Cause**: Loop unrolling or computed goto not being recognized.

**Suggested Fix**:
- Detect repeated code patterns
- Consider re-rolling unrolled loops
- Handle switch/computed-goto patterns

---

### 7. Expression Formatting

**Problem**: Invalid C expressions in output.

**Example**:
```c
arg0 + idx * 4[1]  // Invalid - should be arg0[idx + 1] or similar
```

**Root Cause**: Operator precedence not respected in emitter.

**Suggested Fix**:
- Add proper parenthesization
- Validate expressions during emission
- Convert pointer arithmetic to array syntax

---

### 8. Undefined Variables

**Problem**: Variables like `iter`, `idx` appear without definition.

**Root Cause**: Phi node variables or loop induction variables not being initialized in output.

**Suggested Fix**:
- Ensure all variables have declarations
- Handle phi nodes properly in loop headers
- Track and emit induction variable initialization

---

## Medium Priority Issues

### 9. 16-bit Register Fragments (x86_64)

**Problem**: Shows `ax`, `bx`, `dx` as separate variables.

**Suggested Fix**: Merge 8/16/32-bit accesses to the same register into a single 64-bit variable.

### 10. swap() Function Misidentification

**Problem**: XCHG or CMPXCHG instructions decoded as `swap()` calls.

**Suggested Fix**: Proper atomic instruction handling.

### 11. Field Access Naming

**Problem**: Generic `field_4`, `field_8` instead of meaningful names.

**Suggested Fix**: Use DWARF debug info or struct type recovery.

### 12. Stack Canary Detection

**Problem**: Stack canary checks shown as raw code.

**Suggested Fix**: Recognize `__stack_chk_guard` pattern and hide it.

---

## Architecture-Specific Issues

### ARM64
- Pre/post-indexed writeback expressions sometimes missing
- CSEL/CSET patterns not always simplified
- ADRP+ADD patterns need better resolution for string literals

### x86_64
- Complex addressing modes need better display (e.g., `[rax + rbx*4 + 8]`)
- SSE/AVX operations shown as raw instructions
- REP prefixes not handled for string operations

---

## Testing Infrastructure Needs

### Kernel Module Support (TESTED)
Kernel modules (.ko files) are ELF relocatable objects with unresolved relocations:

**Issues Found**:
- Multiple function bodies merged into single decompilation (bb33, bb57, bb80 in one function)
- Section references shown as `&.data` instead of symbolic names
- Magic poison values shown as raw numbers: `-2401263026318606080` (0xdead...)
- Relocations not applied, causing incorrect jump targets

**Suggested Fixes**:
- Parse relocation sections and apply them during lifting
- Handle R_X86_64_PC32, R_X86_64_PLT32 etc.
- Recognize common poison patterns (POISON_POINTER_DELTA)

### Static Library Support
- Test `.a` archive files
- Handle multiple object files in archives

### Debug Info Integration
- Parse DWARF for variable names
- Extract struct/union definitions
- Map addresses to source locations

---

## Priority Order

1. **Control Flow Structuring** - Most visible issue
2. **Function Signature Detection** - Affects readability
3. **Global Data Naming** - Important for understanding
4. **RIP-Relative Resolution** - x86_64 specific but common
5. **Condition Code Handling** - Improves readability
6. **Expression Formatting** - Basic correctness
7. **Code Duplication** - Large functions become unreadable
8. **Undefined Variables** - Confusing output

---

## Test Binaries Used

| Binary | Architecture | Type | Notes |
|--------|-------------|------|-------|
| glibc_x64.so | x86_64 | Shared lib | glibc 2.36, stripped |
| ld-linux-x64.so | x86_64 | Shared lib | Dynamic linker |
| busybox_arm64 | ARM64 | Executable | Statically linked (musl) |
| busybox_x64 | x86_64 | Executable | Statically linked (musl) |
| debian_ls_x64 | x86_64 | Executable | glibc, PIE, stripped |
| test_extended | ARM64 | Executable | Our test corpus |
| test_extended_x64 | x86_64 | Executable | Our test corpus |
| miniforth_arm64 | ARM64 | Executable | Threaded code |
| miniforth_x64 | x86_64 | Executable | Threaded code |
| irqbypass.ko_x64 | x86_64 | Kernel module | Relocatable object |
| governor_simpleondemand.ko_x64 | x86_64 | Kernel module | Relocatable object |

---

## Additional Issues Found

### 13. Stack Pointer Manipulation in Output

**Problem**: Shows `rsp -= 8;` and `rsp += 8;` in decompiled code.

**Root Cause**: Stack frame setup not being abstracted away.

**Suggested Fix**: Hide stack pointer manipulation unless it's meaningful (e.g., alloca).

### 14. Loop Body Misattribution

**Problem**: Inner loop content shown outside the loop structure.

**Example**: In `_bubble_sort`, the swap logic appears in unreachable `bb9:` block.

**Suggested Fix**: Better recognition of loop-invariant code motion and inner loop bodies.

### 15. Duplicate Return Paths

**Problem**: Multiple `return` statements with same value scattered throughout.

**Suggested Fix**: Merge equivalent return paths in structurer.

---

## Quick Wins (Low Effort, High Impact)

1. **Hide stack pointer ops** - Simple pattern match
2. **Recognize poison patterns** - 0xDEAD..., 0xFEED...
3. **Better global naming** - Use section + offset if no symbol
4. **Parenthesize expressions** - Fix operator precedence in emitter
5. **Hide `__fentry__` calls** - Kernel profiling hooks

---

## Implementation Estimates

| Issue | Complexity | Files Affected |
|-------|-----------|----------------|
| Control flow restructuring | High | structurer.rs |
| Function signature detection | Medium | signature.rs, abi.rs |
| Global data naming | Medium | expression.rs, emitter.rs |
| RIP-relative resolution | Medium | expression.rs |
| Condition code handling | Medium | structurer.rs |
| Expression formatting | Low | emitter.rs |
| Stack pointer hiding | Low | structurer.rs |
| Kernel module relocations | High | hexray-formats |
