// Test arithmetic and bit manipulation patterns for decompiler validation
// Compile: gcc -O2 -o test_arithmetic test_arithmetic.c

#include <stdint.h>

// Division optimization - should recognize x/2 from shift
int half(int x) {
    return x / 2;
}

// Multiplication by constant - may be optimized to shifts/adds
int times_three(int x) {
    return x * 3;
}

// Modulo optimization - should recognize x%4 from mask
int mod_four(int x) {
    return x % 4;
}

// Bit manipulation - test bit
int is_even(int x) {
    return (x & 1) == 0;
}

// Set bit
int set_bit(int x, int pos) {
    return x | (1 << pos);
}

// Clear bit
int clear_bit(int x, int pos) {
    return x & ~(1 << pos);
}

// Toggle bit
int toggle_bit(int x, int pos) {
    return x ^ (1 << pos);
}

// Sign extension
int64_t sign_extend_32(int32_t x) {
    return (int64_t)x;
}

// Zero extension
uint64_t zero_extend_32(uint32_t x) {
    return (uint64_t)x;
}

// Absolute value (should recognize pattern)
int abs_int(int x) {
    return x < 0 ? -x : x;
}

// Min/max patterns
int min_int(int a, int b) {
    return a < b ? a : b;
}

int max_int(int a, int b) {
    return a > b ? a : b;
}

// Clamp pattern
int clamp(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

// Swap using XOR (classic pattern)
void swap_xor(int *a, int *b) {
    *a = *a ^ *b;
    *b = *a ^ *b;
    *a = *a ^ *b;
}

// Population count pattern
int popcount(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

// Count leading zeros pattern
int clz(uint32_t x) {
    if (x == 0) return 32;
    int n = 0;
    if ((x & 0xFFFF0000) == 0) { n += 16; x <<= 16; }
    if ((x & 0xFF000000) == 0) { n += 8; x <<= 8; }
    if ((x & 0xF0000000) == 0) { n += 4; x <<= 4; }
    if ((x & 0xC0000000) == 0) { n += 2; x <<= 2; }
    if ((x & 0x80000000) == 0) { n += 1; }
    return n;
}

// Power of 2 check
int is_power_of_two(uint32_t x) {
    return x && !(x & (x - 1));
}

// Round up to power of 2
uint32_t next_power_of_two(uint32_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x++;
    return x;
}

// Byte swap
uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0xFF) |
           ((x >> 8) & 0xFF00) |
           ((x << 8) & 0xFF0000) |
           ((x << 24) & 0xFF000000);
}

// Rotate left
uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Rotate right
uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

int main(void) {
    int result = 0;
    result += half(100);
    result += times_three(10);
    result += mod_four(17);
    result += is_even(4);
    result += set_bit(0, 3);
    result += clear_bit(0xFF, 3);
    result += toggle_bit(0, 5);
    result += abs_int(-42);
    result += min_int(5, 10);
    result += max_int(5, 10);
    result += clamp(50, 0, 100);
    result += popcount(0xFF);
    result += clz(0x1000);
    result += is_power_of_two(8);
    result += (int)next_power_of_two(5);
    result += (int)bswap32(0x12345678);
    result += (int)rotl32(1, 4);
    return result;
}
