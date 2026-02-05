// Test various loop patterns for decompiler validation
// Compile: gcc -O2 -o test_loops test_loops.c

#include <stddef.h>

// Simple for loop - should produce clean for() output
int sum_array(int *arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

// Nested loops - should produce clean nested for() output
void matrix_multiply(int *a, int *b, int *c, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int sum = 0;
            for (int k = 0; k < n; k++) {
                sum += a[i * n + k] * b[k * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

// While loop with break - should produce while() with break
int find_first(int *arr, int n, int target) {
    int i = 0;
    while (i < n) {
        if (arr[i] == target) {
            break;
        }
        i++;
    }
    return i;
}

// Do-while loop - should produce do...while() output
int count_digits(int n) {
    int count = 0;
    do {
        count++;
        n /= 10;
    } while (n != 0);
    return count;
}

// Loop with continue - should produce for() with continue
int sum_positive(int *arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if (arr[i] < 0) {
            continue;
        }
        sum += arr[i];
    }
    return sum;
}

// Loop unrolling candidate - decompiler should recognize pattern
void memcpy_unrolled(char *dst, const char *src, size_t n) {
    size_t i = 0;
    while (n >= 4) {
        dst[i] = src[i];
        dst[i + 1] = src[i + 1];
        dst[i + 2] = src[i + 2];
        dst[i + 3] = src[i + 3];
        i += 4;
        n -= 4;
    }
    while (n > 0) {
        dst[i] = src[i];
        i++;
        n--;
    }
}

// Backward loop - should produce for() with decrement
void reverse_array(int *arr, int n) {
    for (int i = n - 1; i >= 0; i--) {
        arr[i] = arr[n - 1 - i];
    }
}

int main(void) {
    int arr[] = {1, 2, 3, 4, 5, -1, 6, 7};
    int result = 0;
    result += sum_array(arr, 8);
    result += find_first(arr, 8, 4);
    result += count_digits(12345);
    result += sum_positive(arr, 8);
    return result;
}
