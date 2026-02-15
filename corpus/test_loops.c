#include <stdio.h>

// Simple struct for testing
struct Rectangle {
    int width;
    int height;
};

// Test: struct field access
int rectangle_area(struct Rectangle r) {
    return r.width * r.height;
}

// Test: basic loop with array
int sum_array(int *arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

// Test: nested loops
int matrix_sum(int rows, int cols, int matrix[rows][cols]) {
    int sum = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            sum += matrix[i][j];
        }
    }
    return sum;
}

// Test: while loop
int count_digits(int n) {
    int count = 0;
    while (n != 0) {
        count++;
        n /= 10;
    }
    return count;
}

// Test: comparison returning bool
int is_even(int n) {
    return (n % 2) == 0;
}

// Test: if-else chain
char grade(int score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}

// Test: switch statement
const char* day_name(int day) {
    switch (day) {
        case 0: return "Sunday";
        case 1: return "Monday";
        case 2: return "Tuesday";
        case 3: return "Wednesday";
        case 4: return "Thursday";
        case 5: return "Friday";
        case 6: return "Saturday";
        default: return "Unknown";
    }
}

int main(void) {
    struct Rectangle r = {5, 10};
    printf("Area: %d\n", rectangle_area(r));
    
    int arr[] = {1, 2, 3, 4, 5};
    printf("Sum: %d\n", sum_array(arr, 5));
    
    printf("Digits in 12345: %d\n", count_digits(12345));
    printf("Is 4 even? %d\n", is_even(4));
    printf("Grade for 85: %c\n", grade(85));
    printf("Day 3: %s\n", day_name(3));
    
    return 0;
}

// Test: pointer arithmetic
int strlen_manual(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

// Test: bit manipulation
unsigned int count_bits(unsigned int n) {
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

// Test: recursion (factorial)
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// Test: two's complement / abs
int my_abs(int x) {
    return x < 0 ? -x : x;
}

// Test: min/max
int min(int a, int b) {
    return a < b ? a : b;
}

int max(int a, int b) {
    return a > b ? a : b;
}

// Test: clamp
int clamp(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

// Test: binary search
int binary_search(int *arr, int n, int target) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return mid;
        if (arr[mid] < target) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

// Test: bubble sort (nested loops)
void bubble_sort(int *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// Test: string comparison
int my_strcmp(const char *s1, const char *s2) {
    while (*s1 && *s1 == *s2) {
        s1++;
        s2++;
    }
    return *s1 - *s2;
}
