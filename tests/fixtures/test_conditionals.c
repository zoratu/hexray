// Test various conditional patterns for decompiler validation
// Compile: gcc -O2 -o test_conditionals test_conditionals.c

#include <stddef.h>

// Simple if-else
int abs_value(int x) {
    if (x < 0) {
        return -x;
    } else {
        return x;
    }
}

// Chained if-else (should not become switch)
int grade(int score) {
    if (score >= 90) {
        return 'A';
    } else if (score >= 80) {
        return 'B';
    } else if (score >= 70) {
        return 'C';
    } else if (score >= 60) {
        return 'D';
    } else {
        return 'F';
    }
}

// Switch statement - should produce switch/case
int day_of_week(int day) {
    switch (day) {
        case 0: return 'S';
        case 1: return 'M';
        case 2: return 'T';
        case 3: return 'W';
        case 4: return 'T';
        case 5: return 'F';
        case 6: return 'S';
        default: return '?';
    }
}

// Ternary expression - should produce ternary or clean if
int max(int a, int b) {
    return (a > b) ? a : b;
}

// Short-circuit AND - should produce && expression
int safe_divide(int *ptr, int divisor) {
    if (ptr != NULL && divisor != 0) {
        return *ptr / divisor;
    }
    return 0;
}

// Short-circuit OR - should produce || expression
int either_positive(int a, int b) {
    if (a > 0 || b > 0) {
        return 1;
    }
    return 0;
}

// Nested conditionals
int classify(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            return 1;  // quadrant 1
        } else {
            return 4;  // quadrant 4
        }
    } else {
        if (y > 0) {
            return 2;  // quadrant 2
        } else {
            return 3;  // quadrant 3
        }
    }
}

// Boolean expression simplification
int all_positive(int a, int b, int c) {
    return (a > 0) && (b > 0) && (c > 0);
}

// Complex condition
int in_range(int x, int low, int high) {
    return (x >= low) && (x <= high);
}

int main(void) {
    int result = 0;
    result += abs_value(-5);
    result += grade(85);
    result += day_of_week(3);
    result += max(10, 20);
    int val = 42;
    result += safe_divide(&val, 2);
    result += either_positive(-1, 5);
    result += classify(1, -1);
    result += all_positive(1, 2, 3);
    result += in_range(5, 1, 10);
    return result;
}
