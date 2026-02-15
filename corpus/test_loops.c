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
