// Test program compiled with debug info
int factorial(int n) {
    int result = 1;
    for (int i = 1; i <= n; i++) {
        result = result * i;
    }
    return result;
}

int sum_array(int* arr, int size) {
    int total = 0;
    for (int idx = 0; idx < size; idx++) {
        total += arr[idx];
    }
    return total;
}

int main(void) {
    int numbers[5] = {1, 2, 3, 4, 5};
    int fact5 = factorial(5);
    int sum = sum_array(numbers, 5);
    return fact5 + sum;
}
