// Simple test program for decompiler

int factorial(int n) {
    int result = 1;
    for (int i = 1; i <= n; i++) {
        result = result * i;
    }
    return result;
}

int sum_while(int n) {
    int sum = 0;
    int i = 0;
    while (i < n) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}

int conditional(int x) {
    if (x > 10) {
        return x * 2;
    } else if (x > 5) {
        return x + 10;
    } else {
        return x;
    }
}

int main(void) {
    int a = factorial(5);
    int b = sum_while(10);
    int c = conditional(7);
    return a + b + c;
}
