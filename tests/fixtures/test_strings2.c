// Test program with multiple string patterns
#include <stdio.h>

void greet_user(const char *name) {
    printf("Hello, %s!\n", name);
}

void show_numbers(void) {
    printf("Numbers: 1, 2, 3\n");
    printf("More numbers: 4, 5, 6\n");
}

int check_condition(int x) {
    if (x > 10) {
        printf("Value is large: %d\n", x);
        return 1;
    } else {
        printf("Value is small: %d\n", x);
        return 0;
    }
}

int main(void) {
    greet_user("Alice");
    greet_user("Bob");
    show_numbers();
    return check_condition(15);
}
