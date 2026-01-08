// Test program with strings

#include <stdio.h>

const char *greeting = "Hello, World!";

void print_message(const char *msg) {
    printf("%s\n", msg);
}

int main(void) {
    print_message(greeting);
    print_message("This is a test string");
    return 0;
}
