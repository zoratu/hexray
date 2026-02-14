// Callback-heavy fixture for CLI decompiler regression tests.
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>

typedef int (*cmp_fn_t)(const void*, const void*);
typedef void (*handler_fn_t)(int);

static int cmp_ints(const void* a, const void* b) {
    int lhs = *(const int*)a;
    int rhs = *(const int*)b;
    if (lhs < rhs) {
        return -1;
    }
    if (lhs > rhs) {
        return 1;
    }
    return 0;
}

int sort_with_cmp(int* arr, size_t n, cmp_fn_t cmp) {
    qsort(arr, n, sizeof(int), cmp);
    return arr[0];
}

int lookup_with_cmp(int* arr, size_t n, int key, cmp_fn_t cmp) {
    int* found = bsearch(&key, arr, n, sizeof(int), cmp);
    return found ? *found : -1;
}

int sort_with_static_cmp(int* arr, size_t n, void* ctx) {
    (void)ctx;
    qsort(arr, n, sizeof(int), cmp_ints);
    return arr[0];
}

handler_fn_t install_handler(handler_fn_t h) {
    return signal(SIGINT, h);
}

int run_callbacks(int* arr, size_t n, handler_fn_t h) {
    int first = sort_with_cmp(arr, n, cmp_ints);
    int looked = lookup_with_cmp(arr, n, 3, cmp_ints);
    return first + looked + (install_handler(h) != 0);
}

int main(void) {
    int data[4] = {4, 2, 3, 1};
    return run_callbacks(data, 4, 0);
}
