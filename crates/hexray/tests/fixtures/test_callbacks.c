// Callback-heavy fixture for CLI decompiler regression tests.
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>

typedef int (*cmp_fn_t)(const void*, const void*);
typedef int (*cmp_ctx_fn_t)(const void*, const void*, void*);
typedef void (*handler_fn_t)(int);
typedef void* (*thread_start_t)(void*);
typedef void (*atfork_fn_t)(void);
typedef void (*on_exit_fn_t)(int, void*);

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

static int cmp_ints_with_ctx(const void* a, const void* b, void* ctx) {
    int delta = ctx ? *(const int*)ctx : 0;
    return cmp_ints(a, b) + delta;
}

int hexray_qsort_r(
    void* base,
    size_t n,
    size_t size,
    int (*compar)(const void*, const void*, void*),
    void* thunk
) {
    if (base && n > 1 && compar) {
        const char* bytes = (const char*)base;
        (void)compar(bytes, bytes + size, thunk);
    }
    return 0;
}

int hexray_bsd_qsort_r(
    void* base,
    size_t n,
    size_t size,
    void* thunk,
    int (*compar)(const void*, const void*, void*)
) {
    if (base && n > 1 && compar) {
        const char* bytes = (const char*)base;
        (void)compar(bytes, bytes + size, thunk);
    }
    return 0;
}

int sort_with_cmp(int* arr, size_t n, cmp_fn_t cmp) {
    qsort(arr, n, sizeof(int), cmp);
    return arr[0];
}

int sort_with_qsort_r_glibc(int* arr, size_t n, cmp_ctx_fn_t cmp, void* ctx) {
    int* base = arr;
    size_t count = n;
    cmp_ctx_fn_t cb = cmp;
    void* thunk = ctx;
    return hexray_qsort_r(base, count, sizeof(int), cb, thunk);
}

int sort_with_qsort_r_bsd(int* arr, size_t n, cmp_ctx_fn_t cmp, void* ctx) {
    int* base = arr;
    size_t count = n;
    cmp_ctx_fn_t cb = cmp;
    void* thunk = ctx;
    return hexray_bsd_qsort_r(base, count, sizeof(int), thunk, cb);
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

static void* thread_trampoline(void* arg) {
    return arg;
}

int spawn_with_start(thread_start_t start_routine, void* arg) {
    pthread_t tid;
    return pthread_create(&tid, 0, start_routine, arg);
}

int spawn_with_static_start(void* arg) {
    pthread_t tid;
    return pthread_create(&tid, 0, thread_trampoline, arg);
}

int sort_with_cmp_multihop(int* arr, size_t n, cmp_fn_t cmp) {
    cmp_fn_t level0 = cmp;
    cmp_fn_t level1 = level0;
    cmp_fn_t level2 = level1;
    qsort(arr, n, sizeof(int), level2);
    return arr[0];
}

int sort_mixed_forwarding(int* arr, size_t n, cmp_fn_t cmp, int use_dynamic) {
    cmp_fn_t selected = use_dynamic ? cmp : cmp_ints;
    qsort(arr, n, sizeof(int), selected);
    return arr[0];
}

int spawn_with_start_multihop(thread_start_t start_routine, void* arg) {
    thread_start_t level0 = start_routine;
    thread_start_t level1 = level0;
    pthread_t tid;
    return pthread_create(&tid, 0, level1, arg);
}

int spawn_mixed_forwarding(thread_start_t start_routine, void* arg, int use_dynamic) {
    thread_start_t selected = use_dynamic ? start_routine : thread_trampoline;
    pthread_t tid;
    return pthread_create(&tid, 0, selected, arg);
}

handler_fn_t install_handler(handler_fn_t h) {
    return signal(SIGINT, h);
}

static void on_exit_trampoline(int status, void* arg) {
    (void)status;
    (void)arg;
}

int hexray_on_exit(on_exit_fn_t cb, void* arg) {
    if (cb) {
        cb(0, arg);
    }
    return 0;
}

int register_on_exit(on_exit_fn_t cb, void* arg) {
    on_exit_fn_t handler = cb;
    void* context = arg;
    return hexray_on_exit(handler, context);
}

static void atfork_prepare(void) {}
static void atfork_parent(void) {}
static void atfork_child(void) {}

int hexray_pthread_atfork(atfork_fn_t prepare, atfork_fn_t parent, atfork_fn_t child) {
    if (prepare) {
        prepare();
    }
    if (parent) {
        parent();
    }
    if (child) {
        child();
    }
    return 0;
}

int register_atfork(atfork_fn_t prepare, atfork_fn_t parent, atfork_fn_t child) {
    atfork_fn_t prep = prepare;
    atfork_fn_t par = parent;
    atfork_fn_t chi = child;
    return hexray_pthread_atfork(prep, par, chi);
}

int run_callbacks(int* arr, size_t n, handler_fn_t h) {
    int first = sort_with_cmp(arr, n, cmp_ints);
    int looked = lookup_with_cmp(arr, n, 3, cmp_ints);
    int spawned = spawn_with_start(thread_trampoline, arr);
    int glibc_like = sort_with_qsort_r_glibc(arr, n, cmp_ints_with_ctx, 0);
    int bsd_like = sort_with_qsort_r_bsd(arr, n, cmp_ints_with_ctx, 0);
    int reg_exit = register_on_exit(on_exit_trampoline, arr);
    int reg_atfork = register_atfork(atfork_prepare, atfork_parent, atfork_child);
    return first + looked + spawned + glibc_like + bsd_like + reg_exit + reg_atfork
        + (install_handler(h) != 0);
}

int main(void) {
    int data[4] = {4, 2, 3, 1};
    return run_callbacks(data, 4, 0);
}
