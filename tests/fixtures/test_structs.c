// Test struct access patterns for decompiler validation
// Compile: gcc -O2 -o test_structs test_structs.c

#include <stddef.h>

// Simple struct
struct Point {
    int x;
    int y;
};

// Nested struct
struct Rectangle {
    struct Point top_left;
    struct Point bottom_right;
};

// Struct with array
struct Buffer {
    int size;
    int capacity;
    int data[16];
};

// Struct field access
int point_sum(struct Point *p) {
    return p->x + p->y;
}

// Struct initialization and return
struct Point make_point(int x, int y) {
    struct Point p;
    p.x = x;
    p.y = y;
    return p;
}

// Nested struct access
int rectangle_area(struct Rectangle *r) {
    int width = r->bottom_right.x - r->top_left.x;
    int height = r->bottom_right.y - r->top_left.y;
    return width * height;
}

// Struct array access
int buffer_sum(struct Buffer *buf) {
    int sum = 0;
    for (int i = 0; i < buf->size; i++) {
        sum += buf->data[i];
    }
    return sum;
}

// Struct modification
void buffer_push(struct Buffer *buf, int value) {
    if (buf->size < buf->capacity) {
        buf->data[buf->size] = value;
        buf->size++;
    }
}

// Array of structs
int total_x(struct Point *points, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += points[i].x;
    }
    return sum;
}

// Pointer arithmetic with structs
struct Point *find_closest(struct Point *points, int n, int target_x) {
    struct Point *closest = points;
    int min_dist = target_x > points[0].x ? target_x - points[0].x : points[0].x - target_x;

    for (int i = 1; i < n; i++) {
        int dist = target_x > points[i].x ? target_x - points[i].x : points[i].x - target_x;
        if (dist < min_dist) {
            min_dist = dist;
            closest = &points[i];
        }
    }
    return closest;
}

int main(void) {
    struct Point p = {10, 20};
    struct Rectangle r = {{0, 0}, {100, 50}};
    struct Buffer buf = {3, 16, {1, 2, 3}};
    struct Point points[3] = {{1, 1}, {5, 5}, {10, 10}};

    int result = 0;
    result += point_sum(&p);
    result += rectangle_area(&r);
    result += buffer_sum(&buf);
    buffer_push(&buf, 4);
    result += total_x(points, 3);
    struct Point *closest = find_closest(points, 3, 7);
    result += closest->x;
    return result;
}
