// Test D language patterns for decompiler validation
// Compile: dmd -O -of=test_d_patterns test_d_patterns.d
// Or: ldc2 -O2 -of=test_d_patterns test_d_patterns.d

import core.stdc.stdio : printf;

// Struct with methods
struct Point {
    int x, y;

    int distanceSquared(Point other) const {
        int dx = x - other.x;
        int dy = y - other.y;
        return dx * dx + dy * dy;
    }

    void translate(int dx, int dy) {
        x += dx;
        y += dy;
    }

    static Point create(int x, int y) {
        return Point(x, y);
    }
}

// Class with inheritance
class Shape {
    int x, y;

    this(int x, int y) {
        this.x = x;
        this.y = y;
    }

    abstract int area();
    abstract int perimeter();

    int getX() const { return x; }
    int getY() const { return y; }
}

class Rectangle : Shape {
    int width, height;

    this(int x, int y, int w, int h) {
        super(x, y);
        width = w;
        height = h;
    }

    override int area() {
        return width * height;
    }

    override int perimeter() {
        return 2 * (width + height);
    }
}

class Circle : Shape {
    int radius;

    this(int x, int y, int r) {
        super(x, y);
        radius = r;
    }

    override int area() {
        return 314 * radius * radius / 100;
    }

    override int perimeter() {
        return 628 * radius / 100;
    }
}

// Interface
interface Drawable {
    void draw();
}

class ColoredRectangle : Rectangle, Drawable {
    int color;

    this(int x, int y, int w, int h, int c) {
        super(x, y, w, h);
        color = c;
    }

    void draw() {
        // Simulated drawing
        int c = color;
    }
}

// Templates (D's version of generics)
T max(T)(T a, T b) {
    return a > b ? a : b;
}

T min(T)(T a, T b) {
    return a < b ? a : b;
}

T clamp(T)(T value, T lo, T hi) {
    return max(lo, min(hi, value));
}

// Array operations with slices
int sumArray(int[] arr) {
    int sum = 0;
    foreach (x; arr) {
        sum += x;
    }
    return sum;
}

int findMax(int[] arr) {
    if (arr.length == 0) return 0;
    int maxVal = arr[0];
    foreach (x; arr[1..$]) {
        if (x > maxVal) {
            maxVal = x;
        }
    }
    return maxVal;
}

// Range-based iteration
int sumRange(int start, int end) {
    int sum = 0;
    foreach (i; start..end) {
        sum += i;
    }
    return sum;
}

// Static arrays vs dynamic arrays
int[4] staticArray() {
    int[4] arr = [1, 2, 3, 4];
    return arr;
}

int[] dynamicArray(size_t n) {
    int[] arr = new int[n];
    foreach (i; 0..n) {
        arr[i] = cast(int)i;
    }
    return arr;
}

// Associative arrays
int lookupOrDefault(int[string] map, string key, int defaultValue) {
    if (auto p = key in map) {
        return *p;
    }
    return defaultValue;
}

// Nullable types
struct Nullable(T) {
    T value;
    bool isNull = true;

    static Nullable!T some(T val) {
        Nullable!T n;
        n.value = val;
        n.isNull = false;
        return n;
    }

    static Nullable!T none() {
        return Nullable!T.init;
    }

    T getOrElse(T defaultValue) {
        return isNull ? defaultValue : value;
    }
}

Nullable!int safeDivide(int a, int b) {
    if (b == 0) {
        return Nullable!int.none();
    }
    return Nullable!int.some(a / b);
}

// Exception handling
class MathException : Exception {
    this(string msg) {
        super(msg);
    }
}

int checkedDivide(int a, int b) {
    if (b == 0) {
        throw new MathException("Division by zero");
    }
    return a / b;
}

int safeCheckedDivide(int a, int b) {
    try {
        return checkedDivide(a, b);
    } catch (MathException e) {
        return -1;
    }
}

// Scope guards (D-specific RAII)
int withScopeGuard(int x) {
    int result = 0;
    scope(exit) result += 1;  // Always runs
    scope(success) result += 10;  // Runs on normal exit
    scope(failure) result += 100;  // Runs on exception

    if (x < 0) {
        throw new Exception("Negative value");
    }
    result = x * 2;
    return result;
}

// Contract programming
int divide(int a, int b)
in {
    assert(b != 0, "Divisor cannot be zero");
}
out (result) {
    assert(result * b <= a, "Result too large");
}
do {
    return a / b;
}

// Compile-time function evaluation (CTFE)
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

enum factorialOf5 = factorial(5);  // Computed at compile time

// Mixins (string mixins for code generation)
string generateGetter(string name) {
    return "int get" ~ name ~ "() { return " ~ name ~ "; }";
}

struct Config {
    int value;
    mixin(generateGetter("value"));
}

// Alias this (implicit conversion)
struct Wrapper {
    int value;
    alias value this;  // Wrapper implicitly converts to int
}

int useWrapper(Wrapper w) {
    return w + 10;  // Uses alias this
}

// Bit manipulation
uint setBit(uint value, int bit) {
    return value | (1u << bit);
}

uint clearBit(uint value, int bit) {
    return value & ~(1u << bit);
}

bool testBit(uint value, int bit) {
    return (value & (1u << bit)) != 0;
}

// Main function
void main() {
    int result = 0;

    // Test struct
    auto p1 = Point(0, 0);
    auto p2 = Point.create(3, 4);
    result += p1.distanceSquared(p2);

    // Test classes
    Shape rect = new Rectangle(0, 0, 10, 5);
    Shape circ = new Circle(0, 0, 5);
    result += rect.area() + circ.area();

    // Test interface
    auto cr = new ColoredRectangle(0, 0, 4, 4, 0xFF0000);
    cr.draw();
    result += cr.area();

    // Test templates
    result += max(10, 20);
    result += clamp(15, 0, 10);

    // Test arrays
    int[] arr = [1, 2, 3, 4, 5];
    result += sumArray(arr);
    result += findMax(arr);

    // Test range
    result += sumRange(1, 11);

    // Test nullable
    result += safeDivide(10, 2).getOrElse(0);
    result += safeDivide(10, 0).getOrElse(-1);

    // Test exception handling
    result += safeCheckedDivide(20, 4);
    result += safeCheckedDivide(20, 0);

    // Test CTFE
    result += factorialOf5;

    // Test bit operations
    result += cast(int)setBit(0, 3);
    result += testBit(8, 3) ? 1 : 0;

    printf("Result: %d\n", result);
}
