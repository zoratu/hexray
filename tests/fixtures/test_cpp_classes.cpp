// Test C++ class patterns for decompiler validation
// Compile: g++ -O2 -o test_cpp_classes test_cpp_classes.cpp
// Or: clang++ -O2 -o test_cpp_classes test_cpp_classes.cpp

#include <cstddef>

// Simple class with constructor/destructor
class Counter {
private:
    int value;
public:
    Counter() : value(0) {}
    Counter(int v) : value(v) {}
    ~Counter() { value = -1; }

    void increment() { value++; }
    void decrement() { value--; }
    int get() const { return value; }
    void set(int v) { value = v; }
};

// Class with virtual functions (vtable)
class Shape {
protected:
    int x, y;
public:
    Shape(int x, int y) : x(x), y(y) {}
    virtual ~Shape() {}

    virtual int area() const = 0;
    virtual int perimeter() const = 0;

    int getX() const { return x; }
    int getY() const { return y; }
};

class Rectangle : public Shape {
private:
    int width, height;
public:
    Rectangle(int x, int y, int w, int h)
        : Shape(x, y), width(w), height(h) {}

    int area() const override { return width * height; }
    int perimeter() const override { return 2 * (width + height); }

    int getWidth() const { return width; }
    int getHeight() const { return height; }
};

class Circle : public Shape {
private:
    int radius;
public:
    Circle(int x, int y, int r) : Shape(x, y), radius(r) {}

    int area() const override { return 314 * radius * radius / 100; }
    int perimeter() const override { return 628 * radius / 100; }

    int getRadius() const { return radius; }
};

// Multiple inheritance
class Drawable {
public:
    virtual void draw() const = 0;
    virtual ~Drawable() {}
};

class ColoredShape : public Shape, public Drawable {
protected:
    int color;
public:
    ColoredShape(int x, int y, int c) : Shape(x, y), color(c) {}

    void draw() const override {
        // Simulated drawing - just use color
        volatile int c = color;
        (void)c;
    }

    int getColor() const { return color; }
};

class ColoredRectangle : public ColoredShape {
private:
    int width, height;
public:
    ColoredRectangle(int x, int y, int w, int h, int c)
        : ColoredShape(x, y, c), width(w), height(h) {}

    int area() const override { return width * height; }
    int perimeter() const override { return 2 * (width + height); }
};

// Template-like pattern (expanded)
class IntStack {
private:
    int data[16];
    int top;
public:
    IntStack() : top(0) {}

    void push(int val) {
        if (top < 16) {
            data[top++] = val;
        }
    }

    int pop() {
        if (top > 0) {
            return data[--top];
        }
        return 0;
    }

    bool empty() const { return top == 0; }
    int size() const { return top; }
};

// RTTI patterns
Shape* createShape(int type, int x, int y, int size) {
    switch (type) {
        case 0: return new Rectangle(x, y, size, size);
        case 1: return new Circle(x, y, size);
        default: return nullptr;
    }
}

int main() {
    // Test simple class
    Counter c(10);
    c.increment();
    c.increment();
    c.decrement();
    int result = c.get();

    // Test virtual functions
    Rectangle rect(0, 0, 10, 20);
    Circle circ(0, 0, 5);

    Shape* shapes[2] = { &rect, &circ };
    int totalArea = 0;
    for (int i = 0; i < 2; i++) {
        totalArea += shapes[i]->area();
    }

    // Test multiple inheritance
    ColoredRectangle cr(0, 0, 5, 5, 0xFF0000);
    cr.draw();
    result += cr.area();

    // Test stack
    IntStack stack;
    stack.push(1);
    stack.push(2);
    stack.push(3);
    result += stack.pop();

    // Test dynamic allocation
    Shape* dynamic = createShape(0, 0, 0, 10);
    if (dynamic) {
        result += dynamic->area();
        delete dynamic;
    }

    return result + totalArea;
}
