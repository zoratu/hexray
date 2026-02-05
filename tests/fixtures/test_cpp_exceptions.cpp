// Test C++ exception handling patterns for decompiler validation
// Compile: g++ -O2 -fexceptions -o test_cpp_exceptions test_cpp_exceptions.cpp
// Or: clang++ -O2 -fexceptions -o test_cpp_exceptions test_cpp_exceptions.cpp

#include <cstddef>

// Custom exception classes
class Error {
protected:
    int code;
public:
    Error(int c) : code(c) {}
    virtual ~Error() {}
    virtual int getCode() const { return code; }
};

class IOError : public Error {
public:
    IOError(int c) : Error(c) {}
};

class MemoryError : public Error {
public:
    MemoryError() : Error(-1) {}
};

// Function that throws
int divide(int a, int b) {
    if (b == 0) {
        throw Error(1);
    }
    return a / b;
}

// Function with try-catch
int safeDivide(int a, int b) {
    try {
        return divide(a, b);
    } catch (const Error& e) {
        return e.getCode();
    }
}

// Multiple catch blocks
int handleErrors(int type) {
    try {
        if (type == 0) {
            throw IOError(42);
        } else if (type == 1) {
            throw MemoryError();
        } else if (type == 2) {
            throw Error(100);
        }
        return 0;
    } catch (const IOError& e) {
        return e.getCode() + 1000;
    } catch (const MemoryError& e) {
        return e.getCode() + 2000;
    } catch (const Error& e) {
        return e.getCode() + 3000;
    } catch (...) {
        return -9999;
    }
}

// Nested try-catch
int nestedTryCatch(int a, int b) {
    int result = 0;
    try {
        try {
            result = divide(a, b);
        } catch (const Error& e) {
            // Re-throw with different code
            throw Error(e.getCode() * 10);
        }
    } catch (const Error& e) {
        result = e.getCode();
    }
    return result;
}

// RAII pattern with exceptions
class Resource {
private:
    int* data;
public:
    Resource(int size) {
        data = new int[size];
        for (int i = 0; i < size; i++) {
            data[i] = i;
        }
    }

    ~Resource() {
        delete[] data;
    }

    int sum(int n) const {
        int s = 0;
        for (int i = 0; i < n; i++) {
            s += data[i];
        }
        return s;
    }
};

int useResource(int size) {
    Resource r(size);
    if (size < 0) {
        throw Error(-1);
    }
    return r.sum(size);
}

int safeUseResource(int size) {
    try {
        return useResource(size);
    } catch (const Error& e) {
        return e.getCode();
    }
}

// Exception specification (noexcept)
int noThrow(int a, int b) noexcept {
    if (b == 0) return 0;
    return a / b;
}

// Function try block (less common)
class Initializer {
private:
    int value;
public:
    Initializer(int v) try : value(v) {
        if (v < 0) {
            throw Error(v);
        }
    } catch (const Error&) {
        // Cannot access non-static members here
        // Just re-throw
        throw;
    }

    int get() const { return value; }
};

int main() {
    int result = 0;

    // Test basic try-catch
    result += safeDivide(10, 2);
    result += safeDivide(10, 0);

    // Test multiple catch blocks
    result += handleErrors(0);
    result += handleErrors(1);
    result += handleErrors(2);
    result += handleErrors(3);

    // Test nested try-catch
    result += nestedTryCatch(10, 2);
    result += nestedTryCatch(10, 0);

    // Test RAII with exceptions
    result += safeUseResource(5);
    result += safeUseResource(-1);

    // Test noexcept
    result += noThrow(10, 2);
    result += noThrow(10, 0);

    return result;
}
