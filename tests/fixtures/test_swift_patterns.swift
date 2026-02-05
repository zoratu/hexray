// Test Swift patterns for decompiler validation
// Compile: swiftc -O -o test_swift_patterns test_swift_patterns.swift
// Or: swiftc -Osize -o test_swift_patterns test_swift_patterns.swift

import Foundation

// MARK: - Structs (value types)

struct Point {
    var x: Int
    var y: Int

    func distanceSquared(to other: Point) -> Int {
        let dx = x - other.x
        let dy = y - other.y
        return dx * dx + dy * dy
    }

    mutating func translate(dx: Int, dy: Int) {
        x += dx
        y += dy
    }
}

// MARK: - Classes (reference types)

class Shape {
    var x: Int
    var y: Int

    init(x: Int, y: Int) {
        self.x = x
        self.y = y
    }

    func area() -> Int {
        fatalError("Must override")
    }

    func perimeter() -> Int {
        fatalError("Must override")
    }
}

class Rectangle: Shape {
    var width: Int
    var height: Int

    init(x: Int, y: Int, width: Int, height: Int) {
        self.width = width
        self.height = height
        super.init(x: x, y: y)
    }

    override func area() -> Int {
        return width * height
    }

    override func perimeter() -> Int {
        return 2 * (width + height)
    }
}

class Circle: Shape {
    var radius: Int

    init(x: Int, y: Int, radius: Int) {
        self.radius = radius
        super.init(x: x, y: y)
    }

    override func area() -> Int {
        return 314 * radius * radius / 100
    }

    override func perimeter() -> Int {
        return 628 * radius / 100
    }
}

// MARK: - Protocols

protocol Drawable {
    func draw()
}

extension Rectangle: Drawable {
    func draw() {
        // Simulated drawing
        let _ = width * height
    }
}

// MARK: - Enums with associated values

enum Color {
    case red
    case green
    case blue
    case rgb(r: UInt8, g: UInt8, b: UInt8)

    func toValue() -> UInt32 {
        switch self {
        case .red:
            return 0xFF0000
        case .green:
            return 0x00FF00
        case .blue:
            return 0x0000FF
        case .rgb(let r, let g, let b):
            return (UInt32(r) << 16) | (UInt32(g) << 8) | UInt32(b)
        }
    }
}

// MARK: - Optional handling

func safeDivide(_ a: Int, _ b: Int) -> Int? {
    guard b != 0 else { return nil }
    return a / b
}

func unwrapOrDefault(_ opt: Int?, defaultValue: Int) -> Int {
    if let value = opt {
        return value
    }
    return defaultValue
}

func forceUnwrapIfNotNil(_ opt: Int?) -> Int {
    return opt!
}

// MARK: - Error handling

enum MathError: Error {
    case divisionByZero
    case overflow
    case underflow
}

func checkedDivide(_ a: Int, _ b: Int) throws -> Int {
    if b == 0 {
        throw MathError.divisionByZero
    }
    return a / b
}

func safeCheckedDivide(_ a: Int, _ b: Int) -> Int {
    do {
        return try checkedDivide(a, b)
    } catch MathError.divisionByZero {
        return -1
    } catch {
        return -2
    }
}

// MARK: - Closures

func applyTwice(_ f: (Int) -> Int, to x: Int) -> Int {
    return f(f(x))
}

func makeAdder(_ x: Int) -> (Int) -> Int {
    return { y in x + y }
}

// Closure with capture
func counter(start: Int) -> () -> Int {
    var count = start
    return {
        count += 1
        return count
    }
}

// MARK: - Array operations

func sumArray(_ arr: [Int]) -> Int {
    var sum = 0
    for x in arr {
        sum += x
    }
    return sum
}

func findMax(_ arr: [Int]) -> Int? {
    guard !arr.isEmpty else { return nil }
    var maxVal = arr[0]
    for x in arr.dropFirst() {
        if x > maxVal {
            maxVal = x
        }
    }
    return maxVal
}

func filterPositive(_ arr: [Int]) -> [Int] {
    return arr.filter { $0 > 0 }
}

func mapDouble(_ arr: [Int]) -> [Int] {
    return arr.map { $0 * 2 }
}

func reduceSum(_ arr: [Int]) -> Int {
    return arr.reduce(0, +)
}

// MARK: - Dictionary operations

func lookupOrDefault(_ dict: [String: Int], key: String, defaultValue: Int) -> Int {
    return dict[key] ?? defaultValue
}

// MARK: - Generics

func max<T: Comparable>(_ a: T, _ b: T) -> T {
    return a > b ? a : b
}

func swap<T>(_ a: inout T, _ b: inout T) {
    let temp = a
    a = b
    b = temp
}

// MARK: - Property observers

class Observable {
    var value: Int = 0 {
        willSet {
            // About to change
        }
        didSet {
            // Changed from oldValue to value
        }
    }
}

// MARK: - Computed properties

struct Temperature {
    var celsius: Double

    var fahrenheit: Double {
        get {
            return celsius * 9 / 5 + 32
        }
        set {
            celsius = (newValue - 32) * 5 / 9
        }
    }
}

// MARK: - Defer

func withDefer(_ x: Int) -> Int {
    var result = 0
    defer {
        result += 1  // Modifies local, but return already captured
    }
    result = x * 2
    return result
}

// MARK: - Guard statement

func processPositive(_ x: Int) -> Int {
    guard x > 0 else {
        return -1
    }
    return x * 2
}

// MARK: - Switch with pattern matching

func categorize(_ x: Int) -> String {
    switch x {
    case ..<0:
        return "negative"
    case 0:
        return "zero"
    case 1...10:
        return "small"
    case 11...100:
        return "medium"
    default:
        return "large"
    }
}

func matchTuple(_ point: (Int, Int)) -> Int {
    switch point {
    case (0, 0):
        return 0
    case (let x, 0):
        return x
    case (0, let y):
        return y
    case (let x, let y) where x == y:
        return x * 2
    case (let x, let y):
        return x + y
    }
}

// MARK: - String operations

func stringLength(_ s: String) -> Int {
    return s.count
}

func concatStrings(_ a: String, _ b: String) -> String {
    return a + b
}

// MARK: - Bit operations

func setBit(_ value: UInt, _ bit: Int) -> UInt {
    return value | (1 << bit)
}

func clearBit(_ value: UInt, _ bit: Int) -> UInt {
    return value & ~(1 << bit)
}

func testBit(_ value: UInt, _ bit: Int) -> Bool {
    return (value & (1 << bit)) != 0
}

// MARK: - Main

func main() -> Int {
    var result = 0

    // Test struct
    var p1 = Point(x: 0, y: 0)
    let p2 = Point(x: 3, y: 4)
    result += p1.distanceSquared(to: p2)
    p1.translate(dx: 1, dy: 1)
    result += p1.x + p1.y

    // Test classes
    let rect = Rectangle(x: 0, y: 0, width: 10, height: 5)
    let circ = Circle(x: 0, y: 0, radius: 5)
    result += rect.area() + circ.area()

    // Test protocol
    rect.draw()

    // Test enum
    result += Int(Color.red.toValue())
    result += Int(Color.rgb(r: 128, g: 64, b: 32).toValue())

    // Test optionals
    result += unwrapOrDefault(safeDivide(10, 2), defaultValue: 0)
    result += unwrapOrDefault(safeDivide(10, 0), defaultValue: -1)

    // Test error handling
    result += safeCheckedDivide(20, 4)
    result += safeCheckedDivide(20, 0)

    // Test closures
    result += applyTwice({ $0 + 1 }, to: 5)
    let add5 = makeAdder(5)
    result += add5(10)

    // Test arrays
    let arr = [1, 2, 3, 4, 5]
    result += sumArray(arr)
    result += findMax(arr) ?? 0
    result += reduceSum(filterPositive([-1, 2, -3, 4]))

    // Test dictionary
    let dict = ["a": 1, "b": 2]
    result += lookupOrDefault(dict, key: "a", defaultValue: 0)
    result += lookupOrDefault(dict, key: "c", defaultValue: -1)

    // Test generics
    result += max(10, 20)

    // Test defer
    result += withDefer(5)

    // Test guard
    result += processPositive(5)
    result += processPositive(-5)

    // Test switch
    result += matchTuple((3, 4))

    // Test bit operations
    result += Int(setBit(0, 3))

    return result
}

let exitCode = main()
print("Result: \(exitCode)")
