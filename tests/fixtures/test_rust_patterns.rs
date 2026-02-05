// Test Rust patterns for decompiler validation
// Compile: rustc -O -o test_rust_patterns test_rust_patterns.rs
// Or: rustc -C opt-level=2 -o test_rust_patterns test_rust_patterns.rs

// Simple enum with match
#[derive(Clone, Copy)]
enum Color {
    Red,
    Green,
    Blue,
    Rgb(u8, u8, u8),
}

fn color_to_value(c: Color) -> u32 {
    match c {
        Color::Red => 0xFF0000,
        Color::Green => 0x00FF00,
        Color::Blue => 0x0000FF,
        Color::Rgb(r, g, b) => ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
    }
}

// Option handling patterns
fn safe_divide(a: i32, b: i32) -> Option<i32> {
    if b == 0 {
        None
    } else {
        Some(a / b)
    }
}

fn unwrap_or_default(opt: Option<i32>) -> i32 {
    match opt {
        Some(v) => v,
        None => 0,
    }
}

// Result handling
#[derive(Debug)]
enum MathError {
    DivisionByZero,
    Overflow,
}

fn checked_divide(a: i32, b: i32) -> Result<i32, MathError> {
    if b == 0 {
        Err(MathError::DivisionByZero)
    } else {
        Ok(a / b)
    }
}

fn handle_result(r: Result<i32, MathError>) -> i32 {
    match r {
        Ok(v) => v,
        Err(MathError::DivisionByZero) => -1,
        Err(MathError::Overflow) => -2,
    }
}

// Struct with impl
struct Point {
    x: i32,
    y: i32,
}

impl Point {
    fn new(x: i32, y: i32) -> Self {
        Point { x, y }
    }

    fn distance_squared(&self, other: &Point) -> i32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        dx * dx + dy * dy
    }

    fn translate(&mut self, dx: i32, dy: i32) {
        self.x += dx;
        self.y += dy;
    }
}

// Trait implementation
trait Shape {
    fn area(&self) -> i32;
    fn perimeter(&self) -> i32;
}

struct Rectangle {
    width: i32,
    height: i32,
}

impl Shape for Rectangle {
    fn area(&self) -> i32 {
        self.width * self.height
    }

    fn perimeter(&self) -> i32 {
        2 * (self.width + self.height)
    }
}

struct Square {
    side: i32,
}

impl Shape for Square {
    fn area(&self) -> i32 {
        self.side * self.side
    }

    fn perimeter(&self) -> i32 {
        4 * self.side
    }
}

// Generic function (monomorphized)
fn max<T: Ord>(a: T, b: T) -> T {
    if a > b { a } else { b }
}

// Iterator patterns
fn sum_array(arr: &[i32]) -> i32 {
    let mut sum = 0;
    for x in arr {
        sum += x;
    }
    sum
}

fn find_max(arr: &[i32]) -> Option<i32> {
    if arr.is_empty() {
        return None;
    }
    let mut max_val = arr[0];
    for &x in &arr[1..] {
        if x > max_val {
            max_val = x;
        }
    }
    Some(max_val)
}

// Closure patterns
fn apply_twice<F>(f: F, x: i32) -> i32
where
    F: Fn(i32) -> i32,
{
    f(f(x))
}

// Panic handling (unwinding)
fn assert_positive(x: i32) -> i32 {
    assert!(x > 0, "Value must be positive");
    x
}

// Slice patterns
fn first_last(arr: &[i32]) -> (i32, i32) {
    match arr {
        [] => (0, 0),
        [x] => (*x, *x),
        [first, .., last] => (*first, *last),
    }
}

// Box allocation
fn boxed_value(x: i32) -> Box<i32> {
    Box::new(x * 2)
}

// Vec operations
fn build_vec(n: usize) -> Vec<i32> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        v.push(i as i32);
    }
    v
}

// String operations
fn string_length(s: &str) -> usize {
    s.len()
}

fn concat_strings(a: &str, b: &str) -> String {
    let mut result = String::from(a);
    result.push_str(b);
    result
}

fn main() {
    let mut result: i32 = 0;

    // Test enum matching
    result += color_to_value(Color::Red) as i32;
    result += color_to_value(Color::Rgb(128, 64, 32)) as i32;

    // Test Option
    result += unwrap_or_default(safe_divide(10, 2));
    result += unwrap_or_default(safe_divide(10, 0));

    // Test Result
    result += handle_result(checked_divide(20, 4));
    result += handle_result(checked_divide(20, 0));

    // Test struct methods
    let mut p1 = Point::new(0, 0);
    let p2 = Point::new(3, 4);
    result += p1.distance_squared(&p2);
    p1.translate(1, 1);
    result += p1.x + p1.y;

    // Test trait objects
    let rect = Rectangle { width: 10, height: 5 };
    let sq = Square { side: 4 };
    result += rect.area() + sq.area();

    // Test generics
    result += max(10, 20);
    result += max(-5, -10);

    // Test iterators
    let arr = [1, 2, 3, 4, 5];
    result += sum_array(&arr);
    result += find_max(&arr).unwrap_or(0);

    // Test closures
    result += apply_twice(|x| x + 1, 5);

    // Test slice patterns
    let (first, last) = first_last(&arr);
    result += first + last;

    // Test Box
    let b = boxed_value(10);
    result += *b;

    // Test Vec
    let v = build_vec(5);
    result += v.iter().sum::<i32>();

    // Test strings
    result += string_length("hello") as i32;

    println!("Result: {}", result);
}
