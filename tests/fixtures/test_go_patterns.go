// Test Go patterns for decompiler validation
// Compile: go build -o test_go_patterns test_go_patterns.go

package main

import "fmt"

// Struct with methods
type Point struct {
	X, Y int
}

func NewPoint(x, y int) Point {
	return Point{X: x, Y: y}
}

func (p Point) DistanceSquared(other Point) int {
	dx := p.X - other.X
	dy := p.Y - other.Y
	return dx*dx + dy*dy
}

func (p *Point) Translate(dx, dy int) {
	p.X += dx
	p.Y += dy
}

// Interface and implementation
type Shape interface {
	Area() int
	Perimeter() int
}

type Rectangle struct {
	Width, Height int
}

func (r Rectangle) Area() int {
	return r.Width * r.Height
}

func (r Rectangle) Perimeter() int {
	return 2 * (r.Width + r.Height)
}

type Circle struct {
	Radius int
}

func (c Circle) Area() int {
	return 314 * c.Radius * c.Radius / 100
}

func (c Circle) Perimeter() int {
	return 628 * c.Radius / 100
}

// Function returning interface
func CreateShape(shapeType int, size int) Shape {
	switch shapeType {
	case 0:
		return Rectangle{Width: size, Height: size}
	case 1:
		return Circle{Radius: size}
	default:
		return nil
	}
}

// Multiple return values
func Divide(a, b int) (int, error) {
	if b == 0 {
		return 0, fmt.Errorf("division by zero")
	}
	return a / b, nil
}

func SafeDivide(a, b int) int {
	result, err := Divide(a, b)
	if err != nil {
		return -1
	}
	return result
}

// Defer pattern
func WithDefer(x int) int {
	result := 0
	defer func() {
		result += 1 // This modifies a local, won't affect return
	}()
	result = x * 2
	return result
}

// Panic and recover
func MightPanic(x int) int {
	if x < 0 {
		panic("negative value")
	}
	return x * 2
}

func SafeCall(x int) (result int) {
	defer func() {
		if r := recover(); r != nil {
			result = -1
		}
	}()
	result = MightPanic(x)
	return
}

// Slice operations
func SumSlice(arr []int) int {
	sum := 0
	for _, v := range arr {
		sum += v
	}
	return sum
}

func FindMax(arr []int) int {
	if len(arr) == 0 {
		return 0
	}
	maxVal := arr[0]
	for _, v := range arr[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

// Map operations
func LookupOrDefault(m map[string]int, key string, defaultVal int) int {
	if val, ok := m[key]; ok {
		return val
	}
	return defaultVal
}

func CountOccurrences(arr []int) map[int]int {
	counts := make(map[int]int)
	for _, v := range arr {
		counts[v]++
	}
	return counts
}

// Goroutine patterns (simplified - no concurrency in single binary)
func ChannelSimulation() int {
	ch := make(chan int, 1)
	ch <- 42
	return <-ch
}

// Select simulation
func SelectSimulation(a, b int) int {
	ch1 := make(chan int, 1)
	ch2 := make(chan int, 1)
	ch1 <- a
	ch2 <- b

	select {
	case v := <-ch1:
		return v
	case v := <-ch2:
		return v
	}
}

// Closure patterns
func MakeAdder(x int) func(int) int {
	return func(y int) int {
		return x + y
	}
}

func ApplyTwice(f func(int) int, x int) int {
	return f(f(x))
}

// Type assertion
func ProcessInterface(i interface{}) int {
	switch v := i.(type) {
	case int:
		return v
	case string:
		return len(v)
	case Shape:
		return v.Area()
	default:
		return 0
	}
}

// Embedding (composition)
type Named struct {
	Name string
}

func (n Named) GetName() string {
	return n.Name
}

type NamedRectangle struct {
	Named
	Rectangle
}

// Variadic functions
func Sum(nums ...int) int {
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}

// Array vs slice
func ArraySum(arr [5]int) int {
	sum := 0
	for _, v := range arr {
		sum += v
	}
	return sum
}

// Pointer receiver vs value receiver
type Counter struct {
	value int
}

func (c Counter) Get() int {
	return c.value
}

func (c *Counter) Increment() {
	c.value++
}

func (c *Counter) Add(n int) {
	c.value += n
}

// String operations
func StringLength(s string) int {
	return len(s)
}

func ConcatStrings(a, b string) string {
	return a + b
}

func RuneCount(s string) int {
	count := 0
	for range s {
		count++
	}
	return count
}

// Bit operations
func SetBit(value uint, bit int) uint {
	return value | (1 << bit)
}

func ClearBit(value uint, bit int) uint {
	return value &^ (1 << bit)
}

func TestBit(value uint, bit int) bool {
	return (value & (1 << bit)) != 0
}

// Loop patterns
func ForLoop(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += i
	}
	return sum
}

func WhileLoop(n int) int {
	sum := 0
	i := 0
	for i < n {
		sum += i
		i++
	}
	return sum
}

func InfiniteLoopWithBreak(n int) int {
	sum := 0
	i := 0
	for {
		if i >= n {
			break
		}
		sum += i
		i++
	}
	return sum
}

func main() {
	result := 0

	// Test struct methods
	p1 := NewPoint(0, 0)
	p2 := NewPoint(3, 4)
	result += p1.DistanceSquared(p2)
	p1.Translate(1, 1)
	result += p1.X + p1.Y

	// Test interfaces
	rect := Rectangle{Width: 10, Height: 5}
	circ := Circle{Radius: 5}
	result += rect.Area() + circ.Area()

	// Test interface creation
	shape := CreateShape(0, 4)
	if shape != nil {
		result += shape.Area()
	}

	// Test multiple returns
	result += SafeDivide(10, 2)
	result += SafeDivide(10, 0)

	// Test defer
	result += WithDefer(5)

	// Test panic/recover
	result += SafeCall(5)
	result += SafeCall(-5)

	// Test slices
	arr := []int{1, 2, 3, 4, 5}
	result += SumSlice(arr)
	result += FindMax(arr)

	// Test maps
	m := map[string]int{"a": 1, "b": 2}
	result += LookupOrDefault(m, "a", 0)
	result += LookupOrDefault(m, "c", -1)

	// Test channels
	result += ChannelSimulation()

	// Test closures
	add5 := MakeAdder(5)
	result += add5(10)
	result += ApplyTwice(func(x int) int { return x + 1 }, 5)

	// Test type assertion
	result += ProcessInterface(42)
	result += ProcessInterface("hello")
	result += ProcessInterface(rect)

	// Test variadic
	result += Sum(1, 2, 3, 4, 5)

	// Test counter
	var c Counter
	c.Increment()
	c.Add(5)
	result += c.Get()

	// Test bit operations
	result += int(SetBit(0, 3))

	// Test loops
	result += ForLoop(10)

	fmt.Printf("Result: %d\n", result)
}
