// Test case for loop-around-co_await pattern
// This coroutine has a loop around a co_await point, which is the
// loop-around-co_await extraction challenge.

#include <coroutine>
#include <iostream>

struct Task {
    struct promise_type {
        Task get_return_object() { return {}; }
        std::suspend_never initial_suspend() { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };
};

// Simple awaitable for testing
struct Awaitable {
    bool await_ready() noexcept { return false; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume() noexcept {}
};

// Coroutine with loop around co_await
// The issue: resume target is inside the loop body
Task loop_around_await(int n) {
    co_await Awaitable{};  // Initial suspend point

    int i = 0;
    while (i < n) {
        co_await Awaitable{};  // Resume target is INSIDE the loop!
        std::cout << "Iteration: " << i << std::endl;
        i++;
    }

    co_await Awaitable{};  // Final suspend point after loop
}

// Variant: loop with multiple suspend points inside
void helper();

Task multiple_suspends_in_loop() {
    co_await Awaitable{};

    while (true) {
        co_await Awaitable{};  // First suspend inside loop
        helper();
        co_await Awaitable{};  // Second suspend inside loop
    }
}

void helper() {}
