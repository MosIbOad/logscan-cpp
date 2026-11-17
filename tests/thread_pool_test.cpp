#include "logscan/thread_pool.hpp"

#include <atomic>
#include <chrono>
#include <numeric>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

TEST(ThreadPoolTest, SubmitAndGetFuture) {
    logscan::ThreadPool pool(4);

    auto fut1 = pool.submit([]() { return 42; });
    auto fut2 = pool.submit([](int a, int b) { return a + b; }, 10, 20);

    EXPECT_EQ(fut1.get(), 42);
    EXPECT_EQ(fut2.get(), 30);
}

TEST(ThreadPoolTest, ParallelExecutionAcrossMultipleThreads) {
    const size_t num_threads = 4;
    const size_t task_count = 100;
    logscan::ThreadPool pool(num_threads);

    std::atomic<int> counter{0};
    std::vector<std::future<void>> futures;
    futures.reserve(task_count);

    for (size_t i = 0; i < task_count; ++i) {
        futures.push_back(pool.submit([&counter]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            counter.fetch_add(1, std::memory_order_relaxed);
        }));
    }

    for (auto& f : futures) {
        f.get();
    }

    EXPECT_EQ(counter.load(), static_cast<int>(task_count));
}

TEST(ThreadPoolTest, ExceptionPropagationThroughFuture) {
    logscan::ThreadPool pool(2);

    auto fut = pool.submit([]() -> int {
        throw std::runtime_error("Simulated worker error");
    });

    EXPECT_THROW({
        try {
            fut.get();
        } catch (const std::runtime_error& e) {
            EXPECT_STREQ(e.what(), "Simulated worker error");
            throw;
        }
    }, std::runtime_error);
}

TEST(ThreadPoolTest, GracefulShutdownCompletesPendingTasks) {
    std::atomic<int> processed{0};
    const int total_tasks = 50;

    {
        logscan::ThreadPool pool(4);
        for (int i = 0; i < total_tasks; ++i) {
            pool.submit([&processed]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                processed.fetch_add(1, std::memory_order_relaxed);
            });
        }
        // Pool destructor calls shutdown() and joins all threads
    }

    // All queued tasks must have completed
    EXPECT_EQ(processed.load(), total_tasks);
}
