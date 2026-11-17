#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace logscan {

class ThreadPool {
public:
    explicit ThreadPool(size_t thread_count = std::max(1u, std::thread::hardware_concurrency()));
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    template <typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>> {
        using ReturnType = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>;

        auto task = std::make_shared<std::packaged_task<ReturnType()>>(
            [func = std::forward<F>(f), ...captured_args = std::forward<Args>(args)]() mutable {
                return std::invoke(func, captured_args...);
            }
        );

        std::future<ReturnType> fut = task->get_future();
        {
            std::scoped_lock lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("Cannot submit task to stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        cv_.notify_one();
        return fut;
    }

    void shutdown();

    [[nodiscard]] size_t thread_count() const noexcept {
        return workers_.size();
    }

    [[nodiscard]] bool is_stopped() const noexcept {
        std::scoped_lock lock(mutex_);
        return stopping_;
    }

private:
    void worker_loop(const std::stop_token& stop_token);

    std::vector<std::jthread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stopping_{false};
};

} // namespace logscan
