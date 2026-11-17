#include "logscan/thread_pool.hpp"

namespace logscan {

ThreadPool::ThreadPool(size_t thread_count) {
    if (thread_count == 0) {
        thread_count = 1;
    }

    workers_.reserve(thread_count);
    for (size_t i = 0; i < thread_count; ++i) {
        workers_.emplace_back([this](const std::stop_token& st) {
            worker_loop(st);
        });
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::shutdown() {
    {
        std::scoped_lock lock(mutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
    }

    cv_.notify_all();

    // Joining workers ensures remaining tasks are completely processed
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::worker_loop(const std::stop_token& stop_token) {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [&]() {
                return stopping_ || stop_token.stop_requested() || !tasks_.empty();
            });

            // If stopped or stop requested, finish any remaining tasks before exiting
            if ((stopping_ || stop_token.stop_requested()) && tasks_.empty()) {
                return;
            }

            if (!tasks_.empty()) {
                task = std::move(tasks_.front());
                tasks_.pop();
            }
        }

        if (task) {
            task();
        }
    }
}

} // namespace logscan
