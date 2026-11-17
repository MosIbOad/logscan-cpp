#pragma once

#include "logscan/chunk_processor.hpp"
#include "logscan/chunk_splitter.hpp"
#include "logscan/filter.hpp"
#include "logscan/level.hpp"
#include "logscan/mapped_file.hpp"
#include "logscan/thread_pool.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace logscan {

struct RunResult {
    std::vector<std::string_view> matched_lines{};
    std::array<uint64_t, static_cast<size_t>(Level::COUNT)> level_counts{0};
    std::array<uint64_t, static_cast<size_t>(Level::COUNT)> matched_level_counts{0};
    uint64_t total_lines{0};
    uint64_t unparsed_lines{0};
    uint64_t matched_count{0};
};

class Runner {
public:
    explicit Runner(size_t thread_count = std::max(1u, std::thread::hardware_concurrency()));

    [[nodiscard]] RunResult run(
        const MappedFile& file,
        const FilterChain& filter_chain,
        const Options& options = Options{}
    );

    [[nodiscard]] RunResult run(
        std::string_view content,
        const FilterChain& filter_chain,
        const Options& options = Options{}
    );

    [[nodiscard]] size_t thread_count() const noexcept {
        return pool_.thread_count();
    }

private:
    ThreadPool pool_;
};

} // namespace logscan
