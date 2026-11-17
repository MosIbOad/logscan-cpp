#pragma once

#include "logscan/filter.hpp"
#include "logscan/level.hpp"

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace logscan {

struct Options {
    bool collect_matched_lines{true};
};

struct ChunkResult {
    std::vector<std::string_view> matched_lines{};
    std::array<uint64_t, static_cast<size_t>(Level::COUNT)> level_counts{0};
    std::array<uint64_t, static_cast<size_t>(Level::COUNT)> matched_level_counts{0};
    uint64_t total_lines{0};
    uint64_t unparsed_lines{0};
    uint64_t matched_count{0};
};

[[nodiscard]] ChunkResult process_chunk(
    std::string_view chunk,
    const FilterChain& filter_chain,
    const Options& options = Options{}
);

} // namespace logscan
