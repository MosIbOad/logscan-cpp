#pragma once

#include "logscan/level.hpp"

#include <string_view>

namespace logscan {

struct LogLine {
    std::string_view raw{};
    std::string_view timestamp{};
    std::string_view level_str{};
    std::string_view source{};
    std::string_view message{};
    Level level{Level::INFO};
    bool is_parsed{false};
};

[[nodiscard]] LogLine parse_log_line(std::string_view line) noexcept;

} // namespace logscan
