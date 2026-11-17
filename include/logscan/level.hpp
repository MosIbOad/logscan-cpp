#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace logscan {

enum class Level : uint8_t {
    TRACE = 0,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL,
    COUNT
};

[[nodiscard]] constexpr std::string_view to_string(Level level) noexcept {
    switch (level) {
        case Level::TRACE: return "TRACE";
        case Level::DEBUG: return "DEBUG";
        case Level::INFO:  return "INFO";
        case Level::WARN:  return "WARN";
        case Level::ERROR: return "ERROR";
        case Level::FATAL: return "FATAL";
        default:           return "UNKNOWN";
    }
}

[[nodiscard]] std::optional<Level> parse_level(std::string_view sv) noexcept;

} // namespace logscan
