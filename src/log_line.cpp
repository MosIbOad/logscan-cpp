#include "logscan/log_line.hpp"

namespace logscan {

std::optional<Level> parse_level(std::string_view sv) noexcept {
    if (sv == "INFO") {
        return Level::INFO;
    }
    if (sv == "WARN" || sv == "WARNING") {
        return Level::WARN;
    }
    if (sv == "ERROR" || sv == "ERR") {
        return Level::ERROR;
    }
    if (sv == "DEBUG") {
        return Level::DEBUG;
    }
    if (sv == "TRACE") {
        return Level::TRACE;
    }
    if (sv == "FATAL" || sv == "CRITICAL") {
        return Level::FATAL;
    }
    return std::nullopt;
}

LogLine parse_log_line(std::string_view line) noexcept {
    LogLine result;
    result.raw = line;
    result.is_parsed = false;

    if (line.empty() || line.front() != '[') {
        return result;
    }

    // 1. Timestamp: [2026-11-17 14:03:22]
    const size_t close1 = line.find(']', 1);
    if (close1 == std::string_view::npos) {
        return result;
    }
    result.timestamp = line.substr(1, close1 - 1);
    if (result.timestamp.empty()) {
        return result;
    }

    // 2. Level: [ERROR]
    const size_t open2 = line.find('[', close1 + 1);
    if (open2 == std::string_view::npos) {
        return result;
    }
    for (size_t i = close1 + 1; i < open2; ++i) {
        if (line[i] != ' ') {
            return result;
        }
    }
    const size_t close2 = line.find(']', open2 + 1);
    if (close2 == std::string_view::npos) {
        return result;
    }
    result.level_str = line.substr(open2 + 1, close2 - open2 - 1);
    const auto opt_level = parse_level(result.level_str);
    if (!opt_level.has_value()) {
        return result;
    }
    result.level = *opt_level;

    // 3. Source: [Resource:core]
    const size_t open3 = line.find('[', close2 + 1);
    if (open3 == std::string_view::npos) {
        return result;
    }
    for (size_t i = close2 + 1; i < open3; ++i) {
        if (line[i] != ' ') {
            return result;
        }
    }
    const size_t close3 = line.find(']', open3 + 1);
    if (close3 == std::string_view::npos) {
        return result;
    }
    result.source = line.substr(open3 + 1, close3 - open3 - 1);
    if (result.source.empty()) {
        return result;
    }

    // 4. Message: remainder after [Source]
    std::string_view remainder = line.substr(close3 + 1);
    while (!remainder.empty() && remainder.front() == ' ') {
        remainder.remove_prefix(1);
    }
    result.message = remainder;
    result.is_parsed = true;

    return result;
}

} // namespace logscan
