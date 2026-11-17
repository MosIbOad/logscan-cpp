#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace logscan {

// Fast zero-allocation handwritten ISO8601 parser: "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DDTHH:MM:SS"
[[nodiscard]] std::optional<int64_t> parse_iso8601_timestamp(std::string_view sv) noexcept;

} // namespace logscan
