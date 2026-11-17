#include "logscan/filter.hpp"

namespace logscan {

TimeRangeFilter TimeRangeFilter::from_strings(
    std::optional<std::string_view> start_str,
    std::optional<std::string_view> end_str
) {
    std::optional<int64_t> start_epoch;
    std::optional<int64_t> end_epoch;

    if (start_str.has_value() && !start_str->empty()) {
        start_epoch = parse_iso8601_timestamp(*start_str);
    }
    if (end_str.has_value() && !end_str->empty()) {
        end_epoch = parse_iso8601_timestamp(*end_str);
    }

    return {start_epoch, end_epoch};
}

} // namespace logscan
