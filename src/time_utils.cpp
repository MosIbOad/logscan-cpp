#include "logscan/time_utils.hpp"

namespace logscan {

namespace {

[[nodiscard]] constexpr bool is_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

// Howard Hinnant's algorithm for converting civil date to days since 1970-01-01 (Unix epoch)
[[nodiscard]] constexpr int64_t days_from_civil(int y, unsigned m, unsigned d) noexcept {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - (era * 400));
    const unsigned doy = (((153 * (m > 2 ? m - 3 : m + 9)) + 2) / 5) + d - 1;
    const unsigned doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy;
    return (era * 146097) + static_cast<int64_t>(doe) - 719468;
}

} // namespace

std::optional<int64_t> parse_iso8601_timestamp(std::string_view sv) noexcept {
    if (sv.size() < 19) {
        return std::nullopt;
    }

    if (!is_digit(sv[0]) || !is_digit(sv[1]) || !is_digit(sv[2]) || !is_digit(sv[3]) ||
        sv[4] != '-' ||
        !is_digit(sv[5]) || !is_digit(sv[6]) ||
        sv[7] != '-' ||
        !is_digit(sv[8]) || !is_digit(sv[9]) ||
        (sv[10] != ' ' && sv[10] != 'T') ||
        !is_digit(sv[11]) || !is_digit(sv[12]) ||
        sv[13] != ':' ||
        !is_digit(sv[14]) || !is_digit(sv[15]) ||
        sv[16] != ':' ||
        !is_digit(sv[17]) || !is_digit(sv[18])) {
        return std::nullopt;
    }

    const int year = ((sv[0] - '0') * 1000) + ((sv[1] - '0') * 100) + ((sv[2] - '0') * 10) + (sv[3] - '0');
    const auto month = static_cast<unsigned>(((sv[5] - '0') * 10) + (sv[6] - '0'));
    const auto day = static_cast<unsigned>(((sv[8] - '0') * 10) + (sv[9] - '0'));

    const int hour = ((sv[11] - '0') * 10) + (sv[12] - '0');
    const int minute = ((sv[14] - '0') * 10) + (sv[15] - '0');
    const int second = ((sv[17] - '0') * 10) + (sv[18] - '0');

    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
        return std::nullopt;
    }

    const int64_t days = days_from_civil(year, month, day);
    const int64_t total_seconds = (days * 86400) +
                                  (static_cast<int64_t>(hour) * 3600) +
                                  (static_cast<int64_t>(minute) * 60) +
                                  static_cast<int64_t>(second);

    return total_seconds;
}

} // namespace logscan
