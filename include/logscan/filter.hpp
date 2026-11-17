#pragma once

#include "logscan/log_line.hpp"
#include "logscan/time_utils.hpp"

#include <initializer_list>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace logscan {

class Filter {
public:
    virtual ~Filter() = default;
    [[nodiscard]] virtual bool matches(const LogLine& line) const = 0;
};

class SubstringFilter : public Filter {
public:
    explicit SubstringFilter(std::string needle, bool search_message_only = false)
        : needle_(std::move(needle)), search_message_only_(search_message_only) {}

    [[nodiscard]] bool matches(const LogLine& line) const override {
        const std::string_view target = search_message_only_ ? line.message : line.raw;
        return target.find(needle_) != std::string_view::npos;
    }

    [[nodiscard]] const std::string& needle() const noexcept {
        return needle_;
    }

    [[nodiscard]] bool search_message_only() const noexcept {
        return search_message_only_;
    }

private:
    std::string needle_;
    bool search_message_only_{false};
};

class RegexFilter : public Filter {
public:
    explicit RegexFilter(std::string pattern, bool search_message_only = false)
        : regex_(pattern), pattern_(std::move(pattern)), search_message_only_(search_message_only) {}

    [[nodiscard]] bool matches(const LogLine& line) const override {
        const std::string_view target = search_message_only_ ? line.message : line.raw;
        return std::regex_search(target.begin(), target.end(), regex_);
    }

    [[nodiscard]] const std::string& pattern() const noexcept {
        return pattern_;
    }

    [[nodiscard]] bool search_message_only() const noexcept {
        return search_message_only_;
    }

private:
    std::regex regex_;
    std::string pattern_;
    bool search_message_only_{false};
};

class LevelFilter : public Filter {
public:
    explicit LevelFilter(Level min_level)
        : min_level_(min_level), use_mask_(false) {}

    LevelFilter(std::initializer_list<Level> levels)
        : use_mask_(true) {
        for (const auto l : levels) {
            mask_ |= (1u << static_cast<size_t>(l));
        }
    }

    explicit LevelFilter(const std::vector<Level>& levels)
        : use_mask_(true) {
        for (const auto l : levels) {
            mask_ |= (1u << static_cast<size_t>(l));
        }
    }

    [[nodiscard]] bool matches(const LogLine& line) const override {
        if (!line.is_parsed) {
            return false;
        }
        if (use_mask_) {
            return (mask_ & (1u << static_cast<size_t>(line.level))) != 0;
        }
        return static_cast<size_t>(line.level) >= static_cast<size_t>(min_level_);
    }

    [[nodiscard]] bool is_using_mask() const noexcept {
        return use_mask_;
    }

    [[nodiscard]] Level min_level() const noexcept {
        return min_level_;
    }

private:
    Level min_level_{Level::TRACE};
    uint32_t mask_{0};
    bool use_mask_{false};
};

class TimeRangeFilter : public Filter {
public:
    TimeRangeFilter(std::optional<int64_t> start_epoch, std::optional<int64_t> end_epoch)
        : start_epoch_(start_epoch), end_epoch_(end_epoch) {}

    static TimeRangeFilter from_strings(
        std::optional<std::string_view> start_str,
        std::optional<std::string_view> end_str
    );

    [[nodiscard]] bool matches(const LogLine& line) const override {
        if (!line.is_parsed) {
            return false;
        }
        const auto epoch_opt = parse_iso8601_timestamp(line.timestamp);
        if (!epoch_opt.has_value()) {
            return false;
        }
        const int64_t t = *epoch_opt;
        if (start_epoch_.has_value() && t < *start_epoch_) {
            return false;
        }
        if (end_epoch_.has_value() && t > *end_epoch_) {
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<int64_t> start_epoch() const noexcept {
        return start_epoch_;
    }

    [[nodiscard]] std::optional<int64_t> end_epoch() const noexcept {
        return end_epoch_;
    }

private:
    std::optional<int64_t> start_epoch_;
    std::optional<int64_t> end_epoch_;
};

class FilterChain {
public:
    FilterChain() = default;

    void add_filter(std::unique_ptr<Filter> filter) {
        if (filter) {
            filters_.push_back(std::move(filter));
        }
    }

    template <typename T, typename... Args>
    void emplace_filter(Args&&... args) {
        filters_.push_back(std::make_unique<T>(std::forward<Args>(args)...));
    }

    [[nodiscard]] bool matches(const LogLine& line) const {
        for (const auto& filter : filters_) {
            if (!filter->matches(line)) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool empty() const noexcept {
        return filters_.empty();
    }

    [[nodiscard]] size_t size() const noexcept {
        return filters_.size();
    }

    void clear() noexcept {
        filters_.clear();
    }

private:
    std::vector<std::unique_ptr<Filter>> filters_;
};

} // namespace logscan
