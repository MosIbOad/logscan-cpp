#pragma once

#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

namespace logscan {

class FastWriter {
public:
    explicit FastWriter(FILE* stream = stdout, size_t buffer_size = 256 * 1024)
        : stream_(stream), capacity_(buffer_size) {
        buffer_.resize(capacity_);
    }

    ~FastWriter() noexcept {
        flush();
    }

    FastWriter(const FastWriter&) = delete;
    FastWriter& operator=(const FastWriter&) = delete;
    FastWriter(FastWriter&&) noexcept = default;
    FastWriter& operator=(FastWriter&&) noexcept = default;

    void write_line(std::string_view line) {
        const size_t total_len = line.size() + 1; // +1 for '\n'
        if (pos_ + total_len > capacity_) {
            flush();
            if (total_len > capacity_) {
                // If the line is larger than the entire buffer, write directly
                std::fwrite(line.data(), 1, line.size(), stream_);
                std::fwrite("\n", 1, 1, stream_);
                return;
            }
        }

        std::memcpy(buffer_.data() + pos_, line.data(), line.size());
        pos_ += line.size();
        buffer_[pos_++] = '\n';
    }

    void write_str(std::string_view text) {
        if (pos_ + text.size() > capacity_) {
            flush();
            if (text.size() > capacity_) {
                std::fwrite(text.data(), 1, text.size(), stream_);
                return;
            }
        }

        std::memcpy(buffer_.data() + pos_, text.data(), text.size());
        pos_ += text.size();
    }

    void flush() noexcept {
        if (pos_ > 0 && stream_ != nullptr) {
            std::fwrite(buffer_.data(), 1, pos_, stream_);
            pos_ = 0;
        }
    }

private:
    FILE* stream_;
    size_t capacity_;
    size_t pos_{0};
    std::vector<char> buffer_;
};

} // namespace logscan
