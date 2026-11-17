#pragma once

#include <cstddef>
#include <filesystem>
#include <string_view>

namespace logscan {

class MappedFile {
public:
    explicit MappedFile(const std::filesystem::path& path);
    ~MappedFile() noexcept;

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    [[nodiscard]] std::string_view view() const noexcept {
        return data_ != nullptr ? std::string_view{data_, size_} : std::string_view{};
    }

    [[nodiscard]] size_t size() const noexcept {
        return size_;
    }

    [[nodiscard]] const char* data() const noexcept {
        return data_;
    }

    [[nodiscard]] bool empty() const noexcept {
        return size_ == 0;
    }

private:
    void cleanup() noexcept;

    const char* data_{nullptr};
    size_t size_{0};

#if defined(_WIN32)
    void* file_handle_{nullptr};    // HANDLE
    void* mapping_handle_{nullptr}; // HANDLE
#else
    int fd_{-1};
#endif
};

} // namespace logscan
