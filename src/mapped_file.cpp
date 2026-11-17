#include "logscan/mapped_file.hpp"

#include <stdexcept>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace logscan {

namespace {

#if defined(_WIN32)
std::string format_windows_error(const std::string& context, DWORD error_code) {
    LPWSTR message_buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message_buffer),
        0,
        nullptr
    );

    std::string result = context + " (Error " + std::to_string(error_code) + ": ";
    if (size > 0 && message_buffer != nullptr) {
        const int utf8_len = WideCharToMultiByte(
            CP_UTF8,
            0,
            message_buffer,
            static_cast<int>(size),
            nullptr,
            0,
            nullptr,
            nullptr
        );
        if (utf8_len > 0) {
            std::string utf8_msg(static_cast<size_t>(utf8_len), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                message_buffer,
                static_cast<int>(size),
                utf8_msg.data(),
                utf8_len,
                nullptr,
                nullptr
            );
            while (!utf8_msg.empty() &&
                   (utf8_msg.back() == '\r' || utf8_msg.back() == '\n' || utf8_msg.back() == ' ')) {
                utf8_msg.pop_back();
            }
            result += utf8_msg;
        } else {
            result += "Unknown error";
        }
        LocalFree(message_buffer);
    } else {
        result += "Unknown error";
    }
    result += ")";
    return result;
}
#else
std::string format_posix_error(const std::string& context, int err) {
    return context + " (Error " + std::to_string(err) + ": " + std::strerror(err) + ")";
}
#endif

} // namespace

MappedFile::MappedFile(const std::filesystem::path& path) {
#if defined(_WIN32)
    const std::wstring wide_path = path.wstring();
    HANDLE file_handle = CreateFileW(
        wide_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file_handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        throw std::runtime_error(format_windows_error("Failed to open file: " + path.string(), err));
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle, &file_size)) {
        const DWORD err = GetLastError();
        CloseHandle(file_handle);
        throw std::runtime_error(format_windows_error("Failed to query file size: " + path.string(), err));
    }

    if (file_size.QuadPart < 0) {
        CloseHandle(file_handle);
        throw std::runtime_error("Invalid negative file size for: " + path.string());
    }

    // Handle empty file (0 bytes) as special case without creating mapping
    if (file_size.QuadPart == 0) {
        CloseHandle(file_handle);
        data_ = nullptr;
        size_ = 0;
        file_handle_ = nullptr;
        mapping_handle_ = nullptr;
        return;
    }

    const auto total_size = static_cast<size_t>(file_size.QuadPart);

    // 0 for maximum size means the mapping size matches the file size
    HANDLE mapping_handle = CreateFileMappingW(
        file_handle,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr
    );

    if (mapping_handle == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(file_handle);
        throw std::runtime_error(format_windows_error("Failed to create file mapping: " + path.string(), err));
    }

    void* mapped_ptr = MapViewOfFile(
        mapping_handle,
        FILE_MAP_READ,
        0,
        0,
        0 // 0 means entire file
    );

    if (mapped_ptr == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        throw std::runtime_error(format_windows_error("Failed to map view of file: " + path.string(), err));
    }

    data_ = static_cast<const char*>(mapped_ptr);
    size_ = total_size;
    file_handle_ = file_handle;
    mapping_handle_ = mapping_handle;

#else
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        const int err = errno;
        throw std::runtime_error(format_posix_error("Failed to open file: " + path.string(), err));
    }

    struct stat st {};
    if (::fstat(fd, &st) == -1) {
        const int err = errno;
        ::close(fd);
        throw std::runtime_error(format_posix_error("Failed to stat file: " + path.string(), err));
    }

    // Handle empty file (0 bytes) as special case
    if (st.st_size == 0) {
        ::close(fd);
        data_ = nullptr;
        size_ = 0;
        fd_ = -1;
        return;
    }

    const auto total_size = static_cast<size_t>(st.st_size);
    void* ptr = ::mmap(nullptr, total_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        const int err = errno;
        ::close(fd);
        throw std::runtime_error(format_posix_error("Failed to mmap file: " + path.string(), err));
    }

#if defined(__linux__) && defined(MADV_SEQUENTIAL)
    ::madvise(ptr, total_size, MADV_SEQUENTIAL);
#endif

    data_ = static_cast<const char*>(ptr);
    size_ = total_size;
    fd_ = fd;
#endif
}

MappedFile::~MappedFile() noexcept {
    cleanup();
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : data_(other.data_),
      size_(other.size_)
#if defined(_WIN32)
    , file_handle_(other.file_handle_),
      mapping_handle_(other.mapping_handle_)
#else
    , fd_(other.fd_)
#endif
{
    other.data_ = nullptr;
    other.size_ = 0;
#if defined(_WIN32)
    other.file_handle_ = nullptr;
    other.mapping_handle_ = nullptr;
#else
    other.fd_ = -1;
#endif
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        cleanup();

        data_ = other.data_;
        size_ = other.size_;
#if defined(_WIN32)
        file_handle_ = other.file_handle_;
        mapping_handle_ = other.mapping_handle_;
        other.file_handle_ = nullptr;
        other.mapping_handle_ = nullptr;
#else
        fd_ = other.fd_;
        other.fd_ = -1;
#endif
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void MappedFile::cleanup() noexcept {
#if defined(_WIN32)
    if (data_ != nullptr) {
        UnmapViewOfFile(data_);
        data_ = nullptr;
    }
    if (mapping_handle_ != nullptr) {
        CloseHandle(reinterpret_cast<HANDLE>(mapping_handle_));
        mapping_handle_ = nullptr;
    }
    if (file_handle_ != nullptr && file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(reinterpret_cast<HANDLE>(file_handle_));
        file_handle_ = nullptr;
    }
#else
    if (data_ != nullptr) {
        ::munmap(const_cast<char*>(data_), size_);
        data_ = nullptr;
    }
    if (fd_ != -1) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
    size_ = 0;
}

} // namespace logscan
