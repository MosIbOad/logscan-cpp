#include "logscan/mapped_file.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

namespace {

// RAII helper for managing temporary files during testing
class ScopedTempFile {
public:
    explicit ScopedTempFile(const std::string& prefix, const std::string& content = "") {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() /
                ("logscan_test_" + prefix + "_" + std::to_string(now) + ".tmp");

        std::ofstream ofs(path_, std::ios::binary);
        if (!content.empty()) {
            ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        }
        ofs.close();
    }

    ~ScopedTempFile() noexcept {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    ScopedTempFile(const ScopedTempFile&) = delete;
    ScopedTempFile& operator=(const ScopedTempFile&) = delete;

    ScopedTempFile(ScopedTempFile&&) noexcept = default;
    ScopedTempFile& operator=(ScopedTempFile&&) noexcept = default;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

} // namespace

TEST(MappedFileTest, NormalFileRead) {
    const std::string expected = "2026-03-29 10:00:00 [INFO] Server started successfully\n"
                                 "2026-03-29 10:00:01 [WARN] High memory pressure detected\n"
                                 "2026-03-29 10:00:02 [ERROR] Database connection lost\n";

    ScopedTempFile temp_file("normal", expected);

    logscan::MappedFile mapped(temp_file.path());

    EXPECT_FALSE(mapped.empty());
    EXPECT_EQ(mapped.size(), expected.size());
    EXPECT_EQ(mapped.view(), expected);
    EXPECT_NE(mapped.data(), nullptr);
}

TEST(MappedFileTest, EmptyFileHandling) {
    ScopedTempFile temp_file("empty", "");

    EXPECT_NO_THROW({
        logscan::MappedFile mapped(temp_file.path());
        EXPECT_TRUE(mapped.empty());
        EXPECT_EQ(mapped.size(), 0u);
        EXPECT_TRUE(mapped.view().empty());
        EXPECT_EQ(mapped.view(), "");
    });
}

TEST(MappedFileTest, NonExistentFileThrows) {
    const std::filesystem::path non_existent =
        std::filesystem::temp_directory_path() / "logscan_non_existent_file_999999.log";

    // Ensure the file truly doesn't exist
    std::error_code ec;
    std::filesystem::remove(non_existent, ec);

    try {
        logscan::MappedFile mapped(non_existent);
        FAIL() << "Expected std::runtime_error for non-existent file";
    } catch (const std::runtime_error& err) {
        const std::string err_msg = err.what();
        EXPECT_NE(err_msg.find(non_existent.string()), std::string::npos)
            << "Error message should include the file path: " << err_msg;
    }
}

TEST(MappedFileTest, MoveSemantics) {
    const std::string content = "Sample log data for move semantics verification\nLine 2\n";
    ScopedTempFile temp_file("move", content);

    // 1. Move Constructor
    logscan::MappedFile file1(temp_file.path());
    EXPECT_EQ(file1.view(), content);
    EXPECT_EQ(file1.size(), content.size());

    logscan::MappedFile file2(std::move(file1));
    EXPECT_EQ(file2.view(), content);
    EXPECT_EQ(file2.size(), content.size());
    EXPECT_TRUE(file1.empty());
    EXPECT_EQ(file1.size(), 0u);
    EXPECT_TRUE(file1.view().empty());

    // 2. Move Assignment
    ScopedTempFile another_temp("another", "Short string");
    logscan::MappedFile file3(another_temp.path());
    EXPECT_EQ(file3.view(), "Short string");

    file3 = std::move(file2);
    EXPECT_EQ(file3.view(), content);
    EXPECT_EQ(file3.size(), content.size());
    EXPECT_TRUE(file2.empty());
    EXPECT_EQ(file2.size(), 0u);
    EXPECT_TRUE(file2.view().empty());
}
