#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

#if defined(_WIN32)
#define popen_compat _popen
#define pclose_compat _pclose
#else
#define popen_compat popen
#define pclose_compat pclose
#endif

namespace {

struct ExecResult {
    int exit_code{0};
    std::string output{};
};

ExecResult run_cmd(const std::string& cmd) {
    ExecResult res;
    char buffer[256];

    // On Windows, cmd.exe /c requires wrapping the entire command string in an extra
    // pair of double quotes when multiple quoted tokens are used.
#if defined(_WIN32)
    const std::string full_cmd = "\"" + cmd + "\"";
#else
    const std::string full_cmd = cmd;
#endif

    FILE* pipe = popen_compat(full_cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen failed for command: " + cmd);
    }
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        res.output += buffer;
    }
    res.exit_code = pclose_compat(pipe);
    return res;
}

class ScopedCliLogFile {
public:
    explicit ScopedCliLogFile(const std::string& content) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() /
                ("logscan_cli_test_" + std::to_string(now) + ".log");

        std::ofstream ofs(path_, std::ios::binary);
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        ofs.close();
    }

    ~ScopedCliLogFile() noexcept {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

} // namespace

TEST(CliEndToEndTest, HelpAndVersionOptions) {
    const std::string exe = LOGSCAN_CLI_EXE;

    // 1. --help
    const auto help_res = run_cmd("\"" + exe + "\" --help");
    EXPECT_EQ(help_res.exit_code, 0);
    EXPECT_NE(help_res.output.find("Kullanım:"), std::string::npos);

    // 2. --version
    const auto ver_res = run_cmd("\"" + exe + "\" --version");
    EXPECT_EQ(ver_res.exit_code, 0);
    EXPECT_NE(ver_res.output.find("logscan v0.1.0"), std::string::npos);
}

TEST(CliEndToEndTest, FilterContainsAndStreaming) {
    const std::string sample_data =
        "[2026-11-17 10:00:00] [INFO] [Auth] User logged in\n"
        "[2026-11-17 10:00:01] [ERROR] [Database] Connection timeout\n"
        "[2026-11-17 10:00:02] [WARN] [Network] High latency 150ms\n"
        "[2026-11-17 10:00:03] [ERROR] [Database] Connection timeout\n"
        "[2026-11-17 10:00:04] [INFO] [Auth] User logged out\n";

    ScopedCliLogFile log_file(sample_data);
    const std::string exe = LOGSCAN_CLI_EXE;

    const auto res = run_cmd("\"" + exe + "\" \"" + log_file.path().string() + "\" --contains timeout");
    EXPECT_EQ(res.exit_code, 0);

    // Expect the two matching lines to be present in stdout
    EXPECT_NE(res.output.find("[2026-11-17 10:00:01] [ERROR] [Database] Connection timeout"), std::string::npos);
    EXPECT_NE(res.output.find("[2026-11-17 10:00:03] [ERROR] [Database] Connection timeout"), std::string::npos);
    // Non-matching line should NOT be present
    EXPECT_EQ(res.output.find("High latency"), std::string::npos);
}

TEST(CliEndToEndTest, CountOnlyOption) {
    const std::string sample_data =
        "[2026-11-17 10:00:00] [INFO] [Auth] User logged in\n"
        "[2026-11-17 10:00:01] [ERROR] [Database] Connection timeout\n"
        "[2026-11-17 10:00:02] [WARN] [Network] High latency\n"
        "[2026-11-17 10:00:03] [ERROR] [Database] Deadlock detected\n";

    ScopedCliLogFile log_file(sample_data);
    const std::string exe = LOGSCAN_CLI_EXE;

    const auto res = run_cmd("\"" + exe + "\" \"" + log_file.path().string() + "\" --level ERROR --count");
    EXPECT_EQ(res.exit_code, 0);

    // Exactly 2 ERROR lines
    EXPECT_EQ(res.output, "2\n");
}

TEST(CliEndToEndTest, StatsAndTopNOption) {
    const std::string sample_data =
        "[2026-11-17 10:00:00] [INFO] [Auth] Heartbeat\n"
        "[2026-11-17 10:00:01] [ERROR] [DB] Connection timeout\n"
        "[2026-11-17 10:00:02] [ERROR] [DB] Connection timeout\n"
        "[2026-11-17 10:00:03] [ERROR] [DB] Connection timeout\n"
        "[2026-11-17 10:00:04] [WARN] [Disk] Low space\n"
        "[2026-11-17 10:00:05] [WARN] [Disk] Low space\n";

    ScopedCliLogFile log_file(sample_data);
    const std::string exe = LOGSCAN_CLI_EXE;

    const auto res = run_cmd("\"" + exe + "\" \"" + log_file.path().string() + "\" --stats --top 2");
    EXPECT_EQ(res.exit_code, 0);

    // Summary header must be present
    EXPECT_NE(res.output.find("[logscan İstatistik Özeti]"), std::string::npos);
    EXPECT_NE(res.output.find("Toplam Satır     : 6"), std::string::npos);

    // Top-N output
    EXPECT_NE(res.output.find("En Sık Karşılaşılan 2 Mesaj:"), std::string::npos);
    EXPECT_NE(res.output.find("[3 kez] Connection timeout"), std::string::npos);
    EXPECT_NE(res.output.find("[2 kez] Low space"), std::string::npos);
}

TEST(CliEndToEndTest, MissingFileReturnsNonZero) {
    const std::string exe = LOGSCAN_CLI_EXE;
    const std::string missing_path = "non_existent_logscan_test_file_98765.log";

    const auto res = run_cmd("\"" + exe + "\" \"" + missing_path + "\" 2>&1");
    EXPECT_NE(res.exit_code, 0);
    EXPECT_NE(res.output.find("Hata: Dosya açılamadı"), std::string::npos);
}
