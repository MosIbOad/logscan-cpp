#include "logscan/runner.hpp"
#include "logscan/filter.hpp"
#include "logscan/mapped_file.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

namespace {

// Helper to generate a deterministic synthetic log dataset
std::string generate_synthetic_log(size_t num_lines) {
    std::ostringstream oss;
    const char* levels[] = {"INFO", "WARN", "ERROR", "DEBUG", "FATAL"};

    for (size_t i = 0; i < num_lines; ++i) {
        if (i % 25 == 0) {
            // Introduce occasional unparsed / broken lines
            oss << "MALFORMED_LINE_AT_INDEX_" << i << "\n";
            continue;
        }

        const char* lvl = levels[i % 5];
        const int sec = static_cast<int>(i % 60);
        const int min = static_cast<int>((i / 60) % 60);
        const int hour = static_cast<int>((i / 3600) % 24);

        char time_buf[32];
        std::snprintf(time_buf, sizeof(time_buf), "2026-11-17 %02d:%02d:%02d", hour, min, sec);

        oss << "[" << time_buf << "] [" << lvl << "] [Module:" << (i % 10) << "] ";
        if (i % 3 == 0) {
            oss << "Connection timeout on port " << (8000 + i % 100) << "\n";
        } else if (i % 3 == 1) {
            oss << "User session authenticated client_id=" << i << "\n";
        } else {
            oss << "Cache lookup completed in " << (i % 15) << "ms\n";
        }
    }

    return oss.str();
}

// Custom throwing filter to test exception propagation in Runner
class ThrowingFilter : public logscan::Filter {
public:
    [[nodiscard]] bool matches(const logscan::LogLine& line) const override {
        if (line.raw.find("TRIGGER_ERROR") != std::string_view::npos) {
            throw std::runtime_error("Triggered test exception in filter");
        }
        return true;
    }
};

} // namespace

TEST(RunnerTest, DeterministicResultsAcrossThreadCounts) {
    // Generate 1200 log lines to ensure oversubscription creates plenty of chunks
    const std::string log_data = generate_synthetic_log(1200);

    // Filter by WARN or ERROR level and containing "timeout"
    logscan::FilterChain filter_chain;
    filter_chain.emplace_filter<logscan::LevelFilter>(logscan::Level::WARN);
    filter_chain.emplace_filter<logscan::SubstringFilter>("timeout");

    logscan::Runner runner1(1);
    logscan::Runner runner2(2);
    logscan::Runner runner8(8);

    const logscan::RunResult res1 = runner1.run(log_data, filter_chain);
    const logscan::RunResult res2 = runner2.run(log_data, filter_chain);
    const logscan::RunResult res8 = runner8.run(log_data, filter_chain);

    // 1. Total lines and unparsed lines must match exactly
    EXPECT_GT(res1.total_lines, 0u);
    EXPECT_EQ(res1.total_lines, res2.total_lines);
    EXPECT_EQ(res1.total_lines, res8.total_lines);

    EXPECT_GT(res1.unparsed_lines, 0u);
    EXPECT_EQ(res1.unparsed_lines, res2.unparsed_lines);
    EXPECT_EQ(res1.unparsed_lines, res8.unparsed_lines);

    // 2. Matched line counts must match
    EXPECT_GT(res1.matched_count, 0u);
    EXPECT_EQ(res1.matched_count, res2.matched_count);
    EXPECT_EQ(res1.matched_count, res8.matched_count);

    // 3. Level counts must match across all threads
    for (size_t l = 0; l < static_cast<size_t>(logscan::Level::COUNT); ++l) {
        EXPECT_EQ(res1.level_counts[l], res2.level_counts[l]);
        EXPECT_EQ(res1.level_counts[l], res8.level_counts[l]);

        EXPECT_EQ(res1.matched_level_counts[l], res2.matched_level_counts[l]);
        EXPECT_EQ(res1.matched_level_counts[l], res8.matched_level_counts[l]);
    }

    // 4. Critical: Matched lines must be in the EXACT SAME ORIGINAL ORDER
    ASSERT_EQ(res1.matched_lines.size(), res2.matched_lines.size());
    ASSERT_EQ(res1.matched_lines.size(), res8.matched_lines.size());

    for (size_t i = 0; i < res1.matched_lines.size(); ++i) {
        ASSERT_EQ(res1.matched_lines[i], res2.matched_lines[i])
            << "Order mismatch between thread=1 and thread=2 at line " << i;
        ASSERT_EQ(res1.matched_lines[i], res8.matched_lines[i])
            << "Order mismatch between thread=1 and thread=8 at line " << i;
    }
}

TEST(RunnerTest, RunWithMappedFile) {
    const std::string log_data = generate_synthetic_log(300);

    const auto temp_path = std::filesystem::temp_directory_path() /
                           ("logscan_runner_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".tmp");

    {
        std::ofstream ofs(temp_path, std::ios::binary);
        ofs.write(log_data.data(), static_cast<std::streamsize>(log_data.size()));
    }

    logscan::MappedFile mapped_file(temp_path);
    logscan::FilterChain chain;
    chain.emplace_filter<logscan::SubstringFilter>("authenticated");

    logscan::Runner runner(4);
    const logscan::RunResult res = runner.run(mapped_file, chain);

    EXPECT_GT(res.matched_count, 0u);
    EXPECT_EQ(res.total_lines, 300u);

    std::error_code ec;
    std::filesystem::remove(temp_path, ec);
}

TEST(RunnerTest, ExceptionPropagationInWorkerTask) {
    const std::string log_data =
        "[2026-11-17 10:00:00] [INFO] [App] Normal line 1\n"
        "[2026-11-17 10:00:01] [INFO] [App] TRIGGER_ERROR here\n"
        "[2026-11-17 10:00:02] [INFO] [App] Normal line 3\n";

    logscan::FilterChain chain;
    chain.emplace_filter<ThrowingFilter>();

    logscan::Runner runner(2);

    EXPECT_THROW({
        try {
            (void)runner.run(log_data, chain);
        } catch (const std::runtime_error& err) {
            const std::string msg = err.what();
            EXPECT_NE(msg.find("Triggered test exception in filter"), std::string::npos);
            EXPECT_NE(msg.find("Error processing chunk"), std::string::npos);
            throw;
        }
    }, std::runtime_error);
}
