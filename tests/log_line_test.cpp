#include "logscan/log_line.hpp"

#include <gtest/gtest.h>

TEST(LogLineTest, ParseValidStandardLine) {
    const std::string_view line = "[2026-11-17 14:03:22] [ERROR] [Resource:core] Mesaj metni burada";
    const logscan::LogLine parsed = logscan::parse_log_line(line);

    EXPECT_TRUE(parsed.is_parsed);
    EXPECT_EQ(parsed.raw, line);
    EXPECT_EQ(parsed.timestamp, "2026-11-17 14:03:22");
    EXPECT_EQ(parsed.level_str, "ERROR");
    EXPECT_EQ(parsed.level, logscan::Level::ERROR);
    EXPECT_EQ(parsed.source, "Resource:core");
    EXPECT_EQ(parsed.message, "Mesaj metni burada");

    // Zero-copy verification: string_view pointers must reside within the input buffer
    EXPECT_GE(parsed.timestamp.data(), line.data());
    EXPECT_LE(parsed.timestamp.data() + parsed.timestamp.size(), line.data() + line.size());
    EXPECT_GE(parsed.message.data(), line.data());
    EXPECT_LE(parsed.message.data() + parsed.message.size(), line.data() + line.size());
}

TEST(LogLineTest, ParseAllLogLevelsAndAliases) {
    struct TestCase {
        std::string_view level_str;
        logscan::Level expected;
    };

    const TestCase cases[] = {
        {"TRACE", logscan::Level::TRACE},
        {"DEBUG", logscan::Level::DEBUG},
        {"INFO", logscan::Level::INFO},
        {"WARN", logscan::Level::WARN},
        {"WARNING", logscan::Level::WARN},
        {"ERROR", logscan::Level::ERROR},
        {"ERR", logscan::Level::ERROR},
        {"FATAL", logscan::Level::FATAL},
        {"CRITICAL", logscan::Level::FATAL},
    };

    for (const auto& c : cases) {
        std::string line = std::string("[2026-11-17 14:03:22] [") + std::string(c.level_str) + "] [src] msg";
        const logscan::LogLine parsed = logscan::parse_log_line(line);
        EXPECT_TRUE(parsed.is_parsed) << "Failed for level: " << c.level_str;
        EXPECT_EQ(parsed.level, c.expected) << "Failed for level: " << c.level_str;
        EXPECT_EQ(parsed.level_str, c.level_str);
    }
}

TEST(LogLineTest, ParseEmptyMessage) {
    const std::string_view line = "[2026-11-17 14:03:22] [INFO] [Kernel]";
    const logscan::LogLine parsed = logscan::parse_log_line(line);

    EXPECT_TRUE(parsed.is_parsed);
    EXPECT_EQ(parsed.timestamp, "2026-11-17 14:03:22");
    EXPECT_EQ(parsed.level, logscan::Level::INFO);
    EXPECT_EQ(parsed.source, "Kernel");
    EXPECT_TRUE(parsed.message.empty());
}

TEST(LogLineTest, ParseExtraSpacingBetweenBrackets) {
    const std::string_view line = "[2026-11-17 14:03:22]    [WARN]   [Security]  Multiple failed attempts";
    const logscan::LogLine parsed = logscan::parse_log_line(line);

    EXPECT_TRUE(parsed.is_parsed);
    EXPECT_EQ(parsed.timestamp, "2026-11-17 14:03:22");
    EXPECT_EQ(parsed.level, logscan::Level::WARN);
    EXPECT_EQ(parsed.source, "Security");
    EXPECT_EQ(parsed.message, "Multiple failed attempts");
}

TEST(LogLineTest, MalformedLinesDoNotCrash) {
    const std::string_view broken_cases[] = {
        "",
        "Plain text without any brackets",
        "[2026-11-17 14:03:22",
        "2026-11-17 14:03:22] [INFO] [src] msg",
        "[2026-11-17 14:03:22] [INVALID_LEVEL] [src] msg",
        "[2026-11-17 14:03:22] [INFO]",
        "[2026-11-17 14:03:22] [INFO] src msg",
        "[] [] []",
        "[2026-11-17 14:03:22]random_chars[INFO] [src] msg",
        "[2026-11-17 14:03:22] [INFO]random_chars[src] msg",
    };

    for (const auto& b : broken_cases) {
        const logscan::LogLine parsed = logscan::parse_log_line(b);
        EXPECT_FALSE(parsed.is_parsed) << "Expected failure for: " << b;
        EXPECT_EQ(parsed.raw, b);
    }
}
