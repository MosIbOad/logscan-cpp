#include "logscan/chunk_processor.hpp"

#include <gtest/gtest.h>

TEST(ChunkProcessorTest, ProcessEmptyChunk) {
    logscan::FilterChain chain;
    const logscan::ChunkResult res = logscan::process_chunk("", chain);

    EXPECT_EQ(res.total_lines, 0u);
    EXPECT_EQ(res.matched_count, 0u);
    EXPECT_EQ(res.unparsed_lines, 0u);
    EXPECT_TRUE(res.matched_lines.empty());
}

TEST(ChunkProcessorTest, ProcessMultiLineChunkWithCounts) {
    const std::string chunk =
        "[2026-11-17 10:00:01] [INFO] [App] Starting service\r\n"
        "[2026-11-17 10:00:02] [DEBUG] [Cache] Cache initialized\n"
        "This is an unparsed garbage line\n"
        "[2026-11-17 10:00:03] [WARN] [Network] High latency 120ms\r\n"
        "[2026-11-17 10:00:04] [ERROR] [DB] Query failed timeout\n"
        "[2026-11-17 10:00:05] [FATAL] [Kernel] Out of memory crash\n";

    logscan::FilterChain chain; // Empty chain: matches all lines
    const logscan::ChunkResult res = logscan::process_chunk(chunk, chain);

    EXPECT_EQ(res.total_lines, 6u);
    EXPECT_EQ(res.unparsed_lines, 1u);
    EXPECT_EQ(res.matched_count, 6u); // Empty chain matches all 6 lines (5 parsed + 1 unparsed)
    EXPECT_EQ(res.matched_lines.size(), 6u);

    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::INFO)], 1u);
    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::DEBUG)], 1u);
    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::WARN)], 1u);
    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::ERROR)], 1u);
    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::FATAL)], 1u);
    EXPECT_EQ(res.level_counts[static_cast<size_t>(logscan::Level::TRACE)], 0u);
}

TEST(ChunkProcessorTest, FilterByLevelAndSubstring) {
    const std::string chunk =
        "[2026-11-17 10:00:01] [INFO] [App] User logged in\n"
        "[2026-11-17 10:00:02] [ERROR] [DB] Connection timeout\n"
        "[2026-11-17 10:00:03] [ERROR] [Auth] Invalid token\n"
        "[2026-11-17 10:00:04] [WARN] [DB] Slow query\n";

    logscan::FilterChain chain;
    chain.emplace_filter<logscan::LevelFilter>(logscan::Level::ERROR);
    chain.emplace_filter<logscan::SubstringFilter>("timeout");

    const logscan::ChunkResult res = logscan::process_chunk(chunk, chain);

    EXPECT_EQ(res.total_lines, 4u);
    EXPECT_EQ(res.unparsed_lines, 0u);
    EXPECT_EQ(res.matched_count, 1u);
    ASSERT_EQ(res.matched_lines.size(), 1u);
    EXPECT_EQ(res.matched_lines[0], "[2026-11-17 10:00:02] [ERROR] [DB] Connection timeout");
}

TEST(ChunkProcessorTest, CollectLinesDisabledForAnalysisMode) {
    const std::string chunk =
        "[2026-11-17 10:00:01] [INFO] [App] Item 1\n"
        "[2026-11-17 10:00:02] [INFO] [App] Item 2\n";

    logscan::FilterChain chain;
    logscan::Options options;
    options.collect_matched_lines = false;

    const logscan::ChunkResult res = logscan::process_chunk(chunk, chain, options);

    EXPECT_EQ(res.total_lines, 2u);
    EXPECT_EQ(res.matched_count, 2u);
    EXPECT_TRUE(res.matched_lines.empty()); // Vector not populated to save RAM
    EXPECT_EQ(res.matched_level_counts[static_cast<size_t>(logscan::Level::INFO)], 2u);
}
