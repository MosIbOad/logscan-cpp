#include "logscan/chunk_splitter.hpp"

#include <numeric>
#include <string>

#include <gtest/gtest.h>

TEST(ChunkSplitterTest, EmptyOrSingleChunk) {
    EXPECT_TRUE(logscan::ChunkSplitter::split("", 4).empty());
    EXPECT_TRUE(logscan::ChunkSplitter::split("data", 0).empty());

    const auto single = logscan::ChunkSplitter::split("single line\n", 1);
    ASSERT_EQ(single.size(), 1u);
    EXPECT_EQ(single[0], "single line\n");
}

TEST(ChunkSplitterTest, SplitAlignsOnNewlineBoundaries) {
    const std::string text =
        "line 1: first log line\n"
        "line 2: second log line\n"
        "line 3: third log line\n"
        "line 4: fourth log line\n"
        "line 5: fifth log line\n"
        "line 6: sixth log line\n";

    const auto chunks = logscan::ChunkSplitter::split(text, 3);
    EXPECT_GE(chunks.size(), 1u);
    EXPECT_LE(chunks.size(), 3u);

    // Reconstructing the text from chunks must be byte-for-byte identical
    std::string reconstructed;
    for (const auto& ch : chunks) {
        // Every chunk except possibly the last one if it has no newline must end with '\n'
        EXPECT_EQ(ch.back(), '\n');
        reconstructed.append(ch);
    }
    EXPECT_EQ(reconstructed, text);
}

TEST(ChunkSplitterTest, TargetChunksExceedsLineCount) {
    const std::string text = "line 1\nline 2\n";
    const auto chunks = logscan::ChunkSplitter::split(text, 10);

    std::string reconstructed;
    for (const auto& ch : chunks) {
        reconstructed.append(ch);
    }
    EXPECT_EQ(reconstructed, text);
}

TEST(ChunkSplitterTest, DataWithoutNewlines) {
    const std::string text = "A very long line without any newline character in it anywhere";
    const auto chunks = logscan::ChunkSplitter::split(text, 4);

    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks[0], text);
}
