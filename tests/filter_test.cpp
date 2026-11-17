#include "logscan/filter.hpp"
#include "logscan/log_line.hpp"
#include "logscan/time_utils.hpp"

#include <gtest/gtest.h>

TEST(TimeUtilsTest, ParseIso8601Timestamps) {
    // 1970-01-01 00:00:00 -> 0
    const auto epoch0 = logscan::parse_iso8601_timestamp("1970-01-01 00:00:00");
    ASSERT_TRUE(epoch0.has_value());
    EXPECT_EQ(*epoch0, 0);

    // 1970-01-02 00:00:00 -> 86400
    const auto epoch1 = logscan::parse_iso8601_timestamp("1970-01-02 00:00:00");
    ASSERT_TRUE(epoch1.has_value());
    EXPECT_EQ(*epoch1, 86400);

    // Leap year 2024-02-29 12:00:00
    const auto leap = logscan::parse_iso8601_timestamp("2024-02-29 12:00:00");
    ASSERT_TRUE(leap.has_value());

    // With 'T' separator
    const auto with_t = logscan::parse_iso8601_timestamp("2026-11-17T14:03:22");
    const auto with_space = logscan::parse_iso8601_timestamp("2026-11-17 14:03:22");
    ASSERT_TRUE(with_t.has_value());
    ASSERT_TRUE(with_space.has_value());
    EXPECT_EQ(*with_t, *with_space);

    // Invalid timestamps
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("").has_value());
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("short").has_value());
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("2026-13-01 10:00:00").has_value()); // Invalid month 13
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("2026-11-32 10:00:00").has_value()); // Invalid day 32
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("2026-11-17 25:00:00").has_value()); // Invalid hour 25
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("2026-11-17 10:65:00").has_value()); // Invalid minute 65
    EXPECT_FALSE(logscan::parse_iso8601_timestamp("2026/11/17 10:00:00").has_value()); // Wrong separator
}

TEST(FilterTest, SubstringFilter) {
    const auto line = logscan::parse_log_line("[2026-11-17 14:03:22] [ERROR] [Resource:db] Connection timeout occurred");

    logscan::SubstringFilter f1("timeout");
    EXPECT_TRUE(f1.matches(line));

    logscan::SubstringFilter f2("Resource:db");
    EXPECT_TRUE(f2.matches(line));

    // Message only search
    logscan::SubstringFilter f3("Resource:db", /*search_message_only=*/true);
    EXPECT_FALSE(f3.matches(line));

    logscan::SubstringFilter f4("not_in_line");
    EXPECT_FALSE(f4.matches(line));

    // Substring filter matches on unparsed raw lines as well
    const auto unparsed = logscan::parse_log_line("Malformed raw error with timeout word");
    EXPECT_TRUE(f1.matches(unparsed));
}

TEST(FilterTest, RegexFilter) {
    const auto line = logscan::parse_log_line("[2026-11-17 14:03:22] [ERROR] [Auth] User 10492 failed password");

    logscan::RegexFilter r1("User \\d+ failed");
    EXPECT_TRUE(r1.matches(line));

    logscan::RegexFilter r2("User [a-z]+ failed");
    EXPECT_FALSE(r2.matches(line));

    logscan::RegexFilter r3("^\\[\\d{4}-\\d{2}-\\d{2}");
    EXPECT_TRUE(r3.matches(line));
}

TEST(FilterTest, LevelFilter) {
    const auto trace_line = logscan::parse_log_line("[2026-11-17 14:03:22] [TRACE] [src] t");
    const auto info_line  = logscan::parse_log_line("[2026-11-17 14:03:22] [INFO] [src] i");
    const auto warn_line  = logscan::parse_log_line("[2026-11-17 14:03:22] [WARN] [src] w");
    const auto error_line = logscan::parse_log_line("[2026-11-17 14:03:22] [ERROR] [src] e");
    const auto fatal_line = logscan::parse_log_line("[2026-11-17 14:03:22] [FATAL] [src] f");
    const auto unparsed   = logscan::parse_log_line("Malformed line");

    // Minimum level: >= WARN
    logscan::LevelFilter min_warn(logscan::Level::WARN);
    EXPECT_FALSE(min_warn.matches(trace_line));
    EXPECT_FALSE(min_warn.matches(info_line));
    EXPECT_TRUE(min_warn.matches(warn_line));
    EXPECT_TRUE(min_warn.matches(error_line));
    EXPECT_TRUE(min_warn.matches(fatal_line));
    EXPECT_FALSE(min_warn.matches(unparsed));

    // Specific set: {INFO, FATAL}
    logscan::LevelFilter set_filter({logscan::Level::INFO, logscan::Level::FATAL});
    EXPECT_FALSE(set_filter.matches(trace_line));
    EXPECT_TRUE(set_filter.matches(info_line));
    EXPECT_FALSE(set_filter.matches(warn_line));
    EXPECT_FALSE(set_filter.matches(error_line));
    EXPECT_TRUE(set_filter.matches(fatal_line));
}

TEST(FilterTest, TimeRangeFilter) {
    const auto line1 = logscan::parse_log_line("[2026-11-17 10:00:00] [INFO] [src] t1");
    const auto line2 = logscan::parse_log_line("[2026-11-17 12:00:00] [INFO] [src] t2");
    const auto line3 = logscan::parse_log_line("[2026-11-17 14:00:00] [INFO] [src] t3");
    const auto unparsed = logscan::parse_log_line("Unparsed without timestamp");

    // Range: [11:00:00, 13:00:00]
    auto range_filter = logscan::TimeRangeFilter::from_strings("2026-11-17 11:00:00", "2026-11-17 13:00:00");
    EXPECT_FALSE(range_filter.matches(line1));
    EXPECT_TRUE(range_filter.matches(line2));
    EXPECT_FALSE(range_filter.matches(line3));
    EXPECT_FALSE(range_filter.matches(unparsed));

    // Range with exact boundary match
    auto exact_filter = logscan::TimeRangeFilter::from_strings("2026-11-17 12:00:00", "2026-11-17 12:00:00");
    EXPECT_FALSE(exact_filter.matches(line1));
    EXPECT_TRUE(exact_filter.matches(line2));
    EXPECT_FALSE(exact_filter.matches(line3));

    // Start only (since >= 12:00:00)
    auto since_filter = logscan::TimeRangeFilter::from_strings("2026-11-17 12:00:00", std::nullopt);
    EXPECT_FALSE(since_filter.matches(line1));
    EXPECT_TRUE(since_filter.matches(line2));
    EXPECT_TRUE(since_filter.matches(line3));

    // End only (until <= 12:00:00)
    auto until_filter = logscan::TimeRangeFilter::from_strings(std::nullopt, "2026-11-17 12:00:00");
    EXPECT_TRUE(until_filter.matches(line1));
    EXPECT_TRUE(until_filter.matches(line2));
    EXPECT_FALSE(until_filter.matches(line3));
}

TEST(FilterTest, FilterChainAndLogic) {
    const auto match_line = logscan::parse_log_line("[2026-11-17 12:30:00] [ERROR] [Database] Connection timeout");
    const auto wrong_level = logscan::parse_log_line("[2026-11-17 12:30:00] [INFO] [Database] Connection timeout");
    const auto wrong_time  = logscan::parse_log_line("[2026-11-17 19:30:00] [ERROR] [Database] Connection timeout");
    const auto wrong_msg   = logscan::parse_log_line("[2026-11-17 12:30:00] [ERROR] [Database] Everything fine");

    logscan::FilterChain chain;
    chain.emplace_filter<logscan::LevelFilter>(logscan::Level::ERROR);
    chain.emplace_filter<logscan::SubstringFilter>("timeout");
    chain.emplace_filter<logscan::TimeRangeFilter>(
        logscan::TimeRangeFilter::from_strings("2026-11-17 10:00:00", "2026-11-17 15:00:00")
    );

    EXPECT_TRUE(chain.matches(match_line));
    EXPECT_FALSE(chain.matches(wrong_level));
    EXPECT_FALSE(chain.matches(wrong_time));
    EXPECT_FALSE(chain.matches(wrong_msg));

    // Empty chain matches all
    logscan::FilterChain empty_chain;
    EXPECT_TRUE(empty_chain.matches(match_line));
    EXPECT_TRUE(empty_chain.matches(wrong_level));
}
