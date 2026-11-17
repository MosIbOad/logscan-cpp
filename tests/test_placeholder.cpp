#include <gtest/gtest.h>
#include "logscan/logscan.hpp"

TEST(LogscanCoreTest, VersionCheck) {
    EXPECT_EQ(logscan::version(), "0.1.0");
}
