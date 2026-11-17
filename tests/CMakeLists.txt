add_executable(logscan_tests
    test_placeholder.cpp
)

target_link_libraries(logscan_tests
    PRIVATE
        logscan_core
        logscan_warnings
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(logscan_tests)
