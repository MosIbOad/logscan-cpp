add_executable(logscan_tests
    test_placeholder.cpp
    mapped_file_test.cpp
    log_line_test.cpp
    filter_test.cpp
    chunk_processor_test.cpp
    thread_pool_test.cpp
    chunk_splitter_test.cpp
    runner_test.cpp
)

target_link_libraries(logscan_tests
    PRIVATE
        logscan_core
        logscan_warnings
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(logscan_tests)
