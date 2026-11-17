add_executable(logscan_bench
    bench_placeholder.cpp
)

target_link_libraries(logscan_bench
    PRIVATE
        logscan_core
        logscan_warnings
)
