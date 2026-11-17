add_executable(gen_logs
    gen_logs.cpp
)

target_link_libraries(gen_logs
    PRIVATE
        logscan_core
        logscan_warnings
)
