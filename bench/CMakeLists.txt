add_executable(logscan_bench
    main_bench.cpp
)

target_link_libraries(logscan_bench
    PRIVATE
        logscan_core
        logscan_warnings
)

if(WIN32)
    target_link_libraries(logscan_bench
        PRIVATE
            psapi
    )
endif()
