add_executable(logscan
    main.cpp
)

target_link_libraries(logscan
    PRIVATE
        logscan_core
        logscan_warnings
)
