add_library(logscan_core STATIC
    mapped_file.cpp
    log_line.cpp
    time_utils.cpp
    filter.cpp
    chunk_processor.cpp
    thread_pool.cpp
    chunk_splitter.cpp
    runner.cpp
)

target_include_directories(logscan_core
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(logscan_core
    PUBLIC
        logscan_warnings
)

add_subdirectory(cli)
