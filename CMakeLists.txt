cmake_minimum_required(VERSION 3.24)

# Set default build type to Release before project() if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

project(logscan
    VERSION 0.1.0
    DESCRIPTION "High-performance C++20 log file scanner and analyzer"
    LANGUAGES CXX
)

# C++20 standard enforcement
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# User configuration options
option(LOGSCAN_BUILD_TESTS "Build tests with GoogleTest" ON)
option(LOGSCAN_BUILD_BENCH "Build benchmarks" ON)

# Compiler warnings interface target
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)

# Core library & main executable
add_subdirectory(src)

# Testing configuration with GoogleTest via FetchContent
if(LOGSCAN_BUILD_TESTS)
    enable_testing()

    # Provide default configuration for multi-config generators when ctest is called without -C
    file(WRITE "${CMAKE_BINARY_DIR}/default_ctest_config.cmake"
        "if(NOT CTEST_CONFIGURATION_TYPE)\n    set(CTEST_CONFIGURATION_TYPE \"Debug\")\nendif()\n"
    )
    set_property(DIRECTORY PROPERTY TEST_INCLUDE_FILES "${CMAKE_BINARY_DIR}/default_ctest_config.cmake")

    include(FetchContent)
    set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "Don't check for updates on already populated dependencies" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    # Prevent overriding parent project's compiler/linker settings on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_subdirectory(tests)
endif()

# Benchmarks
if(LOGSCAN_BUILD_BENCH)
    add_subdirectory(bench)
endif()
