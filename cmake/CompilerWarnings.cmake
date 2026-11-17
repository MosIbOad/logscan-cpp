# Compiler warnings configuration for logscan
include_guard(GLOBAL)

add_library(logscan_warnings INTERFACE)

target_compile_options(logscan_warnings INTERFACE
    $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
    >
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4
        /permissive-
        /EHsc
    >
)
