cmake_minimum_required(VERSION 3.20)

project(LogAnalyzer
    VERSION 0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ======================
# Main executable
# ======================
add_executable(LogAnalyzer
    src/main.cpp
)

# ======================
# Catch2 (FetchContent)
# ======================
include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.4
)

FetchContent_MakeAvailable(Catch2)

# ======================
# Tests
# ======================
enable_testing()

add_executable(LogAnalyzerTests
    tests/test_basic.cpp
)

target_link_libraries(LogAnalyzerTests
    Catch2::Catch2WithMain
)

add_test(NAME BasicTests COMMAND LogAnalyzerTests)
