cmake_minimum_required(VERSION 3.20)

project(LogAnalyzer
    VERSION 0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_CLANG_TIDY
    clang-tidy
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ======================
# Main application
# ======================
add_executable(LogAnalyzer
    src/main.cpp
    src/LogParser.cpp
    src/EventDetector.cpp
    src/ReportGenerator.cpp
)

target_include_directories(LogAnalyzer
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
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
    tests/test_LogParser.cpp
    tests/test_EventDetector.cpp
    tests/test_ReportGenerator.cpp
    tests/test_ConfigManager.cpp
    src/LogParser.cpp
    src/EventDetector.cpp
    src/ReportGenerator.cpp
    src/ConfigManager.cpp
)

target_include_directories(LogAnalyzerTests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(LogAnalyzerTests
    Catch2::Catch2WithMain
)

add_test(NAME LogAnalyzerTests COMMAND LogAnalyzerTests)
