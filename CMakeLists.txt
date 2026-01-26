cmake_minimum_required(VERSION 3.14)
project(LogAnalyzer VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.cpp
    src/LogParser.cpp
    src/EventDetector.cpp
    src/ReportGenerator.cpp
    src/ConfigManager.cpp
)

# Main executable
add_executable(log-analyzer ${SOURCES})

# Compiler warnings
if(MSVC)
    target_compile_options(log-analyzer PRIVATE /W4)
else()
    target_compile_options(log-analyzer PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ============================================================================
# Testing with Catch2
# ============================================================================

option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    # Find Catch2
    find_package(Catch2 3 QUIET)
    
    if(NOT Catch2_FOUND)
        # Fallback: Use FetchContent to download Catch2
        include(FetchContent)
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.4.0
        )
        FetchContent_MakeAvailable(Catch2)
    endif()

    # Test source files (without main.cpp)
    set(TEST_SOURCES
        src/LogParser.cpp
        src/EventDetector.cpp
        src/ReportGenerator.cpp
        src/ConfigManager.cpp
    )

    # Test executables
    add_executable(test_LogParser tests/test_LogParser.cpp ${TEST_SOURCES})
    add_executable(test_EventDetector tests/test_EventDetector.cpp ${TEST_SOURCES})
    add_executable(test_ReportGenerator tests/test_ReportGenerator.cpp ${TEST_SOURCES})
    add_executable(test_ConfigManager tests/test_ConfigManager.cpp ${TEST_SOURCES})

    # Link Catch2 to test executables
    target_link_libraries(test_LogParser PRIVATE Catch2::Catch2WithMain)
    target_link_libraries(test_EventDetector PRIVATE Catch2::Catch2WithMain)
    target_link_libraries(test_ReportGenerator PRIVATE Catch2::Catch2WithMain)
    target_link_libraries(test_ConfigManager PRIVATE Catch2::Catch2WithMain)

    # Enable testing
    enable_testing()
    
    # Add tests to CTest
    add_test(NAME LogParserTests COMMAND test_LogParser)
    add_test(NAME EventDetectorTests COMMAND test_EventDetector)
    add_test(NAME ReportGeneratorTests COMMAND test_ReportGenerator)
    add_test(NAME ConfigManagerTests COMMAND test_ConfigManager)
    
    # Optional: Add all tests target
    add_custom_target(run_all_tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS test_LogParser test_EventDetector test_ReportGenerator test_ConfigManager
        COMMENT "Running all unit tests"
    )
endif()

# ============================================================================
# Installation
# ============================================================================

install(TARGETS log-analyzer DESTINATION bin)
install(DIRECTORY logs/ DESTINATION share/log-analyzer/logs)
install(DIRECTORY reports/ DESTINATION share/log-analyzer/reports)

# ============================================================================
# Documentation
# ============================================================================

# Print build information
message(STATUS "")
message(STATUS "Log Analyzer Configuration:")
message(STATUS "  C++ Standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")