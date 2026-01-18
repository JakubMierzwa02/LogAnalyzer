#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "LogParser.h"
#include <chrono>

/**
 * Unit tests for LogParser namespace functions
 * 
 * These tests verify the correct parsing of authentication log entries,
 * including timestamp parsing, status conversion, and complete log line parsing.
 */

// ============================================================================
// Tests for parseTimestamp()
// ============================================================================

TEST_CASE("parseTimestamp - Valid timestamp", "[LogParser][parseTimestamp]") 
{
    auto result = LogParser::parseTimestamp("2026-01-18 08:45:12");
    
    // Check that parsing succeeded
    REQUIRE(result.has_value());
    
    // Convert back to tm to verify the parsed values
    std::time_t time = std::chrono::system_clock::to_time_t(result.value());
    std::tm* tm = std::localtime(&time);
    
    REQUIRE(tm->tm_year + 1900 == 2026);
    REQUIRE(tm->tm_mon + 1 == 1);     // tm_mon is 0-based
    REQUIRE(tm->tm_mday == 18);
    REQUIRE(tm->tm_hour == 8);
    REQUIRE(tm->tm_min == 45);
    REQUIRE(tm->tm_sec == 12);
}

TEST_CASE("parseTimestamp - Invalid format missing time", "[LogParser][parseTimestamp]") 
{
    auto result = LogParser::parseTimestamp("2026-01-18");
    
    // Should fail because time portion is missing
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseTimestamp - Invalid format wrong separator", "[LogParser][parseTimestamp]") 
{
    auto result = LogParser::parseTimestamp("2026/01/18 08:45:12");
    
    // Should fail because date uses '/' instead of '-'
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseTimestamp - Empty string", "[LogParser][parseTimestamp]") 
{
    auto result = LogParser::parseTimestamp("");
    
    // Should fail on empty input
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseTimestamp - Completely invalid string", "[LogParser][parseTimestamp]") 
{
    auto result = LogParser::parseTimestamp("not a timestamp");
    
    // Should fail on garbage input
    REQUIRE_FALSE(result.has_value());
}

// ============================================================================
// Tests for parseStatus()
// ============================================================================

TEST_CASE("parseStatus - SUCCESS (uppercase)", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("SUCCESS");
    REQUIRE(status == LoginStatus::SUCCESS);
}

TEST_CASE("parseStatus - FAILED (uppercase)", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("FAILED");
    REQUIRE(status == LoginStatus::FAILED);
}

TEST_CASE("parseStatus - success (lowercase)", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("success");
    
    // Should handle case-insensitive input
    REQUIRE(status == LoginStatus::SUCCESS);
}

TEST_CASE("parseStatus - Failed (mixed case)", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("Failed");
    
    // Should handle case-insensitive input
    REQUIRE(status == LoginStatus::FAILED);
}

TEST_CASE("parseStatus - Unknown status", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("PENDING");
    
    // Should return UNKNOWN for unrecognized status
    REQUIRE(status == LoginStatus::UNKNOWN);
}

TEST_CASE("parseStatus - Empty string", "[LogParser][parseStatus]") 
{
    LoginStatus status = LogParser::parseStatus("");
    
    // Should return UNKNOWN for empty input
    REQUIRE(status == LoginStatus::UNKNOWN);
}

// ============================================================================
// Tests for parseLogLine()
// ============================================================================

TEST_CASE("parseLogLine - Valid log entry with SUCCESS", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-18 08:45:12 | jdoe | 192.168.1.10 | SUCCESS";
    auto result = LogParser::parseLogLine(line);
    
    // Check that parsing succeeded
    REQUIRE(result.has_value());
    
    LogEntry entry = result.value();
    
    // Verify all fields
    REQUIRE(entry.username == "jdoe");
    REQUIRE(entry.ip_address == "192.168.1.10");
    REQUIRE(entry.status == LoginStatus::SUCCESS);
    
    // Verify timestamp
    std::time_t time = std::chrono::system_clock::to_time_t(entry.timestamp);
    std::tm* tm = std::localtime(&time);
    REQUIRE(tm->tm_hour == 8);
    REQUIRE(tm->tm_min == 45);
}

TEST_CASE("parseLogLine - Valid log entry with FAILED", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-15 14:30:00 | admin | 10.0.0.5 | FAILED";
    auto result = LogParser::parseLogLine(line);
    
    REQUIRE(result.has_value());
    
    LogEntry entry = result.value();
    REQUIRE(entry.username == "admin");
    REQUIRE(entry.ip_address == "10.0.0.5");
    REQUIRE(entry.status == LoginStatus::FAILED);
}

TEST_CASE("parseLogLine - Extra whitespace around fields", "[LogParser][parseLogLine]") 
{
    std::string line = "  2026-01-18 08:45:12  |  jdoe  |  192.168.1.10  |  SUCCESS  ";
    auto result = LogParser::parseLogLine(line);
    
    // Should successfully parse and trim whitespace
    REQUIRE(result.has_value());
    
    LogEntry entry = result.value();
    REQUIRE(entry.username == "jdoe");
    REQUIRE(entry.ip_address == "192.168.1.10");
    REQUIRE(entry.status == LoginStatus::SUCCESS);
}

TEST_CASE("parseLogLine - Missing fields (only 3 pipes)", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-18 08:45:12 | jdoe | 192.168.1.10";
    auto result = LogParser::parseLogLine(line);
    
    // Should fail due to missing status field
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseLogLine - Too many fields (extra pipe)", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-18 08:45:12 | jdoe | 192.168.1.10 | SUCCESS | extra";
    auto result = LogParser::parseLogLine(line);
    
    // Should still parse correctly - extra data after status is ignored
    REQUIRE(result.has_value());
}

TEST_CASE("parseLogLine - Empty username field", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-18 08:45:12 |  | 192.168.1.10 | SUCCESS";
    auto result = LogParser::parseLogLine(line);
    
    // Should fail due to empty username after trimming
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseLogLine - Invalid timestamp", "[LogParser][parseLogLine]") 
{
    std::string line = "invalid-timestamp | jdoe | 192.168.1.10 | SUCCESS";
    auto result = LogParser::parseLogLine(line);
    
    // Should fail due to invalid timestamp
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseLogLine - Empty line", "[LogParser][parseLogLine]") 
{
    std::string line = "";
    auto result = LogParser::parseLogLine(line);
    
    // Should fail on empty input
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("parseLogLine - Line with no pipes", "[LogParser][parseLogLine]") 
{
    std::string line = "2026-01-18 08:45:12 jdoe 192.168.1.10 SUCCESS";
    auto result = LogParser::parseLogLine(line);
    
    // Should fail because no pipe delimiters exist
    REQUIRE_FALSE(result.has_value());
}