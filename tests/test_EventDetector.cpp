#include <catch2/catch_test_macros.hpp>
#include "EventDetector.h"
#include "LogEntry.h"
#include <chrono>
#include <vector>

/**
 * Unit tests for EventDetector class
 * 
 * These tests verify all detection capabilities:
 * - Multiple failed login attempts (brute-force)
 * - Logins outside business hours
 * - Multiple IP addresses for same user
 */

/**
 * Helper function to create a timestamp with specific date and time
 * Base: 2026-01-18
 */
std::chrono::system_clock::time_point createTimestamp(int hour, int minute) 
{
    std::tm tm = {};
    tm.tm_year = 2026 - 1900;
    tm.tm_mon = 0;
    tm.tm_mday = 18;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = 0;
    
    std::time_t time = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(time);
}

// ============================================================================
// Tests for detectMultipleFailedLogins()
// ============================================================================

TEST_CASE("EventDetector - Default constructor values", "[EventDetector][constructor]") 
{
    EventDetector detector;
    
    // Test that default values work by running detection
    std::vector<LogEntry> entries = {
        LogEntry(createTimestamp(8, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 4), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 6), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 8), "alice", "192.168.1.1", LoginStatus::FAILED)
    };
    
    // Should detect with default threshold of 5
    auto results = detector.detectMultipleFailedLogins(entries);
    REQUIRE(results.size() == 1);
}

TEST_CASE("EventDetector - Custom threshold", "[EventDetector][constructor]") 
{
    // Custom detector with threshold of 3
    EventDetector detector(3, 10, 8, 18);
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(8, 0), "bob", "10.0.0.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 2), "bob", "10.0.0.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(8, 4), "bob", "10.0.0.1", LoginStatus::FAILED)
    };
    
    // Should detect with threshold of 3
    auto results = detector.detectMultipleFailedLogins(entries);
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].event_count == 3);
}

TEST_CASE("EventDetector - Multiple failed logins detected", "[EventDetector][detectMultipleFailedLogins]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 1), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 3), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 5), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 7), "alice", "192.168.1.1", LoginStatus::FAILED)
    };
    
    auto results = detector.detectMultipleFailedLogins(entries);
    
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].username == "alice");
    REQUIRE(results[0].event_count == 6);
    REQUIRE(results[0].type == SuspiciousEventType::MULTIPLE_FAILED_LOGINS);
    REQUIRE_FALSE(results[0].description.empty());
}

TEST_CASE("EventDetector - No detection below threshold", "[EventDetector][detectMultipleFailedLogins]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 4), "alice", "192.168.1.1", LoginStatus::FAILED)
    };
    
    // Only 3 failed attempts, default threshold is 5
    auto results = detector.detectMultipleFailedLogins(entries);
    REQUIRE(results.empty());
}

TEST_CASE("EventDetector - Ignores successful logins in failed count", "[EventDetector][detectMultipleFailedLogins]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 1), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 3), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 4), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 5), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 6), "alice", "192.168.1.1", LoginStatus::FAILED)
    };
    
    // Only 5 failed logins, should be detected
    auto results = detector.detectMultipleFailedLogins(entries);
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].event_count == 5);
}

// ============================================================================
// Tests for detectLoginsOutsideBusinessHours()
// ============================================================================

TEST_CASE("EventDetector - Login during business hours not detected", "[EventDetector][detectLoginsOutsideBusinessHours]") 
{
    EventDetector detector;  // Default: 8-18
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 30), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(14, 0), "bob", "192.168.1.2", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(17, 59), "charlie", "192.168.1.3", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectLoginsOutsideBusinessHours(entries);
    REQUIRE(results.empty());
}

TEST_CASE("EventDetector - Login before business hours detected", "[EventDetector][detectLoginsOutsideBusinessHours]") 
{
    EventDetector detector;  // Default: 8-18
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(7, 30), "alice", "192.168.1.1", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectLoginsOutsideBusinessHours(entries);
    
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].username == "alice");
    REQUIRE(results[0].type == SuspiciousEventType::LOGIN_OUTSIDE_BUSINESS_HOURS);
    REQUIRE_FALSE(results[0].description.empty());
}

TEST_CASE("EventDetector - Login after business hours detected", "[EventDetector][detectLoginsOutsideBusinessHours]") 
{
    EventDetector detector;  // Default: 8-18
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(18, 0), "bob", "192.168.1.2", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(22, 15), "charlie", "192.168.1.3", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectLoginsOutsideBusinessHours(entries);
    
    // Both should be detected (18:00 is outside [8, 18))
    REQUIRE(results.size() == 2);
}

TEST_CASE("EventDetector - Only successful logins checked for business hours", "[EventDetector][detectLoginsOutsideBusinessHours]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(3, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(23, 0), "bob", "192.168.1.2", LoginStatus::FAILED),
        LogEntry(createTimestamp(22, 0), "charlie", "192.168.1.3", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectLoginsOutsideBusinessHours(entries);
    
    // Only the successful login should be detected
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].username == "charlie");
}

TEST_CASE("EventDetector - Custom business hours", "[EventDetector][detectLoginsOutsideBusinessHours]") 
{
    // Business hours: 9-17
    EventDetector detector(5, 10, 9, 17);
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(8, 30), "alice", "192.168.1.1", LoginStatus::SUCCESS),  // Before
        LogEntry(createTimestamp(12, 0), "bob", "192.168.1.2", LoginStatus::SUCCESS),    // During
        LogEntry(createTimestamp(17, 0), "charlie", "192.168.1.3", LoginStatus::SUCCESS) // After
    };
    
    auto results = detector.detectLoginsOutsideBusinessHours(entries);
    
    // Should detect alice (8:30) and charlie (17:00)
    REQUIRE(results.size() == 2);
}

// ============================================================================
// Tests for detectMultipleIPAddresses()
// ============================================================================

TEST_CASE("EventDetector - Single IP not detected", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 5), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 8), "alice", "192.168.1.1", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectMultipleIPAddresses(entries);
    REQUIRE(results.empty());
}

TEST_CASE("EventDetector - Multiple IPs within time window detected", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 5), "alice", "10.0.0.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 8), "alice", "172.16.0.1", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectMultipleIPAddresses(entries);
    
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].username == "alice");
    REQUIRE(results[0].type == SuspiciousEventType::MULTIPLE_IP_ADDRESSES);
    REQUIRE(results[0].ip_addresses.size() == 3);
    REQUIRE(results[0].event_count == 3);
}

TEST_CASE("EventDetector - Two IPs detected", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "bob", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 3), "bob", "10.0.0.1", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectMultipleIPAddresses(entries);
    
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].event_count == 2);
    
    // Verify both IPs are in the list
    REQUIRE(std::find(results[0].ip_addresses.begin(), 
                     results[0].ip_addresses.end(), 
                     "192.168.1.1") != results[0].ip_addresses.end());
    REQUIRE(std::find(results[0].ip_addresses.begin(), 
                     results[0].ip_addresses.end(), 
                     "10.0.0.1") != results[0].ip_addresses.end());
}

TEST_CASE("EventDetector - Multiple IPs outside time window not detected", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;  // Default: 10-minute window
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 15), "alice", "10.0.0.1", LoginStatus::SUCCESS)
    };
    
    // 15 minutes apart, outside 10-minute window
    auto results = detector.detectMultipleIPAddresses(entries);
    REQUIRE(results.empty());
}

TEST_CASE("EventDetector - Only successful logins checked for multiple IPs", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 2), "alice", "10.0.0.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 4), "alice", "172.16.0.1", LoginStatus::FAILED)
    };
    
    // Only one successful login, so no detection
    auto results = detector.detectMultipleIPAddresses(entries);
    REQUIRE(results.empty());
}

TEST_CASE("EventDetector - Different users don't interfere", "[EventDetector][detectMultipleIPAddresses]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 2), "bob", "10.0.0.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(10, 4), "alice", "10.0.0.5", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectMultipleIPAddresses(entries);
    
    // Should detect alice with 2 IPs
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].username == "alice");
}

// ============================================================================
// Tests for detectAll()
// ============================================================================

TEST_CASE("EventDetector - detectAll combines all detections", "[EventDetector][detectAll]") 
{
    EventDetector detector;
    
    std::vector<LogEntry> entries = 
    {
        // Multiple failed logins
        LogEntry(createTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 1), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 3), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTimestamp(10, 4), "alice", "192.168.1.1", LoginStatus::FAILED),
        
        // Login outside business hours
        LogEntry(createTimestamp(22, 0), "bob", "10.0.0.1", LoginStatus::SUCCESS),
        
        // Multiple IPs
        LogEntry(createTimestamp(14, 0), "charlie", "172.16.0.1", LoginStatus::SUCCESS),
        LogEntry(createTimestamp(14, 5), "charlie", "172.16.0.2", LoginStatus::SUCCESS)
    };
    
    auto results = detector.detectAll(entries);
    
    // Should detect all three types of suspicious events
    REQUIRE(results.size() == 3);
    
    // Count each type
    int failed_login_count = 0;
    int outside_hours_count = 0;
    int multiple_ip_count = 0;
    
    for (const auto& event : results) 
    {
        if (event.type == SuspiciousEventType::MULTIPLE_FAILED_LOGINS) 
        {
            failed_login_count++;
        } 
        else if (event.type == SuspiciousEventType::LOGIN_OUTSIDE_BUSINESS_HOURS) 
        {
            outside_hours_count++;
        } 
        else if (event.type == SuspiciousEventType::MULTIPLE_IP_ADDRESSES)
        {
            multiple_ip_count++;
        }
    }
    
    REQUIRE(failed_login_count == 1);
    REQUIRE(outside_hours_count == 1);
    REQUIRE(multiple_ip_count == 1);
}

TEST_CASE("EventDetector - detectAll on empty entries", "[EventDetector][detectAll]") 
{
    EventDetector detector;
    std::vector<LogEntry> entries;
    
    auto results = detector.detectAll(entries);
    REQUIRE(results.empty());
}