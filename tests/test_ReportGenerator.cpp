#include <catch2/catch_test_macros.hpp>
#include "ReportGenerator.h"
#include "EventDetector.h"
#include "LogEntry.h"
#include <sstream>
#include <fstream>
#include <chrono>

/**
 * Unit tests for ReportGenerator class
 * 
 * These tests verify correct report generation including:
 * - Headers and footers
 * - Summary statistics
 * - Anomaly details
 * - File output
 * - Edge cases (empty logs, no anomalies)
 */

/**
 * Helper function to create a timestamp for testing
 */
std::chrono::system_clock::time_point createTestTimestamp(int hour, int minute) 
{
    std::tm tm = {};
    tm.tm_year = 2026 - 1900;
    tm.tm_mon = 0;  // January
    tm.tm_mday = 18;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = 0;
    
    std::time_t time = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(time);
}

// ============================================================================
// Tests for report generation to stream
// ============================================================================

TEST_CASE("ReportGenerator - Generate report with no entries", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    std::vector<LogEntry> entries;
    std::vector<SuspiciousEvent> events;
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check that report contains header
    REQUIRE(report.find("LOG ANALYZER SECURITY REPORT") != std::string::npos);
    
    // Check that report contains warning about empty log
    REQUIRE(report.find("WARNING") != std::string::npos);
    REQUIRE(report.find("No log entries") != std::string::npos);
    
    // Check that report contains footer
    REQUIRE(report.find("END OF REPORT") != std::string::npos);
}

TEST_CASE("ReportGenerator - Generate report with entries but no anomalies", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTestTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTestTimestamp(11, 0), "bob", "192.168.1.2", LoginStatus::SUCCESS),
        LogEntry(createTestTimestamp(12, 0), "charlie", "192.168.1.3", LoginStatus::FAILED)
    };
    
    std::vector<SuspiciousEvent> events;
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check summary statistics
    REQUIRE(report.find("Total Log Entries: 3") != std::string::npos);
    REQUIRE(report.find("Successful Logins: 2") != std::string::npos);
    REQUIRE(report.find("Failed Logins: 1") != std::string::npos);
    REQUIRE(report.find("Suspicious Events Detected: 0") != std::string::npos);
    
    // Check anomalies section
    REQUIRE(report.find("No anomalies detected") != std::string::npos);
}

TEST_CASE("ReportGenerator - Generate report with one suspicious event", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTestTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTestTimestamp(10, 1), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTestTimestamp(10, 2), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTestTimestamp(10, 3), "alice", "192.168.1.1", LoginStatus::FAILED),
        LogEntry(createTestTimestamp(10, 4), "alice", "192.168.1.1", LoginStatus::FAILED)
    };
    
    SuspiciousEvent event(
        SuspiciousEventType::MULTIPLE_FAILED_LOGINS,
        "alice",
        "192.168.1.1",
        createTestTimestamp(10, 0),
        createTestTimestamp(10, 4),
        5
    );
    event.description = "User 'alice' had 5 failed login attempts within 10 minutes";
    
    std::vector<SuspiciousEvent> events = { event };
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check that event is reported
    REQUIRE(report.find("Suspicious Events Detected: 1") != std::string::npos);
    REQUIRE(report.find("Multiple Failed Login Attempts") != std::string::npos);
    REQUIRE(report.find("Username: alice") != std::string::npos);
    REQUIRE(report.find("192.168.1.1") != std::string::npos);
    REQUIRE(report.find("Event Count: 5") != std::string::npos);
    REQUIRE(report.find("5 failed login attempts") != std::string::npos);
}

TEST_CASE("ReportGenerator - Report shows multiple event types", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTestTimestamp(22, 0), "bob", "10.0.0.1", LoginStatus::SUCCESS)
    };
    
    SuspiciousEvent event1(
        SuspiciousEventType::MULTIPLE_FAILED_LOGINS,
        "alice",
        "192.168.1.1",
        createTestTimestamp(10, 0),
        createTestTimestamp(10, 4),
        5
    );
    
    SuspiciousEvent event2(
        SuspiciousEventType::LOGIN_OUTSIDE_BUSINESS_HOURS,
        "bob",
        "10.0.0.1",
        createTestTimestamp(22, 0),
        createTestTimestamp(22, 0),
        1
    );
    
    std::vector<SuspiciousEvent> events = { event1, event2 };
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check both event types are mentioned
    REQUIRE(report.find("Multiple Failed Login Attempts") != std::string::npos);
    REQUIRE(report.find("Login Outside Business Hours") != std::string::npos);
    
    // Check event numbering
    REQUIRE(report.find("[1]") != std::string::npos);
    REQUIRE(report.find("[2]") != std::string::npos);
}

TEST_CASE("ReportGenerator - Report shows multiple IP addresses correctly", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries;
    
    SuspiciousEvent event(
        SuspiciousEventType::MULTIPLE_IP_ADDRESSES,
        "charlie",
        "",  // Will be overwritten
        createTestTimestamp(14, 0),
        createTestTimestamp(14, 8),
        3
    );
    event.ip_addresses = {"192.168.1.1", "10.0.0.1", "172.16.0.1"};
    event.description = "User 'charlie' logged in from 3 different IP addresses within 10 minutes";
    
    std::vector<SuspiciousEvent> events = { event };
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check that event type is shown
    REQUIRE(report.find("Multiple IP Addresses") != std::string::npos);
    
    // Check that all IP addresses are listed
    REQUIRE(report.find("192.168.1.1") != std::string::npos);
    REQUIRE(report.find("10.0.0.1") != std::string::npos);
    REQUIRE(report.find("172.16.0.1") != std::string::npos);
    
    // Check username
    REQUIRE(report.find("Username: charlie") != std::string::npos);
}

TEST_CASE("ReportGenerator - Report includes timestamps", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries;
    
    SuspiciousEvent event(
        SuspiciousEventType::MULTIPLE_FAILED_LOGINS,
        "alice",
        "192.168.1.1",
        createTestTimestamp(10, 30),
        createTestTimestamp(10, 35),
        5
    );
    
    std::vector<SuspiciousEvent> events = { event };
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check that timestamps are included
    REQUIRE(report.find("First Occurrence:") != std::string::npos);
    REQUIRE(report.find("Last Occurrence:") != std::string::npos);
    
    // Check timestamp format (should contain date and time)
    REQUIRE(report.find("2026-01-18") != std::string::npos);
    REQUIRE(report.find("10:30") != std::string::npos);
    REQUIRE(report.find("10:35") != std::string::npos);
}

TEST_CASE("ReportGenerator - Report header includes generation time", "[ReportGenerator][generateReport]") 
{
    ReportGenerator generator;
    std::vector<LogEntry> entries;
    std::vector<SuspiciousEvent> events;
    std::ostringstream output;
    
    generator.generateReport(entries, events, output);
    
    std::string report = output.str();
    
    // Check that header includes "Report Generated:"
    REQUIRE(report.find("Report Generated:") != std::string::npos);
    
    // Check that it contains a timestamp (basic check for year format)
    REQUIRE(report.find("202") != std::string::npos);
}

// ============================================================================
// Tests for file output
// ============================================================================

TEST_CASE("ReportGenerator - Generate report to file successfully", "[ReportGenerator][generateReportToFile]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTestTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS)
    };
    
    std::vector<SuspiciousEvent> events;
    
    std::string test_file = "test_report.txt";
    
    // Generate report to file
    bool success = generator.generateReportToFile(entries, events, test_file);
    
    REQUIRE(success);
    
    // Verify file was created
    std::ifstream file(test_file);
    REQUIRE(file.is_open());
    
    // Read file contents
    std::string line;
    std::ostringstream file_contents;
    while (std::getline(file, line)) 
    {
        file_contents << line << "\n";
    }
    file.close();
    
    std::string report = file_contents.str();
    
    // Verify report content
    REQUIRE(report.find("LOG ANALYZER SECURITY REPORT") != std::string::npos);
    REQUIRE(report.find("Total Log Entries: 1") != std::string::npos);
    
    // Clean up
    std::remove(test_file.c_str());
}

TEST_CASE("ReportGenerator - Generate report to invalid path fails gracefully", "[ReportGenerator][generateReportToFile]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries;
    std::vector<SuspiciousEvent> events;
    
    // Try to write to invalid path (directory that doesn't exist)
    std::string invalid_path = "/invalid/path/that/does/not/exist/report.txt";
    
    bool success = generator.generateReportToFile(entries, events, invalid_path);
    
    // Should return false for invalid path
    REQUIRE_FALSE(success);
}

TEST_CASE("ReportGenerator - File report matches stream report", "[ReportGenerator][generateReportToFile]") 
{
    ReportGenerator generator;
    
    std::vector<LogEntry> entries = 
    {
        LogEntry(createTestTimestamp(10, 0), "alice", "192.168.1.1", LoginStatus::SUCCESS),
        LogEntry(createTestTimestamp(11, 0), "bob", "192.168.1.2", LoginStatus::FAILED)
    };
    
    std::vector<SuspiciousEvent> events;
    
    // Generate to stream
    std::ostringstream stream_output;
    generator.generateReport(entries, events, stream_output);
    std::string stream_report = stream_output.str();
    
    // Generate to file
    std::string test_file = "test_report_compare.txt";
    generator.generateReportToFile(entries, events, test_file);
    
    // Read file
    std::ifstream file(test_file);
    std::ostringstream file_output;
    std::string line;
    while (std::getline(file, line)) 
    {
        file_output << line << "\n";
    }
    file.close();
    std::string file_report = file_output.str();
    
    // Both reports should be identical
    REQUIRE(stream_report == file_report);
    
    // Clean up
    std::remove(test_file.c_str());
}