#ifndef EVENT_DETECTOR_H
#define EVENT_DETECTOR_H

#include "LogEntry.h"
#include <vector>
#include <string>
#include <chrono>

/**
 * @brief Enumeration of different types of suspicious activities
 * 
 * Each enum value represents a specific security pattern or anomaly
 * that can be detected in authentication logs.
 */
enum class SuspiciousEventType 
{
    MULTIPLE_FAILED_LOGINS,      // Brute-force attack indicator
    LOGIN_OUTSIDE_BUSINESS_HOURS, // After-hours access
    MULTIPLE_IP_ADDRESSES         // Account compromise indicator
};

/**
 * @brief Structure representing a detected suspicious event
 * 
 * This structure contains all relevant information about a security
 * anomaly detected during log analysis. It provides context for
 * reporting and further investigation.
 */
struct SuspiciousEvent 
{
    SuspiciousEventType type;                              // Type of anomaly detected
    std::string username;                                   // User involved in the event
    std::vector<std::string> ip_addresses;                  // Related IP address(es)
    std::chrono::system_clock::time_point first_occurrence; // When pattern started
    std::chrono::system_clock::time_point last_occurrence;  // When pattern ended
    int event_count;                                        // Number of related events
    std::string description;                                // Human-readable description
    
    /**
     * @brief Default constructor
     * 
     * Initializes a SuspiciousEvent with default values.
     */
    SuspiciousEvent()
        : type(SuspiciousEventType::MULTIPLE_FAILED_LOGINS),
          username(""),
          ip_addresses(),
          first_occurrence(std::chrono::system_clock::now()),
          last_occurrence(std::chrono::system_clock::now()),
          event_count(0),
          description("") {}
    
    /**
     * @brief Parameterized constructor
     * 
     * @param evt_type Type of suspicious event
     * @param user The username involved
     * @param ip The IP address (will be added to ip_addresses vector)
     * @param first_time Timestamp of first event in pattern
     * @param last_time Timestamp of last event in pattern
     * @param count Number of events in the pattern
     */
    SuspiciousEvent(SuspiciousEventType evt_type,
                   const std::string& user,
                   const std::string& ip,
                   std::chrono::system_clock::time_point first_time,
                   std::chrono::system_clock::time_point last_time,
                   int count)
        : type(evt_type),
          username(user),
          ip_addresses({ip}),
          first_occurrence(first_time),
          last_occurrence(last_time),
          event_count(count),
          description("") {}
};

/**
 * @brief Class responsible for detecting suspicious events in authentication logs
 * 
 * This class analyzes collections of log entries and identifies security-relevant
 * patterns such as brute-force attacks, after-hours access, and potential
 * account compromise indicators.
 * 
 * Detection capabilities:
 * - Multiple failed login attempts (brute-force indicators)
 * - Logins outside defined business hours
 * - Logins from multiple IP addresses in short time windows
 */
class EventDetector 
{
public:
    /**
     * @brief Constructor with default configuration
     * 
     * Initializes the detector with default thresholds:
     * - Failed login threshold: 5 attempts
     * - Time window: 10 minutes
     * - Business hours: 08:00 to 18:00
     */
    EventDetector();
    
    /**
     * @brief Constructor with custom configuration
     * 
     * @param failed_login_threshold Minimum failed attempts to trigger detection
     * @param time_window_minutes Time window for counting events (in minutes)
     * @param business_hour_start Start of business hours (0-23)
     * @param business_hour_end End of business hours (0-23)
     */
    EventDetector(int failed_login_threshold,
                  int time_window_minutes,
                  int business_hour_start,
                  int business_hour_end);
    
    /**
     * @brief Detects multiple failed login attempts for users
     * 
     * Analyzes log entries to identify patterns consistent with brute-force
     * password attacks. Groups failed login attempts by username and detects
     * clusters that exceed the configured threshold within the time window.
     * 
     * Algorithm:
     * 1. Filter entries to only FAILED status
     * 2. Group by username
     * 3. Sort by timestamp
     * 4. Use sliding window to find clusters
     * 5. Report clusters >= threshold
     * 
     * @param entries Vector of log entries to analyze
     * @return Vector of SuspiciousEvent objects for detected attacks
     */
    std::vector<SuspiciousEvent> detectMultipleFailedLogins(
        const std::vector<LogEntry>& entries) const;
    
    /**
     * @brief Detects successful logins outside business hours
     * 
     * Identifies successful authentication events that occur outside the
     * configured business hours, which may indicate unauthorized access
     * or policy violations.
     * 
     * @param entries Vector of log entries to analyze
     * @return Vector of SuspiciousEvent objects for after-hours logins
     * 
     * @note Only considers entries with LoginStatus::SUCCESS
     * @note Business hours are defined by business_hour_start_ and business_hour_end_
     */
    std::vector<SuspiciousEvent> detectLoginsOutsideBusinessHours(
        const std::vector<LogEntry>& entries) const;
    
    /**
     * @brief Detects logins from multiple IP addresses for the same user
     * 
     * Identifies cases where a single user account authenticates from
     * multiple distinct IP addresses within a short time window, which
     * may indicate account compromise or credential sharing.
     * 
     * @param entries Vector of log entries to analyze
     * @return Vector of SuspiciousEvent objects for multiple IP usage
     * 
     * @note Only considers entries with LoginStatus::SUCCESS
     * @note Uses the configured time_window_minutes_ for detection
     */
    std::vector<SuspiciousEvent> detectMultipleIPAddresses(
        const std::vector<LogEntry>& entries) const;
    
    /**
     * @brief Runs all detection methods on the provided log entries
     * 
     * Convenience method that executes all available detection algorithms
     * and returns a combined list of all detected suspicious events.
     * 
     * @param entries Vector of log entries to analyze
     * @return Vector containing all detected suspicious events from all detectors
     */
    std::vector<SuspiciousEvent> detectAll(
        const std::vector<LogEntry>& entries) const;

private:
    /**
     * @brief Helper function to check if two timestamps are within time window
     * 
     * @param time1 First timestamp
     * @param time2 Second timestamp
     * @return true if timestamps are within configured time window
     */
    bool isWithinTimeWindow(
        std::chrono::system_clock::time_point time1,
        std::chrono::system_clock::time_point time2) const;
    
    /**
     * @brief Helper function to extract hour from timestamp
     * 
     * @param timestamp The timestamp to extract hour from
     * @return Hour of day (0-23)
     */
    int getHourOfDay(std::chrono::system_clock::time_point timestamp) const;
    
    // Configuration parameters
    int failed_login_threshold_;    // Minimum failed attempts for detection
    int time_window_minutes_;       // Time window for event clustering
    int business_hour_start_;       // Start of business hours (0-23)
    int business_hour_end_;         // End of business hours (0-23)
};

#endif // EVENT_DETECTOR_H