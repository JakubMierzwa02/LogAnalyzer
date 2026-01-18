#ifndef LOG_ENTRY_H
#define LOG_ENTRY_H

#include <string>
#include <chrono>

/**
 * @brief Enumeration representing the status of a login attempt
 * 
 * This enum is used to distinguish between successful and failed
 * authentication attempts in the log files.
 */
enum class LoginStatus 
{
    SUCCESS,  // Successful login attempt
    FAILED,   // Failed login attempt
    UNKNOWN   // Invalid or unparseable status
};

/**
 * @brief Structure representing a single log entry
 * 
 * This structure contains all the information extracted from a single
 * line in the authentication log file. It uses std::chrono for 
 * timestamp handling to enable easy time-based comparisons.
 */
struct LogEntry 
{
    std::chrono::system_clock::time_point timestamp;  // When the event occurred
    std::string username;                              // User attempting login
    std::string ip_address;                            // Source IP address
    LoginStatus status;                                // Success or failure
    
    /**
     * @brief Default constructor
     * 
     * Initializes a LogEntry with default values:
     * - timestamp: current time
     * - username: empty string
     * - ip_address: empty string
     * - status: UNKNOWN
     */
    LogEntry() 
        : timestamp(std::chrono::system_clock::now()),
          username(""),
          ip_address(""),
          status(LoginStatus::UNKNOWN) {}
    
    /**
     * @brief Parameterized constructor
     * 
     * @param ts The timestamp of the log event
     * @param user The username from the log
     * @param ip The IP address from the log
     * @param stat The login status (SUCCESS/FAILED)
     */
    LogEntry(std::chrono::system_clock::time_point ts,
             const std::string& user,
             const std::string& ip,
             LoginStatus stat)
        : timestamp(ts),
          username(user),
          ip_address(ip),
          status(stat) {}
};

#endif // LOG_ENTRY_H