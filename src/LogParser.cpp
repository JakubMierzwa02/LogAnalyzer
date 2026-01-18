#include "LogParser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace LogParser 
{

/**
 * @brief Helper function to trim whitespace from both ends of a string
 * 
 * @param str The string to trim
 * @return A new string with leading and trailing whitespace removed
 */
static std::string trim(const std::string& str) 
{
    // Find first non-whitespace character
    auto start = std::find_if(str.begin(), str.end(), 
                              [](unsigned char ch) { return !std::isspace(ch); });
    
    // Find last non-whitespace character
    auto end = std::find_if(str.rbegin(), str.rend(),
                            [](unsigned char ch) { return !std::isspace(ch); }).base();
    
    // Return substring between first and last non-whitespace
    return (start < end) ? std::string(start, end) : std::string();
}

std::optional<std::chrono::system_clock::time_point> 
parseTimestamp(const std::string& timestamp_str) 
{
    std::tm tm = {};
    std::istringstream ss(timestamp_str);
    
    // Parse the timestamp in format "YYYY-MM-DD HH:MM:SS"
    // %Y = year, %m = month, %d = day, %H = hour, %M = minute, %S = second
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    // Check if parsing was successful
    if (ss.fail()) 
    {
        return std::nullopt;
    }
    
    // Convert std::tm to time_t, then to system_clock::time_point
    std::time_t time = std::mktime(&tm);
    
    // Check if mktime failed (returns -1 on error)
    if (time == -1) 
    {
        return std::nullopt;
    }
    
    return std::chrono::system_clock::from_time_t(time);
}

LoginStatus parseStatus(const std::string& status_str) 
{
    // Create a copy of the string for case-insensitive comparison
    std::string status_upper = status_str;
    
    // Convert to uppercase for comparison
    std::transform(status_upper.begin(), status_upper.end(), 
                   status_upper.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    
    // Check against known status values
    if (status_upper == "SUCCESS") 
    {
        return LoginStatus::SUCCESS;
    } 
    else if (status_upper == "FAILED") 
    {
        return LoginStatus::FAILED;
    } 
    else 
    {
        return LoginStatus::UNKNOWN;
    }
}

std::optional<LogEntry> parseLogLine(const std::string& line) 
{
    // Use stringstream to split the line by '|' delimiter
    std::istringstream ss(line);
    std::string timestamp_str, username, ip_address, status_str;
    
    // Extract the four fields separated by '|'
    // Expected format: TIMESTAMP | USERNAME | IP | STATUS
    if (!std::getline(ss, timestamp_str, '|')) 
    {
        return std::nullopt;  // Failed to read timestamp
    }
    if (!std::getline(ss, username, '|')) 
    {
        return std::nullopt;  // Failed to read username
    }
    if (!std::getline(ss, ip_address, '|')) 
    {
        return std::nullopt;  // Failed to read IP address
    }
    if (!std::getline(ss, status_str)) 
    {
        return std::nullopt;  // Failed to read status
    }
    
    // Trim whitespace from all fields
    timestamp_str = trim(timestamp_str);
    username = trim(username);
    ip_address = trim(ip_address);
    status_str = trim(status_str);
    
    // Validate that no field is empty after trimming
    if (timestamp_str.empty() || username.empty() || 
        ip_address.empty() || status_str.empty()) 
    {
        return std::nullopt;
    }
    
    // Parse the timestamp
    auto timestamp_opt = parseTimestamp(timestamp_str);
    if (!timestamp_opt.has_value()) 
    {
        return std::nullopt;  // Timestamp parsing failed
    }
    
    // Parse the status
    LoginStatus status = parseStatus(status_str);
    
    // Note: We don't reject UNKNOWN status here - we create the entry
    // and let the caller decide how to handle it
    
    // Construct and return the LogEntry
    return LogEntry(timestamp_opt.value(), username, ip_address, status);
}

} // namespace LogParser