#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include "LogEntry.h"
#include <string>
#include <optional>
#include <chrono>

/**
 * @brief Namespace containing log parsing utilities
 * 
 * This namespace provides functions for parsing authentication log
 * files and converting raw string data into structured LogEntry objects.
 */
namespace LogParser 
{

/**
 * @brief Parses a timestamp string into a time_point object
 * 
 * Expected format: "YYYY-MM-DD HH:MM:SS"
 * Example: "2026-01-10 08:45:12"
 * 
 * @param timestamp_str The timestamp string to parse
 * @return std::optional containing the parsed time_point, or empty if parsing failed
 * 
 * @note This function uses std::tm for parsing and converts to system_clock::time_point
 * @note Returns std::nullopt if the string format is invalid
 */
std::optional<std::chrono::system_clock::time_point> 
parseTimestamp(const std::string& timestamp_str);

/**
 * @brief Converts a status string to LoginStatus enum
 * 
 * Accepts case-insensitive variants of "SUCCESS" and "FAILED"
 * 
 * @param status_str The status string to convert (e.g., "SUCCESS", "FAILED")
 * @return LoginStatus enum value (SUCCESS, FAILED, or UNKNOWN)
 * 
 * @note Returns LoginStatus::UNKNOWN for any unrecognized status string
 */
LoginStatus parseStatus(const std::string& status_str);

/**
 * @brief Parses a single log line into a LogEntry object
 * 
 * Expected format: "YYYY-MM-DD HH:MM:SS | USERNAME | IP_ADDRESS | STATUS"
 * Example: "2026-01-10 08:45:12 | jdoe | 192.168.1.10 | FAILED"
 * 
 * @param line The log line to parse
 * @return std::optional containing the parsed LogEntry, or empty if parsing failed
 * 
 * @note The function trims whitespace around each field
 * @note Returns std::nullopt if:
 *       - The line doesn't contain exactly 4 pipe-separated fields
 *       - The timestamp cannot be parsed
 *       - Any required field is empty
 */
std::optional<LogEntry> parseLogLine(const std::string& line);

} // namespace LogParser

#endif // LOG_PARSER_H