#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include "EventDetector.h"
#include "LogEntry.h"
#include <string>
#include <vector>
#include <ostream>

/**
 * @brief Class responsible for generating security analysis reports
 * 
 * This class takes log entries and detected suspicious events and generates
 * formatted reports in plain text format. Reports include summary statistics,
 * detailed information about detected anomalies, and relevant context.
 * 
 * Report sections:
 * - Header with generation timestamp
 * - Summary statistics (total entries, suspicious events)
 * - Detailed list of detected anomalies with context
 * - Footer
 */
class ReportGenerator 
{
public:
    /**
     * @brief Default constructor
     */
    ReportGenerator();
    
    /**
     * @brief Generates a complete security report
     * 
     * Creates a formatted report containing summary statistics and details
     * of all detected suspicious events. The report is written to the
     * provided output stream.
     * 
     * @param log_entries All log entries that were analyzed
     * @param suspicious_events Detected suspicious events
     * @param output Output stream to write the report to
     * 
     * @note If log_entries is empty, generates a warning report
     * @note If no suspicious events detected, reports "No anomalies found"
     */
    void generateReport(const std::vector<LogEntry>& log_entries,
                       const std::vector<SuspiciousEvent>& suspicious_events,
                       std::ostream& output) const;
    
    /**
     * @brief Generates a report and saves it to a file
     * 
     * Convenience method that creates a report and writes it directly
     * to a file at the specified path.
     * 
     * @param log_entries All log entries that were analyzed
     * @param suspicious_events Detected suspicious events
     * @param output_filepath Path where the report file should be saved
     * @return true if report was successfully written, false on error
     * 
     * @note Creates parent directories if they don't exist
     * @note Overwrites existing file at output_filepath
     */
    bool generateReportToFile(const std::vector<LogEntry>& log_entries,
                             const std::vector<SuspiciousEvent>& suspicious_events,
                             const std::string& output_filepath) const;

private:
    /**
     * @brief Generates the report header section
     * 
     * Creates a header with title and timestamp of report generation.
     * 
     * @param output Output stream to write header to
     */
    void generateHeader(std::ostream& output) const;
    
    /**
     * @brief Generates summary statistics section
     * 
     * Creates a summary containing:
     * - Total number of log entries processed
     * - Number of successful logins
     * - Number of failed logins
     * - Number of suspicious events detected
     * 
     * @param log_entries All log entries analyzed
     * @param suspicious_events Detected suspicious events
     * @param output Output stream to write summary to
     */
    void generateSummary(const std::vector<LogEntry>& log_entries,
                        const std::vector<SuspiciousEvent>& suspicious_events,
                        std::ostream& output) const;
    
    /**
     * @brief Generates detailed anomalies section
     * 
     * Creates detailed descriptions of each detected suspicious event,
     * including type, username, IP addresses, timestamps, and context.
     * 
     * @param suspicious_events Detected suspicious events to detail
     * @param output Output stream to write details to
     */
    void generateAnomaliesDetails(const std::vector<SuspiciousEvent>& suspicious_events,
                                 std::ostream& output) const;
    
    /**
     * @brief Generates the report footer section
     * 
     * Creates a simple footer marking the end of the report.
     * 
     * @param output Output stream to write footer to
     */
    void generateFooter(std::ostream& output) const;
    
    /**
     * @brief Converts SuspiciousEventType enum to human-readable string
     * 
     * @param type The event type to convert
     * @return String representation of the event type
     */
    std::string eventTypeToString(SuspiciousEventType type) const;
    
    /**
     * @brief Formats a timestamp as a readable string
     * 
     * Converts a time_point to format: "YYYY-MM-DD HH:MM:SS"
     * 
     * @param timestamp The timestamp to format
     * @return Formatted timestamp string
     */
    std::string formatTimestamp(std::chrono::system_clock::time_point timestamp) const;
};

#endif // REPORT_GENERATOR_H