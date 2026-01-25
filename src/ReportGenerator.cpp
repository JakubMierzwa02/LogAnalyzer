#include "ReportGenerator.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>

// ============================================================================
// Constructor
// ============================================================================

ReportGenerator::ReportGenerator()
{
}

// ============================================================================
// Public Methods
// ============================================================================

void ReportGenerator::generateReport(
    const std::vector<LogEntry>& log_entries,
    const std::vector<SuspiciousEvent>& suspicious_events,
    std::ostream& output) const
{
    // Generate report header
    generateHeader(output);
    
    // Generate summary statistics
    generateSummary(log_entries, suspicious_events, output);
    
    // Generate detailed anomalies section
    generateAnomaliesDetails(suspicious_events, output);
    
    // Generate footer
    generateFooter(output);
}

bool ReportGenerator::generateReportToFile(
    const std::vector<LogEntry>& log_entries,
    const std::vector<SuspiciousEvent>& suspicious_events,
    const std::string& output_filepath) const
{
    // Open output file for writing
    std::ofstream file(output_filepath);
    
    // Check if file was opened successfully
    if (!file.is_open()) 
    {
        return false;
    }
    
    // Generate report to the file stream
    generateReport(log_entries, suspicious_events, file);
    
    // Close file
    file.close();
    
    return true;
}

// ============================================================================
// Private Helper Methods
// ============================================================================

void ReportGenerator::generateHeader(std::ostream& output) const
{
    output << "========================================\n";
    output << "   LOG ANALYZER SECURITY REPORT\n";
    output << "========================================\n";
    
    // Add current timestamp
    auto now = std::chrono::system_clock::now();
    output << "Report Generated: " << formatTimestamp(now) << "\n";
    output << "========================================\n\n";
}

void ReportGenerator::generateSummary(
    const std::vector<LogEntry>& log_entries,
    const std::vector<SuspiciousEvent>& suspicious_events,
    std::ostream& output) const
{
    output << "SUMMARY STATISTICS\n";
    output << "----------------------------------------\n";
    
    // Handle empty log case
    if (log_entries.empty()) 
    {
        output << "WARNING: No log entries were processed.\n";
        output << "The log file may be empty or invalid.\n\n";
        return;
    }
    
    // Count successful and failed logins
    int total_entries = static_cast<int>(log_entries.size());
    int successful_logins = 0;
    int failed_logins = 0;
    
    for (const auto& entry : log_entries) 
    {
        if (entry.status == LoginStatus::SUCCESS) 
        {
            successful_logins++;
        } 
        else if (entry.status == LoginStatus::FAILED) 
        {
            failed_logins++;
        }
    }
    
    // Output statistics
    output << "Total Log Entries: " << total_entries << "\n";
    output << "Successful Logins: " << successful_logins << "\n";
    output << "Failed Logins: " << failed_logins << "\n";
    output << "Suspicious Events Detected: " << suspicious_events.size() << "\n";
    output << "\n";
}

void ReportGenerator::generateAnomaliesDetails(
    const std::vector<SuspiciousEvent>& suspicious_events,
    std::ostream& output) const
{
    output << "DETECTED ANOMALIES\n";
    output << "----------------------------------------\n";
    
    // Handle case with no suspicious events
    if (suspicious_events.empty()) 
    {
        output << "No anomalies detected.\n";
        output << "All login activity appears normal.\n\n";
        return;
    }
    
    // Output each suspicious event
    int event_number = 1;
    for (const auto& event : suspicious_events) 
    {
        output << "\n[" << event_number << "] " 
               << eventTypeToString(event.type) << "\n";
        
        // Username
        output << "    Username: " << event.username << "\n";
        
        // IP Address(es)
        output << "    IP Address(es): ";
        if (event.ip_addresses.empty()) 
        {
            output << "N/A";
        } 
        else if (event.ip_addresses.size() == 1) 
        {
            output << event.ip_addresses[0];
        } 
        else 
        {
            // Multiple IPs - list them
            output << "\n";
            for (const auto& ip : event.ip_addresses) 
            {
                output << "        - " << ip << "\n";
            }
            output << "    ";  // Indent for next field
        }
        output << "\n";
        
        // Time range
        output << "    First Occurrence: " << formatTimestamp(event.first_occurrence) << "\n";
        output << "    Last Occurrence: " << formatTimestamp(event.last_occurrence) << "\n";
        
        // Event count
        output << "    Event Count: " << event.event_count << "\n";
        
        // Description
        if (!event.description.empty()) 
        {
            output << "    Details: " << event.description << "\n";
        }
        
        event_number++;
    }
    
    output << "\n";
}

void ReportGenerator::generateFooter(std::ostream& output) const
{
    output << "========================================\n";
    output << "         END OF REPORT\n";
    output << "========================================\n";
}

std::string ReportGenerator::eventTypeToString(SuspiciousEventType type) const
{
    switch (type) 
    {
        case SuspiciousEventType::MULTIPLE_FAILED_LOGINS:
            return "Multiple Failed Login Attempts";
        case SuspiciousEventType::LOGIN_OUTSIDE_BUSINESS_HOURS:
            return "Login Outside Business Hours";
        case SuspiciousEventType::MULTIPLE_IP_ADDRESSES:
            return "Multiple IP Addresses";
        default:
            return "Unknown Event Type";
    }
}

std::string ReportGenerator::formatTimestamp(
    std::chrono::system_clock::time_point timestamp) const
{
    // Convert time_point to time_t
    std::time_t time = std::chrono::system_clock::to_time_t(timestamp);
    
    // Convert to local time structure
    std::tm* tm = std::localtime(&time);
    
    // Format as string: YYYY-MM-DD HH:MM:SS
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
    
    return oss.str();
}