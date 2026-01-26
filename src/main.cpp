#include "ConfigManager.h"
#include "LogParser.h"
#include "EventDetector.h"
#include "ReportGenerator.h"
#include <iostream>
#include <fstream>
#include <vector>

/**
 * @brief Main entry point for the Log Analyzer application
 * 
 * This application analyzes authentication log files and detects
 * suspicious login patterns such as brute-force attacks, after-hours
 * access, and multiple IP usage.
 * 
 * Workflow:
 * 1. Parse command-line arguments and load configuration
 * 2. Load and parse log file
 * 3. Run detection algorithms
 * 4. Generate security report
 * 
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, non-zero on error
 */
int main(int argc, char* argv[]) 
{
    // ========================================================================
    // Step 1: Configuration Management
    // ========================================================================
    
    ConfigManager config_manager;
    
    // Parse command-line arguments
    if (!config_manager.parseCommandLineArgs(argc, argv)) 
    {
        std::cerr << "Error: Failed to parse command-line arguments.\n";
        std::cerr << "Use --help for usage information.\n";
        return 1;
    }
    
    // Check if help was requested
    if (config_manager.isHelpRequested()) 
    {
        config_manager.displayUsage();
        return 0;
    }
    
    // Get configuration
    const Configuration& config = config_manager.getConfiguration();
    
    std::cout << "Log Analyzer - Suspicious Event Detection\n";
    std::cout << "==========================================\n";
    std::cout << "Input file: " << config.log_file_path << "\n";
    std::cout << "Output file: " << config.report_output_path << "\n";
    std::cout << "Configuration:\n";
    std::cout << "  - Failed login threshold: " << config.failed_login_threshold << "\n";
    std::cout << "  - Time window: " << config.time_window_minutes << " minutes\n";
    std::cout << "  - Business hours: " << config.business_hour_start 
              << ":00 - " << config.business_hour_end << ":00\n";
    std::cout << "\n";
    
    // ========================================================================
    // Step 2: Load and Parse Log File
    // ========================================================================
    
    std::cout << "Loading log file...\n";
    
    // Open log file
    std::ifstream log_file(config.log_file_path);
    if (!log_file.is_open()) 
    {
        std::cerr << "Error: Cannot open log file '" << config.log_file_path << "'\n";
        std::cerr << "Please check that the file exists and is readable.\n";
        return 2;
    }
    
    // Parse log entries
    std::vector<LogEntry> log_entries;
    std::string line;
    int line_number = 0;
    int invalid_entries = 0;
    
    while (std::getline(log_file, line)) 
    {
        line_number++;
        
        // Skip empty lines
        if (line.empty()) 
        {
            continue;
        }
        
        // Parse the log line
        auto entry_opt = LogParser::parseLogLine(line);
        
        if (entry_opt.has_value()) 
        {
            log_entries.push_back(entry_opt.value());
        } 
        else 
        {
            // Invalid entry - log internally and continue
            invalid_entries++;
            std::cerr << "Warning: Skipping invalid log entry at line " 
                      << line_number << "\n";
        }
    }
    
    log_file.close();
    
    std::cout << "Log file loaded successfully.\n";
    std::cout << "  - Total lines processed: " << line_number << "\n";
    std::cout << "  - Valid entries: " << log_entries.size() << "\n";
    std::cout << "  - Invalid entries: " << invalid_entries << "\n";
    std::cout << "\n";
    
    // Check if log file was empty
    if (log_entries.empty()) 
    {
        std::cout << "Warning: No valid log entries found.\n";
        std::cout << "Generating empty report...\n";
    }
    
    // ========================================================================
    // Step 3: Run Detection Algorithms
    // ========================================================================
    
    std::cout << "Running detection algorithms...\n";
    
    // Create event detector with configuration
    EventDetector detector(
        config.failed_login_threshold,
        config.time_window_minutes,
        config.business_hour_start,
        config.business_hour_end
    );
    
    // Run all detection methods
    std::vector<SuspiciousEvent> suspicious_events = detector.detectAll(log_entries);
    
    std::cout << "Detection complete.\n";
    std::cout << "  - Suspicious events detected: " << suspicious_events.size() << "\n";
    std::cout << "\n";
    
    // ========================================================================
    // Step 4: Generate Security Report
    // ========================================================================
    
    std::cout << "Generating security report...\n";
    
    // Create report generator
    ReportGenerator report_generator;
    
    // Generate report to file
    bool report_success = report_generator.generateReportToFile(
        log_entries,
        suspicious_events,
        config.report_output_path
    );
    
    if (!report_success) 
    {
        std::cerr << "Error: Failed to write report to '" 
                  << config.report_output_path << "'\n";
        std::cerr << "Please check that the directory exists and is writable.\n";
        return 3;
    }
    
    std::cout << "Report generated successfully.\n";
    std::cout << "Output saved to: " << config.report_output_path << "\n";
    std::cout << "\n";
    
    // ========================================================================
    // Step 5: Summary
    // ========================================================================
    
    std::cout << "==========================================\n";
    std::cout << "Analysis Complete\n";
    std::cout << "==========================================\n";
    
    if (suspicious_events.empty()) 
    {
        std::cout << "No security issues detected.\n";
        std::cout << "All login activity appears normal.\n";
    } 
    else 
    {
        std::cout << "WARNING: " << suspicious_events.size() 
                  << " suspicious event(s) detected!\n";
        std::cout << "Please review the generated report for details.\n";
    }
    
    return 0;
}