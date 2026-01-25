#include "ConfigManager.h"
#include <iostream>
#include <sstream>
#include <cctype>

// ============================================================================
// Constructor
// ============================================================================

ConfigManager::ConfigManager()
    : config_(),
      help_requested_(false)
{
}

// ============================================================================
// Public Methods
// ============================================================================

bool ConfigManager::parseCommandLineArgs(int argc, char* argv[]) 
{
    // Reset help flag
    help_requested_ = false;
    
    // Iterate through command-line arguments
    // Start at index 1 to skip program name (argv[0])
    for (int i = 1; i < argc; ++i) 
    {
        std::string arg = argv[i];
        
        // Check for help flag
        if (arg == "--help" || arg == "-h") 
        {
            help_requested_ = true;
            return true;  // Not an error
        }
        
        // Check for input file argument
        else if (arg == "--input" || arg == "-i") 
        {
            // Ensure next argument exists
            if (i + 1 >= argc) 
            {
                std::cerr << "Error: --input requires a file path\n";
                return false;
            }
            config_.log_file_path = argv[++i];
        }
        
        // Check for output file argument
        else if (arg == "--output" || arg == "-o") 
        {
            if (i + 1 >= argc) 
            {
                std::cerr << "Error: --output requires a file path\n";
                return false;
            }
            config_.report_output_path = argv[++i];
        }
        
        // Check for threshold argument
        else if (arg == "--threshold" || arg == "-t") 
        {
            if (i + 1 >= argc) 
            {
                std::cerr << "Error: --threshold requires a number\n";
                return false;
            }
            int threshold;
            if (!parseInteger(argv[++i], threshold)) 
            {
                std::cerr << "Error: Invalid threshold value\n";
                return false;
            }
            config_.failed_login_threshold = threshold;
        }
        
        // Check for time window argument
        else if (arg == "--window" || arg == "-w") 
        {
            if (i + 1 >= argc) 
            {
                std::cerr << "Error: --window requires a number (minutes)\n";
                return false;
            }
            int window;
            if (!parseInteger(argv[++i], window)) 
            {
                std::cerr << "Error: Invalid window value\n";
                return false;
            }
            config_.time_window_minutes = window;
        }
        
        // Check for business hours argument
        else if (arg == "--hours") 
        {
            if (i + 1 >= argc) 
            {
                std::cerr << "Error: --hours requires a range (e.g., 9-17)\n";
                return false;
            }
            int start, end;
            if (!parseBusinessHours(argv[++i], start, end)) 
            {
                std::cerr << "Error: Invalid business hours format (use: start-end)\n";
                return false;
            }
            config_.business_hour_start = start;
            config_.business_hour_end = end;
        }
        
        // Unknown argument
        else 
        {
            std::cerr << "Error: Unknown argument '" << arg << "'\n";
            return false;
        }
    }
    
    // Validate the configuration after parsing
    if (!help_requested_ && !validateConfiguration()) 
    {
        std::cerr << "Error: Invalid configuration values\n";
        return false;
    }
    
    return true;
}

const Configuration& ConfigManager::getConfiguration() const 
{
    return config_;
}

bool ConfigManager::setConfiguration(const Configuration& config) 
{
    // Store temporarily to validate
    Configuration temp = config_;
    config_ = config;
    
    // Validate new configuration
    if (!validateConfiguration()) 
    {
        // Restore previous configuration if validation fails
        config_ = temp;
        return false;
    }
    
    return true;
}

bool ConfigManager::validateConfiguration() const 
{
    // Validate failed login threshold
    if (config_.failed_login_threshold <= 0) 
    {
        return false;
    }
    
    // Validate time window
    if (config_.time_window_minutes <= 0) 
    {
        return false;
    }
    
    // Validate business hour start
    if (config_.business_hour_start < 0 || config_.business_hour_start > 23) 
    {
        return false;
    }
    
    // Validate business hour end
    if (config_.business_hour_end < 0 || config_.business_hour_end > 23) 
    {
        return false;
    }
    
    // Validate that start is before end
    if (config_.business_hour_start >= config_.business_hour_end) 
    {
        return false;
    }
    
    // Validate file paths are not empty
    if (config_.log_file_path.empty()) 
    {
        return false;
    }
    
    if (config_.report_output_path.empty()) 
    {
        return false;
    }
    
    return true;
}

bool ConfigManager::isHelpRequested() const 
{
    return help_requested_;
}

void ConfigManager::displayUsage() const 
{
    std::cout << "Log Analyzer - Suspicious Event Detection\n";
    std::cout << "==========================================\n\n";
    std::cout << "Usage: log-analyzer [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --input, -i <path>        Path to input log file\n";
    std::cout << "                            Default: logs/sample.log\n\n";
    std::cout << "  --output, -o <path>       Path to output report file\n";
    std::cout << "                            Default: reports/report.txt\n\n";
    std::cout << "  --threshold, -t <number>  Failed login threshold\n";
    std::cout << "                            Default: 5\n\n";
    std::cout << "  --window, -w <minutes>    Time window for event clustering\n";
    std::cout << "                            Default: 10\n\n";
    std::cout << "  --hours <start-end>       Business hours (e.g., 9-17)\n";
    std::cout << "                            Default: 8-18\n\n";
    std::cout << "  --help, -h                Display this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  log-analyzer --input auth.log --output security_report.txt\n";
    std::cout << "  log-analyzer --threshold 3 --window 5 --hours 9-17\n";
    std::cout << "  log-analyzer --help\n";
}

// ============================================================================
// Private Helper Methods
// ============================================================================

bool ConfigManager::parseBusinessHours(const std::string& hours_str, 
                                       int& start, 
                                       int& end) const 
{
    // Find the dash separator
    size_t dash_pos = hours_str.find('-');
    
    // Check if dash was found
    if (dash_pos == std::string::npos) 
    {
        return false;
    }
    
    // Extract start and end substrings
    std::string start_str = hours_str.substr(0, dash_pos);
    std::string end_str = hours_str.substr(dash_pos + 1);
    
    // Parse start and end values
    if (!parseInteger(start_str, start)) 
    {
        return false;
    }
    
    if (!parseInteger(end_str, end)) 
    {
        return false;
    }
    
    // Validate range
    if (start < 0 || start > 23 || end < 0 || end > 23) 
    {
        return false;
    }
    
    if (start >= end) 
    {
        return false;
    }
    
    return true;
}

bool ConfigManager::parseInteger(const std::string& str, int& value) const 
{
    // Check for empty string
    if (str.empty()) 
    {
        return false;
    }
    
    // Check that all characters are digits (allow leading minus for negative)
    size_t start_pos = 0;
    if (str[0] == '-') 
    {
        start_pos = 1;
        // Reject lone minus sign
        if (str.length() == 1) 
        {
            return false;
        }
    }
    
    for (size_t i = start_pos; i < str.length(); ++i) 
    {
        if (!std::isdigit(static_cast<unsigned char>(str[i]))) 
        {
            return false;
        }
    }
    
    // Use stringstream to convert
    std::istringstream iss(str);
    iss >> value;
    
    // Check if conversion failed
    if (iss.fail()) 
    {
        return false;
    }
    
    return true;
}