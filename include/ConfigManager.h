#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>

/**
 * @brief Structure holding all configuration parameters for the log analyzer
 * 
 * This structure contains all configurable detection thresholds and parameters
 * used by the EventDetector. It provides a centralized way to manage
 * application configuration.
 */
struct Configuration 
{
    // Detection thresholds
    int failed_login_threshold;      // Minimum failed attempts to trigger alert
    int time_window_minutes;         // Time window for event clustering (minutes)
    
    // Business hours configuration
    int business_hour_start;         // Start of business hours (0-23)
    int business_hour_end;           // End of business hours (0-23)
    
    // File paths
    std::string log_file_path;       // Path to input log file
    std::string report_output_path;  // Path to output report file
    
    /**
     * @brief Default constructor with standard values
     * 
     * Initializes configuration with default values:
     * - failed_login_threshold: 5
     * - time_window_minutes: 10
     * - business_hour_start: 8
     * - business_hour_end: 18
     * - log_file_path: "logs/sample.log"
     * - report_output_path: "reports/report.txt"
     */
    Configuration()
        : failed_login_threshold(5),
          time_window_minutes(10),
          business_hour_start(8),
          business_hour_end(18),
          log_file_path("logs/sample.log"),
          report_output_path("reports/report.txt")
    {}
};

/**
 * @brief Class responsible for managing application configuration
 * 
 * This class handles loading, validating, and providing access to
 * configuration parameters. It ensures that all configuration values
 * are within valid ranges and provides sensible defaults.
 * 
 * Configuration can be:
 * - Set programmatically
 * - Loaded from command-line arguments
 * - Used with default values
 */
class ConfigManager 
{
public:
    /**
     * @brief Default constructor
     * 
     * Initializes ConfigManager with default configuration values.
     */
    ConfigManager();
    
    /**
     * @brief Parses command-line arguments and updates configuration
     * 
     * Processes command-line arguments to extract configuration parameters.
     * Supports the following arguments:
     * - --input <path>         : Path to input log file
     * - --output <path>        : Path to output report file
     * - --threshold <number>   : Failed login threshold
     * - --window <minutes>     : Time window in minutes
     * - --hours <start>-<end>  : Business hours (e.g., "9-17")
     * - --help                 : Display usage information
     * 
     * @param argc Argument count from main()
     * @param argv Argument vector from main()
     * @return true if arguments parsed successfully, false on error
     * 
     * @note Sets help_requested flag if --help is provided
     * @note Returns false for invalid arguments or missing required values
     */
    bool parseCommandLineArgs(int argc, char* argv[]);
    
    /**
     * @brief Gets the current configuration
     * 
     * @return Const reference to the current configuration
     */
    const Configuration& getConfiguration() const;
    
    /**
     * @brief Sets a custom configuration
     * 
     * @param config The configuration to use
     * @return true if configuration is valid, false otherwise
     * 
     * @note Validates the configuration before setting it
     */
    bool setConfiguration(const Configuration& config);
    
    /**
     * @brief Validates the current configuration
     * 
     * Checks that all configuration parameters are within valid ranges:
     * - failed_login_threshold > 0
     * - time_window_minutes > 0
     * - business_hour_start in range [0, 23]
     * - business_hour_end in range [0, 23]
     * - business_hour_start < business_hour_end
     * - File paths are not empty
     * 
     * @return true if configuration is valid, false otherwise
     */
    bool validateConfiguration() const;
    
    /**
     * @brief Checks if help was requested via command-line arguments
     * 
     * @return true if --help flag was provided
     */
    bool isHelpRequested() const;
    
    /**
     * @brief Displays usage information
     * 
     * Prints command-line argument syntax and available options to stdout.
     */
    void displayUsage() const;

private:
    Configuration config_;      // Current configuration
    bool help_requested_;       // Flag indicating --help was requested
    
    /**
     * @brief Helper function to parse business hours string
     * 
     * Parses a string in format "start-end" (e.g., "9-17") into
     * start and end hour integers.
     * 
     * @param hours_str String to parse
     * @param start Output parameter for start hour
     * @param end Output parameter for end hour
     * @return true if parsing successful, false otherwise
     */
    bool parseBusinessHours(const std::string& hours_str, int& start, int& end) const;
    
    /**
     * @brief Helper function to parse integer from string
     * 
     * @param str String to parse
     * @param value Output parameter for parsed value
     * @return true if parsing successful, false otherwise
     */
    bool parseInteger(const std::string& str, int& value) const;
};

#endif // CONFIG_MANAGER_H