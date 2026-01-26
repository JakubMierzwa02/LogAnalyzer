#include <catch2/catch_test_macros.hpp>
#include "ConfigManager.h"
#include <vector>
#include <cstring>

/**
 * Unit tests for ConfigManager class
 * 
 * These tests verify:
 * - Default configuration values
 * - Configuration validation
 * - Command-line argument parsing
 * - Error handling for invalid inputs
 */

/**
 * Helper function to convert vector of strings to char* array
 * This simulates argc/argv from command line
 */
char** createArgv(const std::vector<std::string>& args) 
{
    char** argv = new char*[args.size()];
    for (size_t i = 0; i < args.size(); ++i) 
    {
        argv[i] = new char[args[i].length() + 1];
        std::strcpy(argv[i], args[i].c_str());
    }
    return argv;
}

void freeArgv(char** argv, int argc) 
{
    for (int i = 0; i < argc; ++i) 
    {
        delete[] argv[i];
    }
    delete[] argv;
}

// ============================================================================
// Tests for default configuration
// ============================================================================

TEST_CASE("ConfigManager - Default configuration values", "[ConfigManager][defaults]") 
{
    ConfigManager manager;
    const Configuration& config = manager.getConfiguration();
    
    REQUIRE(config.failed_login_threshold == 5);
    REQUIRE(config.time_window_minutes == 10);
    REQUIRE(config.business_hour_start == 8);
    REQUIRE(config.business_hour_end == 18);
    REQUIRE(config.log_file_path == "logs/sample.log");
    REQUIRE(config.report_output_path == "reports/report.txt");
}

TEST_CASE("ConfigManager - Default configuration is valid", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    REQUIRE(manager.validateConfiguration());
}

// ============================================================================
// Tests for configuration validation
// ============================================================================

TEST_CASE("ConfigManager - Validate invalid threshold (zero)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.failed_login_threshold = 0;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid threshold (negative)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.failed_login_threshold = -5;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid time window (zero)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.time_window_minutes = 0;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid time window (negative)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.time_window_minutes = -10;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid business hour start (negative)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_start = -1;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid business hour start (too high)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_start = 24;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid business hour end (negative)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_end = -1;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate invalid business hour end (too high)", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_end = 25;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate start >= end for business hours", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_start = 18;
    config.business_hour_end = 8;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate start == end for business hours", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.business_hour_start = 10;
    config.business_hour_end = 10;
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate empty log file path", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.log_file_path = "";
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Validate empty report output path", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config = manager.getConfiguration();
    config.report_output_path = "";
    
    REQUIRE_FALSE(manager.setConfiguration(config));
}

TEST_CASE("ConfigManager - Valid custom configuration", "[ConfigManager][validation]") 
{
    ConfigManager manager;
    Configuration config;
    config.failed_login_threshold = 3;
    config.time_window_minutes = 5;
    config.business_hour_start = 9;
    config.business_hour_end = 17;
    config.log_file_path = "custom.log";
    config.report_output_path = "custom_report.txt";
    
    REQUIRE(manager.setConfiguration(config));
    
    const Configuration& stored = manager.getConfiguration();
    REQUIRE(stored.failed_login_threshold == 3);
    REQUIRE(stored.time_window_minutes == 5);
    REQUIRE(stored.business_hour_start == 9);
    REQUIRE(stored.business_hour_end == 17);
}

// ============================================================================
// Tests for command-line argument parsing
// ============================================================================

TEST_CASE("ConfigManager - Parse no arguments (use defaults)", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE_FALSE(manager.isHelpRequested());
    
    // Should have default values
    const Configuration& config = manager.getConfiguration();
    REQUIRE(config.failed_login_threshold == 5);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse help flag", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--help"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.isHelpRequested());
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse short help flag", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "-h"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.isHelpRequested());
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse input file argument", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--input", "custom.log"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.getConfiguration().log_file_path == "custom.log");
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse output file argument", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--output", "custom_report.txt"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.getConfiguration().report_output_path == "custom_report.txt");
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse threshold argument", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--threshold", "3"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.getConfiguration().failed_login_threshold == 3);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse window argument", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--window", "15"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.getConfiguration().time_window_minutes == 15);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse business hours argument", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--hours", "9-17"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    REQUIRE(manager.getConfiguration().business_hour_start == 9);
    REQUIRE(manager.getConfiguration().business_hour_end == 17);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse multiple arguments", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = 
    {
        "log-analyzer", 
        "--input", "test.log",
        "--threshold", "7",
        "--hours", "9-17"
    };
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    
    const Configuration& config = manager.getConfiguration();
    REQUIRE(config.log_file_path == "test.log");
    REQUIRE(config.failed_login_threshold == 7);
    REQUIRE(config.business_hour_start == 9);
    REQUIRE(config.business_hour_end == 17);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Parse short argument forms", "[ConfigManager][parseArgs]") 
{
    ConfigManager manager;
    std::vector<std::string> args = 
    {
        "log-analyzer",
        "-i", "short.log",
        "-o", "short_report.txt",
        "-t", "4",
        "-w", "20"
    };
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE(success);
    
    const Configuration& config = manager.getConfiguration();
    REQUIRE(config.log_file_path == "short.log");
    REQUIRE(config.report_output_path == "short_report.txt");
    REQUIRE(config.failed_login_threshold == 4);
    REQUIRE(config.time_window_minutes == 20);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

// ============================================================================
// Tests for error handling in argument parsing
// ============================================================================

TEST_CASE("ConfigManager - Error on missing input file path", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--input"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Error on missing threshold value", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--threshold"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Error on invalid threshold value", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--threshold", "abc"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Error on invalid business hours format", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--hours", "9:17"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Error on unknown argument", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    std::vector<std::string> args = {"log-analyzer", "--unknown"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}

TEST_CASE("ConfigManager - Error on invalid configuration after parsing", "[ConfigManager][parseArgs][errors]") 
{
    ConfigManager manager;
    // Set threshold to 0, which is invalid
    std::vector<std::string> args = {"log-analyzer", "--threshold", "0"};
    char** argv = createArgv(args);
    
    bool success = manager.parseCommandLineArgs(static_cast<int>(args.size()), argv);
    
    REQUIRE_FALSE(success);
    
    freeArgv(argv, static_cast<int>(args.size()));
}