# Log Analyzer - Suspicious Event Detection

A command-line application for analyzing authentication log files and detecting suspicious or anomalous login activity.

## Features

- **Parse authentication logs** - Processes log files in standard format
- **Brute-force detection** - Identifies multiple failed login attempts
- **After-hours monitoring** - Detects logins outside business hours
- **IP anomaly detection** - Flags logins from multiple IP addresses
- **Configurable thresholds** - Customizable detection parameters
- **Detailed reports** - Generates comprehensive security reports

## Project Structure

```
log-analyzer/
├── src/
│   ├── main.cpp              # Application entry point
│   ├── LogParser.cpp         # Log file parsing
│   ├── EventDetector.cpp     # Suspicious event detection
│   ├── ReportGenerator.cpp   # Security report generation
│   └── ConfigManager.cpp     # Configuration management
│
├── include/
│   ├── LogEntry.h           # Log entry data structures
│   ├── LogParser.h          # Log parser declarations
│   ├── EventDetector.h      # Event detector declarations
│   ├── ReportGenerator.h    # Report generator declarations
│   └── ConfigManager.h      # Config manager declarations
│
├── tests/
│   ├── test_LogParser.cpp
│   ├── test_EventDetector.cpp
│   ├── test_ReportGenerator.cpp
│   └── test_ConfigManager.cpp
│
├── logs/
│   └── sample.log           # Example log file
│
├── reports/
│   └── report.txt           # Generated reports
│
├── CMakeLists.txt           # Build configuration
└── README.md                # This file
```

## Building the Project

### Requirements

- C++17 compatible compiler
- CMake 3.14 or higher
- Catch2 3.x (for unit tests)

### Build Instructions

```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build the project
cmake --build .

# Run the application
./log-analyzer --input ../logs/sample.log --output ../reports/report.txt
```

### Building with Tests

```bash
# Configure with tests enabled (default)
cmake -DBUILD_TESTS=ON ..

# Build everything
cmake --build .

# Run all tests
ctest --output-on-failure

# Or run specific test
./test_LogParser
./test_EventDetector
./test_ReportGenerator
./test_ConfigManager
```

## Usage

### Basic Usage

```bash
log-analyzer --input logs/auth.log --output reports/security_report.txt
```

### Command-Line Options

```
Options:
  --input, -i <path>        Path to input log file
                            Default: logs/sample.log

  --output, -o <path>       Path to output report file
                            Default: reports/report.txt

  --threshold, -t <number>  Failed login threshold
                            Default: 5

  --window, -w <minutes>    Time window for event clustering
                            Default: 10

  --hours <start-end>       Business hours (e.g., 9-17)
                            Default: 8-18

  --help, -h                Display help message
```

### Examples

```bash
# Use default settings
./log-analyzer

# Custom input and output files
./log-analyzer --input /var/log/auth.log --output security_analysis.txt

# Adjust detection thresholds
./log-analyzer --threshold 3 --window 5

# Set business hours (9 AM to 5 PM)
./log-analyzer --hours 9-17

# Combine multiple options
./log-analyzer -i auth.log -o report.txt -t 3 -w 5 --hours 9-17
```

## Log File Format

The application expects log files in the following format:

```
YYYY-MM-DD HH:MM:SS | USERNAME | IP_ADDRESS | STATUS
```

Example:
```
2026-01-18 08:45:12 | jdoe | 192.168.1.10 | FAILED
2026-01-18 08:46:00 | jdoe | 192.168.1.10 | SUCCESS
2026-01-18 14:30:15 | alice | 10.0.0.5 | SUCCESS
```

**Requirements:**
- Status must be either `SUCCESS` or `FAILED`
- Fields are separated by pipe (`|`) character
- Timestamp format: `YYYY-MM-DD HH:MM:SS`
- Invalid entries are automatically skipped

## Detection Rules

### 1. Multiple Failed Login Attempts
- **Purpose:** Detect brute-force password attacks
- **Default threshold:** 5 failed attempts within 10 minutes
- **Configuration:** `--threshold` and `--window`

### 2. Logins Outside Business Hours
- **Purpose:** Detect unauthorized after-hours access
- **Default hours:** 08:00 to 18:00
- **Configuration:** `--hours`
- **Note:** Only analyzes successful logins

### 3. Multiple IP Addresses
- **Purpose:** Detect account compromise or credential sharing
- **Detection:** Same user from 2+ IPs within time window
- **Configuration:** `--window`
- **Note:** Only analyzes successful logins

## Output Report

The generated report includes:

- **Header** with generation timestamp
- **Summary statistics:**
  - Total log entries processed
  - Successful vs. failed logins
  - Number of suspicious events
- **Detailed anomalies** with:
  - Event type
  - Username involved
  - IP address(es)
  - Time range
  - Event count
  - Description
- **Footer**

Example output:
```
========================================
   LOG ANALYZER SECURITY REPORT
========================================
Report Generated: 2026-01-26 15:30:00
========================================

SUMMARY STATISTICS
----------------------------------------
Total Log Entries: 42
Successful Logins: 35
Failed Logins: 7
Suspicious Events Detected: 3

DETECTED ANOMALIES
----------------------------------------

[1] Multiple Failed Login Attempts
    Username: admin
    IP Address(es): 10.0.0.1
    First Occurrence: 2026-01-18 23:15:00
    Last Occurrence: 2026-01-18 23:20:05
    Event Count: 6
    Details: User 'admin' had 6 failed login attempts within 10 minutes

[2] Login Outside Business Hours
    Username: root
    IP Address(es): 172.16.0.1
    First Occurrence: 2026-01-18 22:30:45
    Last Occurrence: 2026-01-18 22:30:45
    Event Count: 1
    Details: User 'root' logged in at hour 22 (outside business hours: 8:00-18:00)

========================================
         END OF REPORT
========================================
```

## Testing

The project includes comprehensive unit tests using Catch2:

- **test_LogParser.cpp** - 20 tests for log parsing functionality
- **test_EventDetector.cpp** - 27 tests for event detection algorithms
- **test_ReportGenerator.cpp** - 12 tests for report generation
- **test_ConfigManager.cpp** - 33 tests for configuration management

**Total: 92 unit tests**

Run all tests:
```bash
cd build
ctest --output-on-failure
```

## Code Quality

### Running clang-tidy

Generate analysis report:
```bash
# For all source files
clang-tidy src/*.cpp -- -std=c++17 -Iinclude > clang-tidy-report.txt 2>&1

# With compile_commands.json (recommended)
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -B build
clang-tidy -p build src/*.cpp > clang-tidy-report.txt 2>&1
```

See `Clang-Tidy - Generowanie Raportów` artifact for detailed instructions.

## Error Handling

The application handles errors:

- **Missing input file:** Exits with error message
- **Invalid log entries:** Skipped with warning, processing continues
- **Empty log file:** Generates report with warning
- **Incorrect arguments:** Displays usage instructions
- **Output write failure:** Exits with error message

## Technical Details

- **Language:** C++17
- **Build System:** CMake 3.14+
- **Testing Framework:** Catch2 3.x
- **Platforms:** Linux, Windows, macOS
- **Dependencies:** C++ Standard Library (STL)
- **Key Components:** `<chrono>`, `<vector>`, `<map>`, `<set>`, `<fstream>`

## License

Educational/Portfolio Project - Free to use and modify.

## Author
Jakub Mierzwa