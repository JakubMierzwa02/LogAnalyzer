#include "EventDetector.h"
#include <map>
#include <set>
#include <algorithm>

// ============================================================================
// Constructors
// ============================================================================

EventDetector::EventDetector()
    : failed_login_threshold_(5),
      time_window_minutes_(10),
      business_hour_start_(8),
      business_hour_end_(18)
{
}

EventDetector::EventDetector(int failed_login_threshold,
                             int time_window_minutes,
                             int business_hour_start,
                             int business_hour_end)
    : failed_login_threshold_(failed_login_threshold),
      time_window_minutes_(time_window_minutes),
      business_hour_start_(business_hour_start),
      business_hour_end_(business_hour_end)
{
}

// ============================================================================
// Private Helper Functions
// ============================================================================

bool EventDetector::isWithinTimeWindow(
    std::chrono::system_clock::time_point time1,
    std::chrono::system_clock::time_point time2) const
{
    // Calculate absolute difference between timestamps
    auto duration = (time1 > time2) ? (time1 - time2) : (time2 - time1);
    
    // Convert to minutes
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    
    // Check if within configured window
    return minutes.count() <= time_window_minutes_;
}

int EventDetector::getHourOfDay(std::chrono::system_clock::time_point timestamp) const
{
    // Convert time_point to time_t
    std::time_t time = std::chrono::system_clock::to_time_t(timestamp);
    
    // Convert to local time structure
    std::tm* tm = std::localtime(&time);
    
    // Return hour (0-23)
    return tm->tm_hour;
}

// ============================================================================
// Detection Methods
// ============================================================================

std::vector<SuspiciousEvent> EventDetector::detectMultipleFailedLogins(
    const std::vector<LogEntry>& entries) const
{
    std::vector<SuspiciousEvent> detected_events;
    
    // Step 1: Group failed login attempts by username
    // Map: username -> vector of failed login entries
    std::map<std::string, std::vector<LogEntry>> failed_logins_by_user;
    
    for (const auto& entry : entries) 
    {
        // Only consider failed login attempts
        if (entry.status == LoginStatus::FAILED) 
        {
            failed_logins_by_user[entry.username].push_back(entry);
        }
    }
    
    // Step 2: For each user, analyze their failed login attempts
    for (auto& [username, user_failed_logins] : failed_logins_by_user) 
    {
        // Sort the failed logins by timestamp (earliest first)
        std::sort(user_failed_logins.begin(), user_failed_logins.end(),
                  [](const LogEntry& a, const LogEntry& b) 
                  {
                      return a.timestamp < b.timestamp;
                  });
        
        // Step 3: Use sliding window to find clusters of failed attempts
        for (size_t i = 0; i < user_failed_logins.size(); ++i) 
        {
            const LogEntry& window_start = user_failed_logins[i];
            
            // Count failed attempts within time window from this entry
            int count = 1;  // Current entry counts
            size_t window_end_idx = i;
            
            // Scan forward to find all entries within time window
            for (size_t j = i + 1; j < user_failed_logins.size(); ++j) 
            {
                if (isWithinTimeWindow(window_start.timestamp, 
                                      user_failed_logins[j].timestamp)) 
                {
                    count++;
                    window_end_idx = j;
                } 
                else 
                {
                    // Entries are sorted, so we can break early
                    break;
                }
            }
            
            // Step 4: If cluster meets threshold, report it
            if (count >= failed_login_threshold_) 
            {
                const LogEntry& window_end = user_failed_logins[window_end_idx];
                
                // Create suspicious event
                SuspiciousEvent event(
                    SuspiciousEventType::MULTIPLE_FAILED_LOGINS,
                    username,
                    window_start.ip_address,
                    window_start.timestamp,
                    window_end.timestamp,
                    count
                );
                
                // Add description
                event.description = "User '" + username + "' had " + 
                                   std::to_string(count) + 
                                   " failed login attempts within " +
                                   std::to_string(time_window_minutes_) + " minutes";
                
                detected_events.push_back(event);
                
                // Skip to end of cluster to avoid overlapping detections
                i = window_end_idx;
            }
        }
    }
    
    return detected_events;
}

std::vector<SuspiciousEvent> EventDetector::detectLoginsOutsideBusinessHours(
    const std::vector<LogEntry>& entries) const
{
    std::vector<SuspiciousEvent> detected_events;
    
    // Analyze each entry
    for (const auto& entry : entries) 
    {
        // Only consider successful logins
        if (entry.status != LoginStatus::SUCCESS) 
        {
            continue;
        }
        
        // Get hour of day for this login
        int hour = getHourOfDay(entry.timestamp);
        
        // Check if outside business hours
        // Business hours are inclusive: [start, end)
        // For example: 8-18 means 08:00:00 to 17:59:59
        bool outside_hours = (hour < business_hour_start_ || hour >= business_hour_end_);
        
        if (outside_hours) 
        {
            // Create suspicious event for this after-hours login
            SuspiciousEvent event(
                SuspiciousEventType::LOGIN_OUTSIDE_BUSINESS_HOURS,
                entry.username,
                entry.ip_address,
                entry.timestamp,
                entry.timestamp,  // Single event, so first = last
                1
            );
            
            // Add description
            event.description = "User '" + entry.username + 
                               "' logged in at hour " + std::to_string(hour) +
                               " (outside business hours: " +
                               std::to_string(business_hour_start_) + ":00-" +
                               std::to_string(business_hour_end_) + ":00)";
            
            detected_events.push_back(event);
        }
    }
    
    return detected_events;
}

std::vector<SuspiciousEvent> EventDetector::detectMultipleIPAddresses(
    const std::vector<LogEntry>& entries) const
{
    std::vector<SuspiciousEvent> detected_events;
    
    // Step 1: Group successful logins by username
    std::map<std::string, std::vector<LogEntry>> logins_by_user;
    
    for (const auto& entry : entries) 
    {
        // Only consider successful logins
        if (entry.status == LoginStatus::SUCCESS) 
        {
            logins_by_user[entry.username].push_back(entry);
        }
    }
    
    // Step 2: For each user, check for multiple IPs in time windows
    for (auto& [username, user_logins] : logins_by_user) 
    {
        // Sort by timestamp
        std::sort(user_logins.begin(), user_logins.end(),
                  [](const LogEntry& a, const LogEntry& b) 
                  {
                      return a.timestamp < b.timestamp;
                  });
        
        // Step 3: Use sliding window to find multiple distinct IPs
        for (size_t i = 0; i < user_logins.size(); ++i) 
        {
            const LogEntry& window_start = user_logins[i];
            
            // Collect all distinct IPs within time window
            std::set<std::string> ip_addresses;
            ip_addresses.insert(window_start.ip_address);
            
            size_t window_end_idx = i;
            
            // Scan forward to find all entries within time window
            for (size_t j = i + 1; j < user_logins.size(); ++j) 
            {
                if (isWithinTimeWindow(window_start.timestamp,
                                      user_logins[j].timestamp)) 
                {
                    ip_addresses.insert(user_logins[j].ip_address);
                    window_end_idx = j;
                } 
                else 
                {
                    break;
                }
            }
            
            // Step 4: If multiple distinct IPs found, report it
            // We consider 2 or more distinct IPs as suspicious
            if (ip_addresses.size() >= 2) 
            {
                const LogEntry& window_end = user_logins[window_end_idx];
                
                // Create suspicious event
                SuspiciousEvent event(
                    SuspiciousEventType::MULTIPLE_IP_ADDRESSES,
                    username,
                    "", // Will fill ip_addresses vector instead
                    window_start.timestamp,
                    window_end.timestamp,
                    static_cast<int>(ip_addresses.size())
                );
                
                // Add all IP addresses to the event
                event.ip_addresses.clear();
                for (const auto& ip : ip_addresses) 
                {
                    event.ip_addresses.push_back(ip);
                }
                
                // Add description
                event.description = "User '" + username + 
                                   "' logged in from " + 
                                   std::to_string(ip_addresses.size()) + 
                                   " different IP addresses within " +
                                   std::to_string(time_window_minutes_) + " minutes";
                
                detected_events.push_back(event);
                
                // Skip to end of window
                i = window_end_idx;
            }
        }
    }
    
    return detected_events;
}

std::vector<SuspiciousEvent> EventDetector::detectAll(
    const std::vector<LogEntry>& entries) const
{
    std::vector<SuspiciousEvent> all_events;
    
    // Run all detection methods
    auto failed_logins = detectMultipleFailedLogins(entries);
    auto outside_hours = detectLoginsOutsideBusinessHours(entries);
    auto multiple_ips = detectMultipleIPAddresses(entries);
    
    // Combine all results
    all_events.insert(all_events.end(), failed_logins.begin(), failed_logins.end());
    all_events.insert(all_events.end(), outside_hours.begin(), outside_hours.end());
    all_events.insert(all_events.end(), multiple_ips.begin(), multiple_ips.end());
    
    return all_events;
}