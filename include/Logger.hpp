/**
 * @file Logger.hpp
 * @brief Thread-safe logging facility for application-wide status and error reporting.
 * @details Provides a unified, thread-safe static logging mechanism capable of formatting
 *          and synchronizing messages originating from multiple concurrent threads.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <mutex>
#include <string_view>

/**
 * @enum LogLevel
 * @brief Strongly-typed enumeration representing severity levels for log entries.
 */
 enum class LogLevel {
    INFO,    ///< Standard operational messages and throughput statistics.
    WARNING, ///< Non-critical anomalies or recoverable network drop warnings.
    ERROR,   ///< Runtime errors requiring immediate operational attention.
    ALERT    ///< High-severity statistical traffic anomalies (e.g., Z-score > 3.0).
};

/**
 * @class Logger
 * @brief Thread-safe static utility class for logging events.
 * @details Utilizes a shared static std::mutex to synchronize concurrent output operations 
 *          to stdout/stderr, preventing console output corruption (interleaving).
 */
class Logger {
public:
    // Disallow instantiation for a pure static utility class
    Logger() = delete;

    /**
     * @brief Logs a synchronized message with a specified severity level.
     * 
     * @param level The severity level of the log message (INFO, WARNING, ERROR, ALERT).
     * @param message The descriptive log message content.
     * 
     * @note This function is fully thread-safe and blocking.
     * @note Optimized in C++17 using (std::string_view) instead of (const std::string&)
     *       to avoid unnecessary memory allocations for string literals.
     */  
    static void log(LogLevel level, std::string_view message);

    private:
    /// Static mutex ensuring mutual exclusion during console output operations.
    static std::mutex log_mutex;
};

#endif // LOGGER_HPP