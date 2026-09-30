/**
 * @file Logger.cpp
 * @brief Implementation of the thread-safe Logger class.
 * @details Handles synchronized timestamps formatting, terminal color-coding,
 *          and race-condition-free standard console logging.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */
#include "Logger.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>

// Explicit static member definition in memory: Allocate memory for the shared mutex
std::mutex Logger::log_mutex;

void Logger::log(LogLevel level, std::string_view message) {

    // RAII Lock Management: Automatically acquires mutex on construction,
    // and guarantees release on destruction even in the event of exceptions (safe cleanup even on exceptions).
    std::lock_guard<std::mutex> lock(log_mutex);
    
    // Capture high-precision current system timestamp
    const auto now = std::chrono::system_clock::now();
    const auto in_time_t = std::chrono::system_clock::to_time_t(now);

    // Thread-safe conversion to local time structure (POSIX safe variant)
    struct tm time_info{};
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&time_info, &in_time_t);
#else
    localtime_r(&in_time_t, &time_info); // POSIX Thread-safe variant
#endif
    // Format and print ISO-8601 extended timestamp ( ISO-like timestamp: [YYYY-MM-DD HH:MM:SS] )
    std::cout << "[" << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S") << "] ";

    
    // Apply ANSI Escape Codes for CLI visual distinction
    switch (level) {
        case LogLevel::INFO:
            std::cout << "\033[32m[INFO]\033[0m "; // Green
            break;
        case LogLevel::WARNING:
            std::cout << "\033[33m[WARN]\033[0m "; // Yellow
            break;
        case LogLevel::ERROR:
            std::cout << "\033[31m[ERROR]\033[0m "; // Red
            break;
        case LogLevel::ALERT:
            std::cout << "\033[1;31m[ALERT]\033[0m "; // Bold Red
            break;
    }

    // Print actual log message content and flush stdout buffer
    std::cout << message << std::endl;
}