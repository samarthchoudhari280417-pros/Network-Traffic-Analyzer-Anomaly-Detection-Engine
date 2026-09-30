/**
 * @file main.cpp
 * @brief Application entry point implementing a multi-threaded Producer-Consumer pipeline.
 * @details Spawns a dedicated consumer thread reading from a Bounded ThreadSafeQueue while 
 *          the libpcap ingestion loop acts as the producer thread. Handles POSIX signals
 *          to ensure clean thread joining and zero memory leaks.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#include "PacketIngestor.hpp"
#include "ThreadSafeQueue.hpp"
#include "AnomalyDetector.hpp"
#include "Logger.hpp"
#include <thread>
#include <csignal>
#include <memory>
#include <atomic>

/// Global unique pointer managing the PacketIngestor instance lifecycle.
std::unique_ptr<PacketIngestor> global_ingestor;

/// Global thread-safe queue bridging Producer and Consumer threads.
ThreadSafeQueue<PacketMetadata> packet_queue;

/// Atomic flag controlling the lifecycle of concurrent background worker threads.
std::atomic<bool> is_running{true};

/**
 * @brief POSIX Signal Handler for graceful multi-threaded shutdown.
 * @param signal Numeric signal identifier (SIGINT, SIGTERM).
 */
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        Logger::log(LogLevel::WARNING, "Shutdown signal received. Stopping threads safely...");
        
        is_running = false;
        
        // Unblock waiting consumer threads
        packet_queue.stop();
        
        // Break the libpcap ingestion loop
        if (global_ingestor) {
            global_ingestor->stop_capture();
        }
    }
}

/**
 * @brief Worker function for the Consumer Thread processing packets from the queue.
 */
void consumer_worker() {
    Logger::log(LogLevel::INFO, "Consumer Thread started successfully.");
    
    while (is_running) {
        // Blocking pop from the Bounded ThreadSafeQueue
        auto packet_opt = packet_queue.pop();
        if (!packet_opt.has_value()) {
            break; // Queue was stopped
        }

        const auto& meta = packet_opt.value();
        
        // Process packet metadata (Decoupled from ingestion thread)
        std::string msg = "Processed via Queue: " + meta.source_ip + ":" + std::to_string(meta.source_port) + 
                          " -> " + meta.dest_ip + ":" + std::to_string(meta.dest_port) + 
                          " | Size: " + std::to_string(meta.packet_size) + " bytes";
        
        Logger::log(LogLevel::INFO, msg);
    }

    Logger::log(LogLevel::INFO, "Consumer Thread terminated gracefully.");
}

/**
 * @brief Application main entry point.
 */
int main(int argc, char* argv[]) {
    std::string interface = "eth0";
    if (argc > 1) {
        interface = argv[1];
    }

    // Register POSIX Signal Handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    Logger::log(LogLevel::INFO, "Starting Multi-threaded Network Analyzer Pipeline...");

    // Spawn Consumer Thread in the background
    std::thread consumer_thread(consumer_worker);

    global_ingestor = std::make_unique<PacketIngestor>(interface);

    // Producer Loop: Ingestion thread pushes incoming packets straight to queue
    global_ingestor->start_capture([](const PacketMetadata& meta) {
        packet_queue.push(meta);
    });

    // Safely await Consumer Thread completion on exit
    if (consumer_thread.joinable()) {
        consumer_thread.join();
    }

    Logger::log(LogLevel::INFO, "Application exit complete.");
    return 0;
}