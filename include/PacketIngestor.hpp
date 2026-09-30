/**
 * @file PacketIngestor.hpp
 * @brief Header for the libpcap wrapper encapsulating packet ingestion logic.
 * @details Implements a thread-safe RAII-compliant network interface listener that captures 
 *          raw network frames and yields structured metadata via lightweight callbacks.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#ifndef PACKET_INGESTOR_HPP
#define PACKET_INGESTOR_HPP

#include "PacketMetadata.hpp"
#include <pcap.h>
#include <string>
#include <functional>
#include <atomic>

/**
 * @class PacketIngestor
 * @brief High-level C++17 wrapper around raw libpcap network capture handles.
 * @details Responsible for binding to network interfaces, executing capture loops,
 *          parsing raw IP/TCP headers, and forwarding metadata to processing threads.
 */
class PacketIngestor {
public:
/// Type alias for the processing callback invoked on every captured packet.
    using PacketCallback = std::function<void(const PacketMetadata&)>;

    /**
     * @brief Explicit constructor binding the ingestor to a specific network interface.
     * @param interface_name Device interface identifier (e.g., "eth0", "wlan0", or pcap file path).
     */
    explicit PacketIngestor(std::string interface_name);
    
    /**
     * @brief Destructor delivering RAII guarantees by safely stopping capture and releasing pcap handles.
     */
    ~PacketIngestor();

    // Prevent copying to guarantee exclusive ownership of the underlying pcap handle
    // Disable copy operations to prevent double-free of raw handles
    PacketIngestor(const PacketIngestor&) = delete;
    PacketIngestor& operator=(const PacketIngestor&) = delete;

    // Allow Move operations/semantics for resource transfer (Optional / Good Practice)
    PacketIngestor(PacketIngestor&&) noexcept = default;
    PacketIngestor& operator=(PacketIngestor&&) noexcept = default;

    /**
     * @brief Starts the network capture loop on the bound interface.
     * @param callback High-performance callback function invoked per captured frame.
     * @return true if interface initialization and loop startup succeeded, false otherwise.
     */
    bool start_capture(PacketCallback callback);

    /**
     * @brief Signals the ingestion loop to terminate gracefully and releases device locks.
     */
    void stop_capture();

private:
    /// Target network interface identifier or file path.
    std::string interface_name_;

    /// Raw pointer to the libpcap capture session handle.
    pcap_t* pcap_handle_{nullptr};

    /// Atomic boolean controlling execution state across thread boundaries.
    std::atomic<bool> is_running_{false};

    /**
     * @brief C-compatible static callback bridge for libpcap processing.
     * @param user_data Opaque pointer referencing the parent PacketIngestor instance (`this`).
     * @param pkthdr Header containing capture metadata (timestamp, length, wire size).
     * @param packet Raw byte payload buffer captured from the network interface.
     */
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // PACKET_INGESTOR_HPP