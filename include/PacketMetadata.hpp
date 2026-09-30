/**
 * @file PacketMetadata.hpp
 * @brief Defines the core Data Transfer Object (DTO) for network packet information.
 * @details Encapsulates lightweight packet metadata stripped from raw network frames 
 *          to enable high-throughput processing across thread boundaries.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#ifndef PACKET_METADATA_HPP
#define PACKET_METADATA_HPP

#include <string>
#include <chrono>
#include <cstdint>

/**
 * @struct PacketMetadata
 * @brief Plain Data Container holding essential extracted packet properties.
 * @details Designed to pass from the ingestion engine (Producer) to the anomaly 
 *          detection engine (Consumer) via thread-safe queues. Omits heavy raw 
 *          payloads to minimize memory overhead.
 * 
 * @note To maximize performance across thread boundaries, instances should be 
 *       passed using std::move or passed by value.
 */
struct PacketMetadata{
    /// Source IPv4/IPv6 address represented as a string (e.g., "192.168.1.1").
    std::string source_ip;
    
    /// Destination IPv4/IPv6 address represented as a string.
    std::string dest_ip;

    /// Source TCP/UDP port number (0 to 65535). Defaults to 0.
    uint16_t source_port{0};

    /// Destination TCP/UDP port number (0 to 65535). Defaults to 0.
    uint16_t dest_port{0};

    /// Total size of the packet frame in bytes. Defaults to 0.
    size_t packet_size{0};

    //  High-precision timestamp capturing the exact moment of packet ingestion.
    std::chrono::system_clock::time_point timestamp;
};

#endif // PACKET_METADATA_HPP
