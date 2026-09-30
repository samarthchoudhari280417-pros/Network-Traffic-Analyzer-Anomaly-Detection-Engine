/**
 * @file PacketIngestor.cpp
 * @brief Implementation of the libpcap packet ingestion layer.
 * @details Handles promiscuous interface binding, offset-based header parsing,
 *          and thread-safe IP address conversions.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#include "PacketIngestor.hpp"
#include "Logger.hpp"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <utility>

PacketIngestor::PacketIngestor(std::string interface_name)
    : interface_name_(std::move(interface_name)) {}

PacketIngestor::~PacketIngestor() {
    // RAII Cleanup: Close handle safely after loop termination
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool PacketIngestor::start_capture(PacketCallback callback) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open device in Promiscuous mode (1) with 1000ms read timeout
    pcap_handle_ = pcap_open_live(interface_name_.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!pcap_handle_) {
        Logger::log(LogLevel::ERROR, "Failed to open interface " + interface_name_ + ": " + errbuf);
        return false;
    }

    is_running_ = true;
    Logger::log(LogLevel::INFO, "Listening on interface: " + interface_name_);

    // Execute capture loop passing callback via opaque user pointer
    pcap_loop(pcap_handle_, 0, PacketIngestor::packet_handler, reinterpret_cast<u_char*>(&callback));

    is_running_ = false;
    Logger::log(LogLevel::INFO, "Packet capture loop terminated safely.");
    return true;
}

void PacketIngestor::stop_capture() {
    // Async-Signal-Safe: Only break the pcap loop. Do NOT call pcap_close here to prevent Use-After-Free race conditions.
    if (is_running_ && pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
}

void PacketIngestor::packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* callback = reinterpret_cast<PacketCallback*>(user_data);
    
    // Ethernet Header Offset (14 bytes)
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + 14);
    
    if (ip_header->ip_v == 4) { // IPv4 Packet Filtering
        PacketMetadata meta;
        
        char src_buffer[INET_ADDRSTRLEN];
        char dst_buffer[INET_ADDRSTRLEN];

        // Thread-safe IP address string conversion
        inet_ntop(AF_INET, &(ip_header->ip_src), src_buffer, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_buffer, INET_ADDRSTRLEN);

        meta.source_ip = src_buffer;
        meta.dest_ip = dst_buffer;
        meta.packet_size = pkthdr->len;
        meta.timestamp = std::chrono::system_clock::now();

        // Extract Transport Ports
        uint8_t protocol = ip_header->ip_p;
        size_t ip_header_len = ip_header->ip_hl * 4; // Header length in 32-bit words
        
        if (protocol == IPPROTO_TCP) {
            const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + 14 + ip_header_len);
            meta.source_port = ntohs(tcp_header->th_sport);
            meta.dest_port = ntohs(tcp_header->th_dport);
        } else if (protocol == IPPROTO_UDP) {
            const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet + 14 + ip_header_len);
            meta.source_port = ntohs(udp_header->uh_sport);
            meta.dest_port = ntohs(udp_header->uh_dport);
        }

        // Invoke high-level C++ callback
        if (callback && *callback) {
            (*callback)(meta);
        }
    }
}