/**
 * @file AnomalyDetector.cpp
 * @brief Production-grade streaming Welford algorithm featuring Variance Floor protection.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#include "AnomalyDetector.hpp"
#include <algorithm>

AnomalyDetector::AnomalyDetector(double z_threshold, size_t min_samples)
    : z_threshold_(z_threshold), min_samples_(min_samples) {}

AnomalyResult AnomalyDetector::evaluate_and_update(const PacketMetadata& packet) {
    std::lock_guard<std::mutex> lock(state_mutex_);

    AnomalyResult result;
    double x = static_cast<double>(packet.packet_size);

    // 1. Calculate evaluation metrics if we have enough samples (Cold Start Protection)
    if (count_ >= min_samples_) {
        double variance = (count_ > 1) ? (M2_ / (count_ - 1)) : 0.0;
        result.std_dev = std::sqrt(variance);
        result.mean = mean_;
        
        // Apply Standard Deviation Floor (1.0 byte) to prevent Division-by-Zero 
        // and eliminate False Positives on uniform traffic streams.
        double effective_std_dev = std::max(result.std_dev, 1.0);

        result.z_score = (x - result.mean) / effective_std_dev;

        // Trigger anomaly if Z-Score exceeds threshold AND difference is meaningful (> 10 bytes)
        if (std::abs(result.z_score) > z_threshold_ && std::abs(x - result.mean) > 10.0) {
            result.is_anomaly = true;
        }

    }

    // 2. Update Welford's Algorithm Online State (O(1) Memory Space)
    count_++;
    double delta = x - mean_;
    mean_ += delta / count_;
    double delta2 = x - mean_;
    M2_ += delta * delta2;

    return result;
}

void AnomalyDetector::reset() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    count_ = 0;
    mean_ = 0.0;
    M2_ = 0.0;
}