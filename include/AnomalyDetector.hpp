/**
 * @file AnomalyDetector.hpp
 * @brief High-performance streaming anomaly detection engine using Welford's algorithm.
 * @details Calculates running statistical metrics (Mean, Variance, StdDev) in O(1) memory
 *          and flags volume anomalies based on Z-Score statistical thresholding.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#ifndef ANOMALY_DETECTOR_HPP
#define ANOMALY_DETECTOR_HPP

#include "PacketMetadata.hpp"
#include <mutex>
#include <cmath>

/**
 * @struct AnomalyResult
 * @brief Evaluation metrics returned after analyzing a packet.
 */
struct AnomalyResult {
    bool is_anomaly{false};
    double z_score{0.0};
    double mean{0.0};
    double std_dev{0.0};
};

/**
 * @class AnomalyDetector
 * @brief Thread-safe statistical analyzer for real-time packet stream evaluations.
 */
class AnomalyDetector {
public:
    /**
     * @brief Constructor for the AnomalyDetector.
     * @param z_threshold Threshold multiplier for standard deviations (Defaults to 3.0).
     * @param min_samples Minimum required samples before triggering alerts (Defaults to 30).
     */
    explicit AnomalyDetector(double z_threshold = 3.0, size_t min_samples = 30);
    ~AnomalyDetector() = default;

    /**
     * @brief Evaluates a packet's metrics and updates running statistical state.
     * @param packet The PacketMetadata object containing packet metrics.
     * @return AnomalyResult evaluated metrics and alert flag.
     */
    AnomalyResult evaluate_and_update(const PacketMetadata& packet);

    /**
     * @brief Resets the internal Welford statistical state.
     */
    void reset();

private:
    double z_threshold_;
    size_t min_samples_;

    // Statistical State Variables for Welford's Algorithm
    size_t count_{0};
    double mean_{0.0};
    double M2_{0.0}; // Running sum of squared differences

    mutable std::mutex state_mutex_;
};

#endif // ANOMALY_DETECTOR_HPP