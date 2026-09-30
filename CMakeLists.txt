# ==============================================================================
# Production-grade CMake Build Script
# Project: High-Performance Multi-threaded Network Traffic Analyzer
# Author: Yara Hneif
# Date: 2026
# ==============================================================================

cmake_minimum_required(VERSION 3.14)
project(NetworkAnalyzer VERSION 1.0.0 LANGUAGES CXX)

# Enforce C++17 standard compliance across all targets
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find System Dependencies (libpcap via PkgConfig)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Enable Strict Compiler Warnings for Production Quality
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -O3 # Optimization Level 3: High Throughput performance
)

# Core Application Source Files
set(SOURCES
    src/PacketIngestor.cpp
    src/AnomalyDetector.cpp
    src/Logger.cpp
)

# Build Main NetworkAnalyzer Executable
add_executable(NetworkAnalyzer src/main.cpp ${SOURCES})

# Target-Specific Include Directories (Modern CMake)
target_include_directories(NetworkAnalyzer PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

# Link Libraries
target_link_libraries(NetworkAnalyzer PRIVATE
    ${PCAP_LIBRARIES}
    pthread
)

# System Installation Rules
install(TARGETS NetworkAnalyzer DESTINATION bin)

# ==============================================================================
# Automated Testing Suite (CTest Integration)
# ==============================================================================
enable_testing()

# Helper Macro to register unit and integration tests cleanly
macro(add_network_analyzer_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE} src/AnomalyDetector.cpp src/Logger.cpp)
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(${TEST_NAME} PRIVATE pthread)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

# 1. Mathematical & Welford Anomaly Detector Unit Test
add_network_analyzer_test(test_anomaly_detector tests/test_anomaly_detector.cpp)

# 2. Concurrency & Backpressure ThreadSafeQueue Test
add_network_analyzer_test(test_thread_safe_queue tests/test_thread_safe_queue.cpp)

# 3. Packet Ingestor & Metadata Integrity Test
add_network_analyzer_test(test_packet_ingestor tests/test_packet_ingestor.cpp)

# 4. End-to-End Multi-threaded Pipeline Integration Test
add_network_analyzer_test(test_integration_pipeline tests/test_integration_pipeline.cpp)