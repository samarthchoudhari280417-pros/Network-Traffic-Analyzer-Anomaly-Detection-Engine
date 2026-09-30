# 🛡️ High-Performance Multi-threaded Network Analyzer & Anomaly Detector

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Linux](https://img.shields.io/badge/Platform-Linux%20%2F%20POSIX-orange.svg)
![Build](https://img.shields.io/badge/Build-CMake%203.14%2B-green.svg)
![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)
> A C++17 real-time network packet ingestion engine, thread-safe Producer-Consumer pipeline, and streaming $O(1)$ memory anomaly detection system.

An enterprise-grade, real-time network traffic analysis engine written in modern **C++17**. The system captures live raw network packets at high speed, processes headers concurrently across multi-core processors using a decoupled **Producer-Consumer pipeline**, and detects statistical traffic anomalies (e.g., DDoS spikes or packet flooding) in **$O(1)$ memory complexity** using **Welford's Streaming Algorithm**.

---

## 📖 Table of Contents
1. [Executive Summary & Problem Statement](#-1-executive-summary--problem-statement)
2. [The Architectural Solution](#-2-the-architectural-solution)
3. [System Architecture & Data Flow](#-3-system-architecture--data-flow)
4. [Project Structure & Layout](#-4-project-structure--layout)
5. [How the Engine Works: Simple Analogy & Mathematical Intuition](#-5-how-the-engine-works-simple-analogy--mathematical-intuition)
    
    5.1. [Understanding the Mathematics (Made Simple)](#-understanding-the-mathematics-made-simple)

    5.2 [Simplifying the Core Algorithms (For Everyone)](#-5-simplifying-the-core-algorithms-for-everyone)
    - [A. Real-World Analogy](#a-real-world-analogy-airport-cargo-inspection)
    - [B. Welford's Algorithm ($O(1)$ Memory Space)](#b-welfords-algorithm-o1-memory-space)
    - [C. Z-Score Statistical Thresholding](#c-z-score-statistical-thresholding)
    - [D. Producer-Consumer Pattern & Backpressure](#d-producer-consumer-pattern--backpressure)
6. [Building & Running the Project](#-6-building--running-the-project)
7. [Running the Automated Test Suite](#-7-running-the-automated-test-suite)
8. [Performance & Thread Safety Guarantees](#-8-performance--thread-safety-guarantees)
9. [Key C++17 Engineering Concepts](#-9-key-c17-engineering-concepts)
10. [Author & License](#-10-author--license)

---
## 📌 1. Executive Summary & Problem Statement

### 🔍 The Problem
In modern data centers and cloud infrastructure, network traffic streams at millions of packets per second. Detecting threats like **DDoS (Distributed Denial of Service) attacks**, **packet flooding**, or **data exfiltration** requires analyzing packet headers in real-time.

Traditional naive approaches face three critical engineering bottlenecks:
1. **The I/O Bottleneck:** Parsing packets and running heavy statistical analysis on the same thread causes dropped packets (*Packet Loss*), as the interface receives data faster than the application can process it.
2. **The Memory Bottleneck:** Calculating statistical metrics like mean and standard deviation over historical packets typically requires storing long historical windows in memory—leading to $O(N)$ memory growth and eventual **Out-Of-Memory (OOM) crashes**.
3. **The Unsafe Shutdown Problem:** Forcefully closing a network monitoring tool using `Ctrl + C` can freeze the network interface card (NIC) or corrupt active memory sockets.

---
## 💡 2. The Architectural Solution

To solve all three bottlenecks, this engine decouples packet capture from analytical processing using modern `C++17` concurrency best practices and online streaming mathematics:

1. **Decoupled Producer-Consumer Architecture:** 
   * **Producer Thread (`PacketIngestor`):** Uses `libpcap` to capture raw network frames in promiscuous mode and pushes lightweight `PacketMetadata` DTOs directly into a thread-safe bounded queue. The network capture thread never pauses or waits for analysis!
   * **Consumer Thread (`AnomalyDetector`):** Runs concurrently in the background, pulling packets from the queue to execute statistical checks without freezing or dropping packets at the network interface.
2. **Bounded Backpressure Flow Control:** The thread-safe queue enforces a fixed capacity limit. If the processing thread lags behind during traffic surges, the buffer safely pauses the producer to prevent memory inflation and **Out-Of-Memory (OOM)** crashes.
3. **$O(1)$ Streaming Mathematics (Welford's Algorithm):** Calculates the running mean and variance continuously in constant memory space ($O(1)$) without storing past packet history—ensuring flat memory usage whether the system runs for 5 seconds or 5 years.
4. **POSIX Signal Handling (Graceful Shutdown):** Intercepts system termination signals (`SIGINT`/`SIGTERM`) to unblock all threads safely, flush memory queues, close raw handles, and exit with zero resource leaks.

---
## 🏗️ 3. System Architecture & Data Flow


Below is the conceptual architecture showing how raw hardware signals travel through our software pipeline:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PHYSICAL NETWORK CARD (NIC)                         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Raw Network Frames
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      PRODUCER THREAD (PacketIngestor)                       │
│  - Promiscuous Mode (libpcap)                                               │
│  - Offsets Ethernet Header (14 bytes) -> Extracts IPv4 Headers              │
│  - Strips Payload, keeps lightweight PacketMetadata DTO                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ PacketMetadata (Pushed)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BOUNDED THREAD-SAFE QUEUE (Buffer)                       │
│  - Synchronized via std::mutex & std::condition_variable                    │
│  - Prevents OOM via Backpressure Mechanism                                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ PacketMetadata (Popped)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CONSUMER THREAD (AnomalyDetector)                       │
│  - Calculates Streaming Mean & StdDev via Welford's Algorithm ($O(1)$)      │
│  - Calculates Z-Score per packet                                            │
│  - If Z-Score > 3.0 -> Triggers Colorized Console Log Alert (Logger)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---
## 📂 4. Project Structure & Architecture
```text
NetworkAnalyzer/
├── CMakeLists.txt            # Production-grade CMake build script with CTest
├── include/
│   ├── PacketMetadata.hpp    # Lightweight DTO holding extracted packet features
│   ├── ThreadSafeQueue.hpp   # Bounded thread-safe FIFO queue with Backpressure
│   ├── PacketIngestor.hpp    # RAII wrapper around libpcap raw network sockets
│   ├── AnomalyDetector.hpp   # Thread-safe streaming Welford anomaly engine
│   └── Logger.hpp            # Synchronized, color-coded thread-safe logging framework
├── src/
│   ├── PacketIngestor.cpp    # Promiscuous interface binding & offset parsing
│   ├── AnomalyDetector.cpp   # Online Welford & Z-score implementation
│   ├── Logger.cpp            # ANSI color-coded stdout logger
│   └── main.cpp              # Multi-threaded entry point with POSIX Signal Handler
├── tests/
│   ├── test_packet_ingestor.cpp    # Unit test for metadata integrity
│   ├── test_thread_safe_queue.cpp  # Concurrent stress test for queue synchronization
│   ├── test_anomaly_detector.cpp   # Mathematical validation of Welford & Z-Score
│   └── test_integration_pipeline.cpp # End-to-End multi-threaded integration pipeline
└── README.md                 # Project documentation
```

---
## 💡 5. How the Engine Works: Simple Analogy & Mathematical Intuition
## 🧮 Understanding the Mathematics (Made Simple)

Even if you don't have a background in statistics, the core algorithm can be understood through three basic questions:

### 1. What is Normal Traffic? (Running Mean & Variance)
Instead of keeping a list of all past packet sizes (e.g., `[64, 64, 128, 64, ...]`):
* **Welford's Algorithm** keeps track of only **three numbers**:
  * `count`: Total number of packets seen so far.
  * `mean`: The current average packet size.
  * `M2`: The running sum of squared differences from the mean.

Whenever a new packet arrives, the algorithm updates the average and variance instantly in $O(1)$ constant time and $O(1)$ constant memory space.

### 2. How Do We Spot Anomalies? (The $Z\text{-Score}$)
The $Z\text{-score}$ measures how many standard deviations a packet size ($x$) strays from the historical average ($\mu$):

$$\text{Z-Score} = \frac{x - \mu}{\sigma}$$

* **Normal Range:** $Z\text{-Score} \le 3.0$ (Captures 99.73% of standard network behavior under Normal Gaussian Distribution).
* **Anomaly Flag:** $Z\text{-Score} > 3.0$ (Spike in packet size or packet frequency signaling potential DDoS or anomaly).

### 3. Preventing False Alarms (Cold Start Protection)
During the first few seconds of execution (fewer than 30 packets), the engine suppresses alerts. This gives the statistical model time to establish a reliable baseline before flagging outliers.

---
## 🧠 Simplifying the Core Algorithms (For Everyone)
### A. Real-World Analogy (Airport Cargo Inspection)
Imagine a busy international airport where thousands of suitcases arrive every minute:

* **Without Our System (Traditional Way):** One security guard stands at the airplane door. He takes a suitcase, opens it, measures it, calculates its weight against all suitcases that have ever arrived today, and writes a report. Meanwhile, 100 other airplanes are waiting in the sky because the guard is too slow. Suitcases get lost!

* **With Our System (Our Design):**

    * **The Ingestion Guard (Producer):** Stands at the airplane door. He only tags each suitcase with a small sticky note (IP address, size, timestamp) and throws it onto a conveyor belt (ThreadSafeQueue). He never stops moving!

    * **The Analysis Guard (Consumer):** Stands at the end of the conveyor belt. He reads the sticky note, updates his running counter on a small whiteboard, and immediately clears the belt. If a massive 500 kg suitcase suddenly arrives, he blows a warning whistle (Anomaly Alert!).

### B. Welford's Algorithm ($O(1)$ Memory Space)
> **Plain English Explanation:**
> Imagine trying to calculate the average height of everyone in a football stadium.
> * **Traditional Method:** Write down the height of all 80,000 people on a giant piece of paper, add them up, and divide by 80,000. *(Requires giant paper / lots of memory).*
> * **Welford's Method:** You only keep track of **three numbers**: how many people you've seen so far ($N$), the current average ($\mu$), and a small difference factor ($M_2$). Every time a new person arrives, you update your average using only their height and your previous 3 numbers. You throw away their height immediately!


**Mathematical Equations Used:**
$$\Delta = x_n - \mu_{n-1}$$
$$\mu_n = \mu_{n-1} + \frac{\Delta}{n}$$
$$M_{2,n} = M_{2,n-1} + \Delta \times (x_n - \mu_n)$$
$$\text{Variance} (\sigma^2) = \frac{M_{2,n}}{n - 1} \quad \implies \quad \text{StdDev} (\sigma) = \sqrt{\text{Variance}}$$


---


### C. Z-Score Statistical Thresholding
> **Plain English Explanation:**
> If most packets on your network are around **64 bytes** (like tiny text messages), and suddenly a packet arrives that is **1,500 bytes** (like a massive video file), is it dangerous?
> The **Z-Score** measures *how many standard deviations* a new packet is away from the normal average traffic.


$$\text{Z-Score} = \frac{\text{Packet Size} - \text{Mean Size}}{\text{Standard Deviation}}$$


* **Z-Score between -3.0 and +3.0:** Normal traffic (**99.73%** of all standard data falls here according to the Gaussian Normal Distribution).
* **Z-Score > 3.0:** Extreme Outlier! The packet is abnormally large compared to current network trends. Triggers an instant **`ALERT`** log.


---


### D. Producer-Consumer Pattern & Backpressure
> **Plain English Explanation:**
> Think of a busy restaurant kitchen.
> * **The Producer (Waiter):** Brings orders from customers as fast as possible.
> * **The Consumer (Chef):** Cooks the meals.
> * **Backpressure (The Limit):** If the counter holds max 10 order slips and it becomes full, the waiter stops taking new orders briefly until the chef finishes cooking a dish. This prevents orders from piling up onto the floor!


---



### 🚗 Simple Analogy (Airport Cargo Inspection)
Imagine a busy international airport where thousands of suitcases arrive every minute:
* **Without Our System (The Old Way):** One security guard stands at the airplane door. He takes a suitcase, opens it, measures it, calculates its weight against all suitcases ever arrived today, and writes a report. Meanwhile, 100 other airplanes are waiting in the sky because the guard is too slow. Suitcases get lost!
* **With Our System (Our Design):**
  * **The Ingestion Guard (Producer):** Stands at the airplane door. He only tags each suitcase with a small sticky note (IP address, size, timestamp) and throws it onto a conveyor belt (`ThreadSafeQueue`). He never stops moving!
  * **The Analysis Guard (Consumer):** Stands at the end of the conveyor belt. He reads the sticky note, updates his running counter on a small whiteboard, and immediately clears the belt. If a massive 500 kg suitcase suddenly arrives, he blows a warning whistle (Anomaly Alert!).


---


### 📊 The Mathematics Made Simple


#### 1. What is Welford's Algorithm?
Traditionally, to calculate the average and variation of numbers, you must keep all past numbers in a notebook and sum them up again every time a new number arrives.


**Welford's Algorithm** allows us to calculate the exact running average ($\mu$) and variance ($\sigma^2$) using only **3 numbers** stored in memory, updated step-by-step:
$$\mu_k = \mu_{k-1} + \frac{x_k - \mu_{k-1}}{k}$$
$$M_{2,k} = M_{2,k-1} + (x_k - \mu_{k-1})(x_k - \mu_k)$$


* $x_k$: Size of the newly arrived packet.
* $\mu_k$: Updated running mean.
* $M_2$: Running sum of squared differences (used to compute variance $\sigma^2 = \frac{M_2}{k-1}$).


> **Why this matters:** It guarantees zero memory leaks, ultra-fast performance, and maximum numerical stability over weeks of uninterrupted operation.


---


#### 2. What is Z-Score?
The **Z-Score** measures how many "standard deviations" a specific packet's size is away from the normal average traffic size:


$$Z = \frac{x - \mu}{\sigma}$$


* According to Gaussian distribution principles, **99.73%** of normal network traffic falls within a Z-Score range between $-3.0$ and $+3.0$.
* If a packet arrives with a **$Z > 3.0$**, there is less than a **0.27% chance** that it is normal traffic. The engine flags it immediately as an **Anomaly Alert**.


---

## 🛠️ 6. Building & Running the Project
### Prerequisites (Ubuntu / Linux)

* **Operating System:** Linux (Ubuntu 22.04 / 24.04 LTS recommended)
* **Compiler:** GCC `g++` (v13+ supporting C++17)
* **Build System:** `CMake` (v3.14+)
* **Dependencies:** `libpcap-dev`

```bash
# Install dependencies on Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
```
### Compiling the Project
```Bash
# 1. Clone or navigate to the repository
cd NetworkAnalyzer 

# 2. Create build directory
mkdir build && cd build

# 3. Generate build files and compile
cmake ..
make -j$(nproc)
```
### Running Automated Test Suite (CTest)
``` bash
ctest --output-on-failure
```
### Running the Analyzer
Note: Capturing raw network packets requires root or raw socket privileges (sudo).
``` Bach
# Run on default interface (eth0)
sudo ./NetworkAnalyzer

# Or specify a target interface (e.g., wlan0)
sudo ./NetworkAnalyzer wlan0
```

## 🧪 7. Running the Automated Test Suite
The project includes an integrated testing suite via `CTest`. All unit and integration **tests validate thread safety**, **mathematical precision**, and **edge cases**.

 To execute all tests simultaneously:

```Bash
cd build
ctest --output-on-failure
```
#### Individual Test Capabilities:
- `test_packet_ingestor`: Validates correct parsing of packet size and header offsets.

- `test_thread_safe_queue`: Runs concurrent multi-threaded push/pop operations under heavy load to test data races and deadlocks.

- `test_anomaly_detector`: Verifies Welford's algorithm convergence, standard deviation accuracy, and Z-score triggers.


- `test_integration_pipeline`: Validates end-to-end multi-threaded data flow from ingestion to anomaly logging.



## ⚡ 8. Performance & Thread Safety Guarantees

| Metric / Feature | Guarantee & Implementation Details |
| :--- | :--- |
| **Language Standard** | C++17 compiled with strict flags (`-Wall -Wextra -Wpedantic -Werror -O3`) |
| **Memory Complexity** | $O(1)$ Constant Memory space via Welford's Streaming Algorithm |
| **Time Complexity** | $O(1)$ per-packet analytical processing
| **Concurrency Pattern** | Decoupled Producer-Consumer using `std::thread` |
| **Synchronization** | Guarded with `std::mutex`, `std::unique_lock`, and `std::condition_variable` |
| **Data Race Safety** | Zero Data Races (verified via ThreadSanitizer & RAII locks) |
| **Memory Management** | "100% RAII compliant (`std::unique_ptr`, zero raw memory allocations))" |
| **Shutdown Protection** | Graceful shutdown (`SIGINT`/`SIGTERM`) with automatic resource cleanup
 |
## 🏛️ 9. Key C++17 Engineering Concepts Implemented

* **RAII (Resource Acquisition Is Initialization):** Encapsulates raw C handles (`pcap_t*`) into C++ objects ensuring clean cleanup on destruction.

* **Concurrency Primitives:** Uses `std::mutex`, `std::unique_lock`, `std::lock_guard`, and `std::condition_variable` to eliminate Data Races and Deadlocks.

* **Backpressure Management:** Bounded ThreadSafeQueue blocks producers when capacity is full to prevent Out-Of-Memory (OOM) exceptions.

* **Signal Safety:** Intercepts POSIX signals (`SIGINT`, `SIGTERM`) to trigger graceful teardowns and clean thread joins.

* **Move Semantics (`std::move`):** Passes metadata across threads with zero unnecessary heap allocations.
## 👩‍💻 10. Author & License
* **Designed and engineered by `Yara Hneif (2026)`.**

* **Domain: `Computer Science` / `High-Performance Systems Programming`.**

* **License: Distributed under the MIT License. Developed for high-performance systems engineering and network security operations.**

