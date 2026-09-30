/**
 * @file ThreadSafeQueue.hpp
 * @brief Bounded Thread-safe FIFO queue implementation with Backpressure support.
 * @details Utilizes dual std::condition_variable instances to block producers when 
 *          capacity is reached and consumers when empty, preventing OOM crashes.
 * 
 * @project High-Performance Multi-threaded Network Traffic Analyzer
 * @author Yara Hneif
 * @date 2026
 */

#ifndef THREAD_SAFE_QUEUE_HPP
#define THREAD_SAFE_QUEUE_HPP

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

/**
 * @class ThreadSafeQueue
 * @brief Thread-safe Bounded FIFO queue supporting Producer Backpressure.
 * @tparam T Type of elements stored in the queue.
 */
template <typename T>
class ThreadSafeQueue {
public:
    /**
     * @brief Constructor initializing the queue capacity bound.
     * @param capacity Maximum number of elements allowed in the queue (Defaults to 10,000).
     */
    explicit ThreadSafeQueue(size_t capacity = 10000) 
        : capacity_(capacity) {}

    ~ThreadSafeQueue() = default;

    // Disallow copying to ensure thread safety integrity
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    /**
     * @brief Pushes an item into the queue. Blocks Producer if queue capacity is reached.
     * @param value Item to be moved into the queue.
     * @return true if pushed successfully, false if queue was stopped.
     */
    bool push(T value) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            
            // Block producer if capacity limit reached (Backpressure)
            cv_producer_.wait(lock, [this] { return queue_.size() < capacity_ || stop_flag_; });

            if (stop_flag_) {
                return false;
            }

            queue_.push(std::move(value));
        }
        
        // Signal one waiting consumer thread that data is available
        cv_consumer_.notify_one();
        return true;
    }

    /**
     * @brief Blocks Consumer until an item is available, then pops and returns it.
     *        Signals waiting Producers upon freeing queue slots.
     * @return std::optional<T> containing popped item, or std::nullopt if queue stopped.
     */
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // Wait until queue is non-empty or stop is requested
        cv_consumer_.wait(lock, [this] { return !queue_.empty() || stop_flag_; });

        if (queue_.empty() && stop_flag_) {
            return std::nullopt;
        }

        T value = std::move(queue_.front());
        queue_.pop();

        // Unlock before notifying waiting producers
        lock.unlock();
        cv_producer_.notify_one();

        return value;
    }

    /**
     * @brief Stops the queue and unblocks ALL waiting producers and consumers.
     */
    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_flag_ = true;
        }
        // Wake up both blocked consumers AND blocked producers for clean termination
        cv_consumer_.notify_all();
        cv_producer_.notify_all();
    }

    /**
     * @brief Returns current element count in a thread-safe manner.
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    /**
     * @brief Checks if queue is currently full.
     */
    bool is_full() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size() >= capacity_;
    }

private:
    std::queue<T> queue_;
    size_t capacity_;
    mutable std::mutex mutex_;
    
    std::condition_variable cv_consumer_; ///< Signals consumers when queue is non-empty
    std::condition_variable cv_producer_; ///< Signals producers when queue has free space
    
    bool stop_flag_{false};
};

#endif // THREAD_SAFE_QUEUE_HPP