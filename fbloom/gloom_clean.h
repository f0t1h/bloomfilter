// Gloom Filter without any dependencies




#ifndef GLOOM_CLEAN_H
#define GLOOM_CLEAN_H

#include <thread>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <algorithm>


#ifndef QUEUE_IMPL
#include "concurrentqueue.h"
#define QUEUE_IMPL moodycamel::ConcurrentQueue
#endif

#ifndef GLOOM_SCOPE
#define GLOOM_SCOPE inline
#endif

namespace fbloom {

class GloomFilter2 {
    static constexpr unsigned BULK_READ_MAX = 512;
public:
    GloomFilter2(size_t num_threads, size_t expected_elements, double false_positive_rate);
    GloomFilter2(const GloomFilter2 &) = delete;
    GloomFilter2 &operator=(const GloomFilter2 &) = delete;
    GloomFilter2(GloomFilter2 &&other) noexcept;


    void Insert(uint32_t h1, uint32_t h2, int tid);
    bool Contains(uint32_t h1, uint32_t h2);
    void Clear();
    size_t BitArraySize() const;
    size_t NumHashFunctions() const;
    size_t TotalBitsUsed() const;
private:
    size_t num_threads;
    size_t expected_elements;
    double false_positive_rate;
    size_t bit_array_size;
    size_t num_hash_functions;
    std::vector<std::vector<uint8_t>> filters;
    std::vector<QUEUE_IMPL<std::pair<uint32_t, uint32_t>>> queues;
    std::vector<std::vector<std::pair<uint32_t, uint32_t>>> bulk_reading;
};

} // namespace fbloom
#define GLOOM_IMPLEMENTATION
#ifdef GLOOM_IMPLEMENTATION
namespace fbloom {
GLOOM_SCOPE GloomFilter2::GloomFilter2(size_t num_threads, size_t expected_elements, double false_positive_rate)
    : num_threads(num_threads), expected_elements(expected_elements), false_positive_rate(false_positive_rate),
        bit_array_size{BitArraySize()}, num_hash_functions(NumHashFunctions()), filters(num_threads, std::vector<uint8_t>(bit_array_size, 0)), queues(num_threads), bulk_reading(num_threads) {
}

GLOOM_SCOPE GloomFilter2::GloomFilter2(GloomFilter2 &&other) noexcept
    : num_threads(other.num_threads), expected_elements(other.expected_elements), false_positive_rate(other.false_positive_rate),
      bit_array_size(other.bit_array_size), num_hash_functions(other.num_hash_functions),
      filters(std::move(other.filters)), queues(std::move(other.queues)), bulk_reading(std::move(other.bulk_reading)) {
}

GLOOM_SCOPE void GloomFilter2::Insert(uint32_t h1, uint32_t h2, int tid) {
    {
        queues[tid].try_dequeue_bulk(
            std::back_inserter(bulk_reading[tid]), BULK_READ_MAX);
        for(const auto &[h1, h2] : bulk_reading[tid])
        {
            for(size_t j = 0; j < num_hash_functions; j++)
            {
                uint32_t hash = (h1 + j * h2) % bit_array_size;
                uint64_t bit_idx = hash % 8;
                uint64_t byte_idx = hash / 8;
                filters[tid][byte_idx] |= (1 << bit_idx);
            }
        }
        // Clear the bulk reading buffer after processing
        bulk_reading[tid].clear();
    }
    if(tid == ((h1>>16)&(num_threads-1))){
        for(size_t i = 0; i < num_hash_functions; i++)
        {
            uint32_t hash = (h1 + i * h2) % bit_array_size;
            uint64_t bit_idx = hash % 8;
            uint64_t byte_idx = hash / 8;
            filters[tid][byte_idx] |= (1 << bit_idx);
        }
    }
    else{
        while(!queues[tid].try_enqueue({h1, h2})) { std::this_thread::sleep_for(std::chrono::microseconds(1));}
    }
}

GLOOM_SCOPE bool GloomFilter2::Contains(uint32_t h1, uint32_t h2) {
    // TODO: Implement
    auto &target_filter = filters[(h1>>16)&(num_threads-1)];
    bool result = true;
    for(size_t i = 0; i < num_hash_functions; i++)
    {
        uint32_t hash = (h1 + i * h2) % bit_array_size;
        uint64_t bit_idx = hash % 8;
        uint64_t byte_idx = hash / 8;
        result &= (target_filter[byte_idx] >> bit_idx) & 1;
    }
    return result;
}

GLOOM_SCOPE void GloomFilter2::Clear() {
    std::fill(filters.begin(), filters.end(), std::vector<uint8_t>(bit_array_size, 0));
}



GLOOM_SCOPE size_t GloomFilter2::BitArraySize() const {
    // Calculate total bits needed, then divide by threads for per-thread allocation
    size_t total_bits = static_cast<size_t>(
        -1.44 * expected_elements * std::log2(false_positive_rate) + 0.5);
    return (total_bits + num_threads - 1) / num_threads; // Round up division
}

GLOOM_SCOPE size_t GloomFilter2::NumHashFunctions() const {
    if (expected_elements == 0) return 1;
    // Use total bit array size (per-thread * num_threads) for hash function calculation
    size_t total_bit_array_size = bit_array_size * num_threads;
    return static_cast<size_t>((double)total_bit_array_size / expected_elements * 0.6931471805599453 + 0.5);
}

GLOOM_SCOPE size_t GloomFilter2::TotalBitsUsed() const {
    // bit_array_size is already in bits per thread, so multiply by num_threads
    return bit_array_size * num_threads;
}

} // namespace fbloom
#endif

#endif