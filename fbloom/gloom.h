#ifndef GLOOM_H
#define GLOOM_H

#include "bloom.h"
#include "concurrentqueue.h"
#include "external/xxhash.h"

#include <array>
#include <cmath>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>

namespace fbloom {
struct bits {
  uint64_t N;
  uint64_t long_count;
  std::vector<uint64_t> bitv;
  bits() : N(64), long_count(1), bitv(1, 0) {}
  bits(uint64_t Nbits)
      : N([&]() {
          uint64_t r = (Nbits < 64) ? 64 : ((Nbits + 63) / 64) * 64;
          return r;
        }()),
        long_count(N / 64), bitv(long_count, 0) {}
  void set(uint64_t index) {
    index = index % N;
    bitv[index / 64] |= (1ULL << (index % 64));
  }
  bool get(uint64_t index) const {
    index = index % N;
    return bitv[index / 64] & (1ULL << (index % 64));
  }
  size_t size() const { return long_count * 64; }
  void clear() { bitv.assign(long_count, 0); }
};

class GloomFilter {
private:
  using hash_func_t = uint64_t (*)(const void *, size_t);
  static constexpr unsigned BULK_READ_MAX = 512;

  unsigned num_threads;
  unsigned bit_mask;
  std::vector<moodycamel::ConcurrentQueue<std::pair<uint32_t, uint32_t>>> queues;
  std::vector<std::vector<std::pair<uint32_t, uint32_t>>> bulk_reading;
  hash_func_t hashf1;
  hash_func_t hashf2;
  size_t per_thread_bits;
  size_t expected_elements_per_thread;
  size_t num_hash_functions;

  std::vector<bits> filters;
  static uint64_t default_hash1(const void *data, size_t len) {
    return XXH64(data, len, 0ULL);
  }
  static uint64_t default_hash2(const void *data, size_t len) {
    return XXH64(data, len, 0x9E3779B97F4A7C15ULL);
  }

public:
  GloomFilter(size_t num_threads, size_t expected_elements,
              double false_positive_rate)
      : num_threads(num_threads),
        bit_mask(num_threads - 1),
        hashf1(default_hash1), hashf2(default_hash2),
        per_thread_bits(calculate_bit_array_size(expected_elements, false_positive_rate)),
        expected_elements_per_thread{static_cast<size_t>(
          round(expected_elements / static_cast<double>(num_threads)))},
        num_hash_functions(calculate_hash_functions(per_thread_bits, expected_elements_per_thread)),
        queues(num_threads), bulk_reading(num_threads), filters(num_threads) {
          assert(num_threads > 0);
          assert(__builtin_popcount(num_threads) == 1);

  }

  GloomFilter(size_t num_threads, size_t expected_elements, double false_positive_rate,
              hash_func_t hash1, hash_func_t hash2)
      : num_threads(num_threads),
        bit_mask(num_threads - 1),
        hashf1(hash1), hashf2(hash2),
        per_thread_bits(calculate_bit_array_size(expected_elements, false_positive_rate)),
        expected_elements_per_thread{static_cast<size_t>(
          round(expected_elements / static_cast<double>(num_threads)))},
        num_hash_functions(calculate_hash_functions(per_thread_bits, expected_elements_per_thread)),
        queues(num_threads), bulk_reading(num_threads), filters(num_threads) {
  }

  GloomFilter(const GloomFilter &) = delete;
  GloomFilter &operator=(const GloomFilter &) = delete;
  GloomFilter(GloomFilter &&other) noexcept;
  GloomFilter &operator=(GloomFilter &&other) noexcept;

  template <typename T>
  std::pair<uint32_t, uint32_t> get_hash(const T &item) const {
    uint64_t h1_64;
    uint64_t h2_64;
    if constexpr (std::is_same<T, std::string>::value) {
      h1_64 = hashf1(item.c_str(), item.length());
      h2_64 = hashf2(item.c_str(), item.length());
    } else if constexpr (std::is_same<T, const char *>::value ||
                         std::is_same<T, char *>::value) {
      h1_64 = hashf1(item, std::strlen(item));
      h2_64 = hashf2(item, std::strlen(item));
    } else if constexpr (std::is_trivially_copyable<T>::value) {
      h1_64 = hashf1(reinterpret_cast<const void *>(&item), sizeof(T));
      h2_64 = hashf2(reinterpret_cast<const void *>(&item), sizeof(T));
    }
    uint32_t h1 = static_cast<uint32_t>(h1_64);
    uint32_t h2 = static_cast<uint32_t>(h2_64) | 1u;
    return {h1, h2};
  }
  template <typename T> bool insert(const T &item, int tid) {
    {
      size_t count =
          queues[tid].try_dequeue_bulk(bulk_reading[tid].data(), BULK_READ_MAX);
      for (size_t j = 0; j < count; ++j) {
        const auto &hv = bulk_reading[tid][j];
        uint64_t h1 = hv.first;
        uint64_t h2 = hv.second;
        for (size_t i = 0; i < num_hash_functions; ++i) {
          filters[tid].set(h1 + static_cast<uint64_t>(i) * h2);
        }
      }
    }
    auto [hash_value1, hash_value2] = get_hash(item);
    size_t target_filter =
        (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;
    if (tid == static_cast<int>(target_filter)) {
      for (size_t i = 0; i < num_hash_functions; ++i) {
        filters[target_filter].set(static_cast<uint64_t>(hash_value1) +
                                   static_cast<uint64_t>(i) *
                                       static_cast<uint64_t>(hash_value2));
      }
    } else {
      queues[target_filter].enqueue({hash_value1, hash_value2});
      return false;
    }
    return true;
  }

private:
  // Common bulk insert implementation
  template <typename Iterator>
  size_t insert_bulk_impl(Iterator begin, Iterator end, int tid) {
    size_t inserted_count = 0;

    {
      bulk_reading[tid].clear();
      size_t count = queues[tid].try_dequeue_bulk(
          std::back_inserter(bulk_reading[tid]), BULK_READ_MAX);
      for (size_t j = 0; j < count; ++j) {
        const auto &hv = bulk_reading[tid][j];
        uint64_t h1 = hv.first;
        uint64_t h2 = hv.second;
        for (size_t i = 0; i < num_hash_functions; ++i) {
          filters[tid].set(h1 + static_cast<uint64_t>(i) * h2);
        }
      }
    }

    for (auto it = begin; it != end; ++it) {
      auto [hash_value1, hash_value2] = get_hash(*it);
      size_t target_filter =
          (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;

      if (tid == static_cast<int>(target_filter)) {
        for (size_t i = 0; i < num_hash_functions; ++i) {
          filters[target_filter].set(static_cast<uint64_t>(hash_value1) +
                                     static_cast<uint64_t>(i) *
                                         static_cast<uint64_t>(hash_value2));
        }
        ++inserted_count;
      } else {
        queues[target_filter].enqueue({hash_value1, hash_value2});
      }
    }

    return inserted_count;
  }

public:
  template <typename Iterator>
  size_t insert_bulk(Iterator begin, Iterator end, int tid) {
    return insert_bulk_impl(begin, end, tid);
  }

#if __cpp_lib_ranges >= 201911L
  template <std::ranges::input_range Range>
  size_t insert_bulk_range(const Range &range, int tid) {
    return insert_bulk_impl(range.begin(), range.end(), tid);
  }

#endif

  void flush() {
    for (unsigned tid = 0; tid < num_threads; ++tid) {
      bulk_reading[tid].clear();
      size_t count = queues[tid].try_dequeue_bulk(
          std::back_inserter(bulk_reading[tid]), BULK_READ_MAX);
      while (count > 0) {
        for (size_t j = 0; j < count; ++j) {
          const auto &hv = bulk_reading[tid][j];
          uint64_t h1 = hv.first;
          uint64_t h2 = hv.second;
          for (size_t i = 0; i < num_hash_functions; ++i) {
            filters[tid].set(h1 + static_cast<uint64_t>(i) * h2);
          }
        }
        bulk_reading[tid].clear();
        count = queues[tid].try_dequeue_bulk(
            std::back_inserter(bulk_reading[tid]), BULK_READ_MAX);
      }
    }
  }
  template <typename T> bool contains(const T &item) const {
    auto [hash_value1, hash_value2] = get_hash(item);
    size_t target_filter =
        (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;
    bool contain_flag = true;
    for (size_t i = 0; i < num_hash_functions; ++i) {
      if (!filters[target_filter].get(static_cast<uint64_t>(hash_value1) +
                                      static_cast<uint64_t>(i) *
                                          static_cast<uint64_t>(hash_value2))) {
        contain_flag = false;
        break;
      }
    }
    return contain_flag;
  }

  static size_t calculate_bit_array_size(size_t expected_elements,
                                         double false_positive_rate) {
    if (expected_elements == 0 || false_positive_rate <= 0.0 ||
        false_positive_rate >= 1.0) {
      return 8192;
    }
    constexpr double LN2_SQ = 0.4804530139182014;
    double m_bits = -(static_cast<double>(expected_elements) *
                      std::log(false_positive_rate)) /
                    LN2_SQ;
    m_bits *= (1.0 / LN2_SQ);
    if (m_bits < 64.0)
      m_bits = 64.0;
    uint64_t bits = static_cast<uint64_t>(m_bits + 0.5);
    bits = ((bits + 63) / 64) * 64;
    return bits;
  }
  static size_t calculate_hash_functions(size_t num_bits,
                                         size_t expected_elements) {
    size_t k;
    if (expected_elements == 0)
      return 1;
    k = (size_t)((double)num_bits / expected_elements * 0.6931471805599453);
    return k > 0 ? k : 1;
  }
};

struct RegisterBlockedGloomFilter {
private:
  static constexpr unsigned BULK_READ_MAX = 512;
  using hash_func_t = uint64_t (*)(const void *, size_t);
  size_t bit_count;
  unsigned num_threads;
  unsigned num_blocks;
  unsigned bit_mask;
  std::vector<std::vector<uint64_t>> filters;
  std::vector<moodycamel::ConcurrentQueue<std::pair<uint32_t, uint32_t>>>
      queues;
  std::vector<std::vector<std::pair<uint32_t, uint32_t>>> bulk_reading;
  size_t num_hash_functions;

public:
  RegisterBlockedGloomFilter(size_t num_threads, size_t expected_elements,
                             double false_positive_rate)
      : bit_count(
            calculate_bit_array_size(expected_elements, false_positive_rate)),
        num_threads(num_threads), num_blocks(bit_count / 64),
        bit_mask(num_threads - 1),
        filters(num_threads, std::vector<uint64_t>(num_blocks, 0)),
        queues(num_threads), bulk_reading(num_threads),
        num_hash_functions(
            calculate_hash_functions(bit_count, expected_elements)) {}

  const uint64_t *GetBlock(uint32_t target_filter, uint32_t h1,
                           uint32_t h2) const {
    uint32_t block_idx = h1 % num_blocks;
    return &filters[target_filter].at(block_idx);
  }
  uint64_t *GetBlock(uint32_t target_filter, uint32_t h1, uint32_t h2) {
    uint32_t block_idx = h1 % num_blocks;
    return &filters[target_filter][block_idx];
  }
  uint64_t ConstructMask(uint32_t h1, uint32_t h2) const {
    uint64_t mask = 0;
    for (int i = 1; i < num_hash_functions; i++) {
      uint32_t bit_pos = (h1 + i * h2) % 64;
      mask |= (1ull << bit_pos);
    }
    return mask;
  }

  bool contains_with_hash(uint32_t h1, uint32_t h2) const {
    size_t target_filter = (static_cast<unsigned>(h1) >> 16) & bit_mask;
    const uint64_t *block = GetBlock(target_filter, h1, h2);
    uint64_t mask = ConstructMask(h1, h2);
    return (*block & mask) == mask;
  }

  bool insert_with_hash(uint32_t hash_value1, uint32_t hash_value2, int tid) {
    size_t count = queues[tid].try_dequeue_bulk(
        std::back_inserter(bulk_reading[tid]), BULK_READ_MAX);
    for (size_t j = 0; j < count; ++j) {
      const auto &hv = bulk_reading[tid][j];
      uint64_t *block = GetBlock(tid, hv.first, hv.second);
      *block |= ConstructMask(hv.first, hv.second);
    }
    bulk_reading[tid].clear();

    size_t target_filter =
        (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;
    if (tid == static_cast<int>(target_filter)) {
      uint64_t *block = GetBlock(tid, hash_value1, hash_value2);
      *block |= ConstructMask(hash_value1, hash_value2);
    } else {
      queues[target_filter].enqueue({hash_value1, hash_value2});
      return false;
    }
    return true;
  }

private:
  static size_t calculate_bit_array_size(size_t expected_elements,
                                         double false_positive_rate) {
    return static_cast<size_t>(
        -1.44 * expected_elements * std::log2(false_positive_rate) + 0.5);
  }
  static size_t calculate_hash_functions(size_t num_bits,
                                         size_t expected_elements) {
    return static_cast<size_t>(-std::log2(1.0 / expected_elements) + 0.5);
  }
};

} // namespace fbloom

#endif
