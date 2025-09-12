#ifndef GLOOM_H
#define GLOOM_H

#include "bloom.h"
#include "concurrentqueue.h"
#include "external/xxhash.h"

#include <array>
#include <cmath>
#include <cstring>
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
template <int N, int BULK_READ_MAX = 512> class GloomFilter {
private:
  using hash_func_t = uint64_t (*)(const void *, size_t);

  static constexpr unsigned num_filters = N;

  static constexpr unsigned bit_mask = num_filters - 1;
  std::array<moodycamel::ConcurrentQueue<std::pair<uint32_t, uint32_t>>, num_filters> queues;
  std::array<std::vector<std::pair<uint32_t, uint32_t>>, num_filters> bulk_reading;
  hash_func_t hashf1;
  hash_func_t hashf2;
  size_t expected_elements_per_filter;
  size_t num_hash_functions;
  std::array<bits, num_filters> filters;
  static uint64_t default_hash1(const void *data, size_t len) { return XXH64(data, len, 0ULL); }
  static uint64_t default_hash2(const void *data, size_t len) { return XXH64(data, len, 0x9E3779B97F4A7C15ULL); }

public:
  GloomFilter(size_t expected_elements, double false_positive_rate)
      : hashf1(default_hash1), hashf2(default_hash2),
        expected_elements_per_filter{static_cast<size_t>(
            round(expected_elements / static_cast<double>(num_filters)))}
  {
    uint64_t total_bits = calculate_bit_array_size(expected_elements, false_positive_rate);
    uint64_t per_filter_bits = (total_bits + num_filters - 1) / num_filters;
    per_filter_bits = ((per_filter_bits + 63) / 64) * 64;
    filters = make_array_bits(per_filter_bits, std::make_index_sequence<num_filters>());
    num_hash_functions = calculate_hash_functions(per_filter_bits, expected_elements_per_filter);

  }

  GloomFilter(size_t expected_elements, double false_positive_rate,
              hash_func_t hash1, hash_func_t hash2)
      : hashf1(hash1), hashf2(hash2),
        expected_elements_per_filter{static_cast<size_t>(
            round(expected_elements / static_cast<double>(num_filters)))}
  {
    uint64_t total_bits = calculate_bit_array_size(expected_elements, false_positive_rate);
    uint64_t per_filter_bits = (total_bits + num_filters - 1) / num_filters;
    per_filter_bits = ((per_filter_bits + 63) / 64) * 64;
    filters = make_array_bits(per_filter_bits, std::make_index_sequence<num_filters>());
    num_hash_functions = calculate_hash_functions(per_filter_bits, expected_elements_per_filter);
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
    uint32_t h2 = static_cast<uint32_t>(h2_64) | 1u; // ensure odd stride to improve coverage
    return {h1, h2};
  }
  template <typename T> bool insert(const T &item, int tid) {
    {
      // Bulk dequeue for efficiency
      size_t count = queues[tid].try_dequeue_bulk(bulk_reading[tid].data(), BULK_READ_MAX);
      for (size_t j = 0; j < count; ++j) {
        const auto& hv = bulk_reading[tid][j];
        uint64_t h1 = hv.first;
        uint64_t h2 = hv.second;
        for (size_t i = 0; i < num_hash_functions; ++i) {
          filters[tid].set(h1 + static_cast<uint64_t>(i) * h2);
        }
      }
    }
    auto [hash_value1, hash_value2] = get_hash(item);
    size_t target_filter = (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;
    if (tid == static_cast<int>(target_filter)) {
      for (size_t i = 0; i < num_hash_functions; ++i) {
        filters[target_filter].set(static_cast<uint64_t>(hash_value1) + static_cast<uint64_t>(i) * static_cast<uint64_t>(hash_value2));
      }
    } else {
      queues[target_filter].enqueue({hash_value1, hash_value2});
      return false;
    }
    return true;
  }
  // Ensure all forwarded inserts are applied to shards
  void flush() {
    for (unsigned tid = 0; tid < num_filters; ++tid) {
      // Use bulk dequeue for efficiency
      size_t count = queues[tid].try_dequeue_bulk(bulk_reading[tid].data(), BULK_READ_MAX);
      while (count > 0) {
        for (size_t j = 0; j < count; ++j) {
          const auto& hv = bulk_reading[tid][j];
          uint64_t h1 = hv.first;
          uint64_t h2 = hv.second;
          for (size_t i = 0; i < num_hash_functions; ++i) {
            filters[tid].set(h1 + static_cast<uint64_t>(i) * h2);
          }
        }
        count = queues[tid].try_dequeue_bulk(bulk_reading[tid].data(), BULK_READ_MAX);
      }
    }
  }
  template <typename T> bool contains(const T &item) const {
    auto [hash_value1, hash_value2] = get_hash(item);
    size_t target_filter = (static_cast<unsigned>(hash_value1) >> 16) & bit_mask;
    bool contain_flag = true;
    for (size_t i = 0; i < num_hash_functions; ++i) {
      if (!filters[target_filter].get(static_cast<uint64_t>(hash_value1) + static_cast<uint64_t>(i) * static_cast<uint64_t>(hash_value2))) {
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
    // Match baseline BloomFilter memory sizing (which effectively uses ln(2)^4)
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
  template <typename HashFunc1, typename HashFunc2, std::size_t... I>
  static std::array<bits, num_filters>
  make_array(size_t expected_elements, double false_positive_rate,
             HashFunc1 hash1_func, HashFunc2 hash2_func,
             std::index_sequence<I...>) {
    // Create array of LockedBloomFilter instances, each initialized with the
    // same parameters
    (void)hash1_func; (void)hash2_func;
    uint64_t bit_count =
        calculate_bit_array_size(expected_elements, false_positive_rate);
    return {((void)I, bits{bit_count})...};
  }
  template <std::size_t... I>
  static std::array<bits, num_filters>
  make_array_bits(uint64_t bit_count, std::index_sequence<I...>) {
    return {((void)I, bits{bit_count})...};
  }
};
} // namespace fbloom

#endif
