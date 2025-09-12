#ifndef PARALLEL_BLOOM_H
#define PARALLEL_BLOOM_H
#include "bloom.h"
#include <mutex>
#include <atomic>

struct null_mutex {
    void lock() {}
    void try_lock() {}
    void unlock() {}

    nullptr_t native_handle() {
        return nullptr;
    }
};

struct spinlock {
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
    void lock() {
        while (flag.test_and_set(std::memory_order_acquire)) {}
    }
    bool try_lock() {
        return !flag.test_and_set(std::memory_order_acquire);
    }
    void unlock() {
        flag.clear(std::memory_order_release);
    }
};

 

template<typename mutex_type=null_mutex, typename filter_impl=fbloom::BloomFilter>
struct LockedBloomFilter : public filter_impl {
    // fbloom::BloomFilter filter;
    mutex_type mutex;
    template<class ...ARGS>
    LockedBloomFilter(ARGS... args) : filter_impl(args...) {}
    template<typename T>
    bool insert(const T& item) {
        std::lock_guard<mutex_type> lock(mutex);
        return filter_impl::insert(item);
    }
    template<typename T>
    bool contains(const T& item) const {
        return filter_impl::contains(item);
    }

    bool insert_with_hash(size_t hash1, size_t hash2) {
        std::lock_guard<mutex_type> lock(mutex);
        return filter_impl::insert_with_hash(hash1, hash2);
    }

    bool contains_with_hash(size_t hash1, size_t hash2) const {
        return filter_impl::contains_with_hash(hash1, hash2);
    }
};

template< int N, typename mutex_type=null_mutex, typename filter_impl=fbloom::BloomFilter>
struct ParallelBloomFilter1 {
    static constexpr int num_filters = 1 << N;
    static constexpr unsigned filter_mask = num_filters - 1;
    fbloom::BloomFilter::hash_func_t hash1;
    fbloom::BloomFilter::hash_func_t hash2;
    size_t expected_elements_per_filter;
    std::array<LockedBloomFilter<mutex_type, filter_impl>, num_filters> filters;
    static unsigned hash_func1(const void* data, size_t len) {
        return fbloom_murmurhash((const char*)data, len, 0);
    }
    static unsigned hash_func2(const void* data, size_t len) {
        return fbloom_murmurhash((const char*)data, len, 0x87654321UL);
    }

  
    ParallelBloomFilter1(size_t expected_elements, double false_positive_rate) : 
        hash1(hash_func1),
        hash2(hash_func2),
        expected_elements_per_filter{static_cast<size_t>(round(expected_elements/static_cast<double>(num_filters)))},
        filters { make_array<decltype(hash_func1), decltype(hash_func2)>(expected_elements_per_filter, false_positive_rate, hash_func1, hash_func2, std::make_index_sequence<num_filters>()) }
         {}
    template<typename HashFunc1, typename HashFunc2>
    ParallelBloomFilter1(size_t expected_elements, double false_positive_rate, HashFunc1 hash1_func, HashFunc2 hash2_func) 
    : hash1(hash1_func),
      hash2(hash2_func),
      expected_elements_per_filter{static_cast<size_t>(round(expected_elements/static_cast<double>(num_filters)))},
      filters { make_array<HashFunc1, HashFunc2>(expected_elements_per_filter, false_positive_rate, hash1_func, hash2_func, std::make_index_sequence<num_filters>()) }
      {}


    template<typename T>
    std::pair<size_t, size_t> get_hash(const T& item) const {
        unsigned hv1;
        unsigned hv2;
        if constexpr (std::is_same<T, std::string>::value) {
            hv1 = hash1(item.c_str(), item.length());
            hv2 = hash2(item.c_str(), item.length());
        } else if constexpr (std::is_same<T, const char*>::value || std::is_same<T, char*>::value) {
            hv1 = hash1(item, std::strlen(item));
            hv2 = hash2(item, std::strlen(item));
        } else if constexpr (std::is_trivially_copyable<T>::value) {
            hv1 = hash1(reinterpret_cast<const void*>(&item), sizeof(T));
            hv2 = hash2(reinterpret_cast<const void*>(&item), sizeof(T));
        }
        return std::make_pair(hv1, hv2);
    }

    template<typename T>
    bool insert(const T& item) {
        auto [hash_value1, hash_value2] = get_hash(item);
        // Use higher bits to choose the shard to avoid low-bit bias
        size_t target_filter = (static_cast<unsigned>(hash_value1) >> 16) & filter_mask;
        return filters[target_filter].insert_with_hash(hash_value1, hash_value2);
    }
    
    template<typename T>
    bool contains(const T& item) const {
        auto [hash_value1, hash_value2] = get_hash(item);
        // Use higher bits to choose the shard to avoid low-bit bias
        size_t target_filter = (static_cast<unsigned>(hash_value1) >> 16) & filter_mask;
        return filters[target_filter].contains_with_hash(hash_value1, hash_value2);
    }
    private:
    template <typename HashFunc1, typename HashFunc2, std::size_t... I>
    static std::array<LockedBloomFilter<mutex_type, filter_impl>, num_filters> make_array(size_t expected_elements, double false_positive_rate, HashFunc1 hash1_func, HashFunc2 hash2_func, std::index_sequence<I...>) {
        // Create array of LockedBloomFilter instances, each initialized with the same parameters
        return { ( (void)I, LockedBloomFilter<mutex_type, filter_impl>{expected_elements, false_positive_rate, hash1_func, hash2_func} )... };
    }
};


#endif