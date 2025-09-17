#define FBLOOM_IMPLEMENTATION
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <iomanip>
#include <functional>
#include <fstream>
#include <sys/stat.h>
#include <unordered_set>
#include "fbloom/bloom.h"
#include "fbloom/parallel_bloom.h"
#include "fbloom/gloom.h"

// Include gloom_clean.h with a namespace alias to avoid name conflicts
namespace fbloom_clean {
    #include "fbloom/gloom_clean.h"
}
#include <array>
#include <cmath>
extern "C" {
#include "fbloom/external/xxhash.h"
}

using namespace fbloom;

// Hash function types for different hash algorithms
using HashFunc = std::function<uint32_t(const void*, size_t)>;

// C-style hash function pointers for bloom filter (two independent seeds)
uint32_t murmur_hash_c_s0(const void* data, size_t len) { return fbloom_murmurhash((const char*)data, (uint32_t)len, 0u); }
uint32_t murmur_hash_c_s1(const void* data, size_t len) { return fbloom_murmurhash((const char*)data, (uint32_t)len, 0x87654321u); }

uint32_t xxhash32_hash_c_s0(const void* data, size_t len) { return XXH32(data, len, 0u); }
uint32_t xxhash32_hash_c_s1(const void* data, size_t len) { return XXH32(data, len, 0x87654321u); }

uint32_t xxhash64_hash_c_s0(const void* data, size_t len) { return (uint32_t)XXH64(data, len, 0ull); }
uint32_t xxhash64_hash_c_s1(const void* data, size_t len) { return (uint32_t)XXH64(data, len, 0x87654321ull); }

// Gloom-compatible hash (returns 64-bit)
static uint64_t xxhash64_hash_u64_s0(const void* data, size_t len) { return XXH64(data, len, 0ull); }
static uint64_t xxhash64_hash_u64_s1(const void* data, size_t len) { return XXH64(data, len, 0x87654321ull); }

// Data structure for pre-partitioned work
struct WorkChunk {
    const std::vector<std::string>* data;
    size_t start_idx;
    size_t end_idx;

    WorkChunk(const std::vector<std::string>* d, size_t start, size_t end)
        : data(d), start_idx(start), end_idx(end) {}
};

// Helper to select apples-to-apples hash functions (two independent seeds)
inline bool select_hash_pair(const std::string& hash_name,
                             fbloom_hash_func_t& hash1_ptr,
                             fbloom_hash_func_t& hash2_ptr) {
    if (hash_name == "MurmurHash32") {
        hash1_ptr = murmur_hash_c_s0;
        hash2_ptr = murmur_hash_c_s1;
        return true;
    } else if (hash_name == "XXHash32") {
        hash1_ptr = xxhash32_hash_c_s0;
        hash2_ptr = xxhash32_hash_c_s1;
        return true;
    } else if (hash_name == "XXHash64") {
        hash1_ptr = xxhash64_hash_c_s0;
        hash2_ptr = xxhash64_hash_c_s1;
        return true;
    }
    return false;
}

// Generate test data
std::vector<std::string> generate_test_data(size_t size, size_t string_length = 16) {
    std::vector<std::string> data;
    data.reserve(size);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(32, 126); // Printable ASCII characters

    for (size_t i = 0; i < size; ++i) {
        std::string str;
        str.reserve(string_length);
        for (size_t j = 0; j < string_length; ++j) {
            str += static_cast<char>(dis(gen));
        }
        data.push_back(str);
    }

    return data;
}

// Worker function for parallel insertions (no atomics, no locks)
void insert_worker(BloomFilter& filter, const WorkChunk& chunk) {
    for (size_t i = chunk.start_idx; i < chunk.end_idx; ++i) {
        filter.insert((*chunk.data)[i]);
    }
}

// Worker function for parallel contains checks (no atomics, no locks)
void contains_worker(const BloomFilter& filter, const WorkChunk& chunk, std::vector<bool>& results) {
    for (size_t i = chunk.start_idx; i < chunk.end_idx; ++i) {
        results[i] = filter.contains((*chunk.data)[i]);
    }
}

// Worker function for parallel ParallelBloomFilter1 insertions
template<int N, typename mutex_type>
void parallel_insert_worker(ParallelBloomFilter1<N, mutex_type>& filter, const WorkChunk& chunk) {
    for (size_t i = chunk.start_idx; i < chunk.end_idx; ++i) {
        filter.insert((*chunk.data)[i]);
    }
}

// Worker function for parallel ParallelBloomFilter1 contains checks
template<int N, typename mutex_type>
void parallel_contains_worker(const ParallelBloomFilter1<N, mutex_type>& filter, const WorkChunk& chunk, std::vector<bool>& results) {
    for (size_t i = chunk.start_idx; i < chunk.end_idx; ++i) {
        results[i] = filter.contains((*chunk.data)[i]);
    }
}

// Structure to hold test data for unified benchmarking
struct BenchmarkTestData {
    std::vector<std::string> insert_data;
    std::vector<std::string> test_data;
    size_t expected_inserted_count;
    std::unordered_set<std::string> positives; // items in test_data that were inserted
    std::unordered_set<std::string> negatives; // items in test_data that are new
};


void write_tsv_row(const std::string& path,
                   const std::string& filter_name,
                   int threads,
                   size_t insert_count,
                   size_t test_count,
                   size_t expected_inserted,
                   double insert_ms,
                   double contains_ms,
                   size_t tp,
                   size_t fp,
                   size_t fn,
                   size_t total_bits) {
    // Write header if file is missing OR empty
    bool write_header = false;
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        write_header = true; // file doesn't exist yet
    } else if (st.st_size == 0) {
        write_header = true; // exists but empty
    }
    std::ofstream out(path, std::ios::app);
    if (!out.is_open()) return;
    if (write_header) {
        out << "filter\tthreads\tinsert_count\ttest_count\texpected_inserted\tinsert_ms\tcontains_ms\ttp\tfp\tfn\tfp_rate\tfn_rate\ttotal_bits\tbits_per_item" << '\n';
    }
    double negatives = static_cast<double>(test_count > expected_inserted ? (test_count - expected_inserted) : 0);
    double fp_rate = negatives > 0 ? static_cast<double>(fp) / negatives : 0.0;
    double fn_rate = expected_inserted > 0 ? static_cast<double>(fn) / static_cast<double>(expected_inserted) : 0.0;
    double bits_per_item = insert_count > 0 ? static_cast<double>(total_bits) / static_cast<double>(insert_count) : 0.0;

    out << filter_name << '\t'
        << threads << '\t'
        << insert_count << '\t'
        << test_count << '\t'
        << expected_inserted << '\t'
        << std::fixed << std::setprecision(3) << insert_ms << '\t'
        << contains_ms << '\t'
        << tp << '\t' << fp << '\t' << fn << '\t'
        << std::setprecision(6) << fp_rate << '\t' << fn_rate << '\t'
        << std::setprecision(0) << static_cast<double>(total_bits) << '\t'
        << std::setprecision(3) << bits_per_item << '\n';
}

// Helpers to compute total bits used by a filter
inline size_t total_bits_used(const fbloom::BloomFilter& f) {
    return f.bit_array_size() * 8ULL;
}

template<int N, typename mutex_type>
inline size_t total_bits_used(const ParallelBloomFilter1<N, mutex_type>& f) {
    size_t total = 0;
    for (int i = 0; i < ParallelBloomFilter1<N, mutex_type>::num_filters; ++i) {
        total += f.filters[i].bit_array_size() * 8ULL;
    }
    return total;
}

// Theoretical total bits required for expected_elements at target FPR
inline size_t total_bits_theoretical(size_t expected_elements, double false_positive_rate) {
    if (expected_elements == 0 || false_positive_rate <= 0.0 || false_positive_rate >= 1.0) {
        return 0;
    }
    // m = -(n * ln(p)) / (ln(2)^2)
    double m_bits = -(static_cast<double>(expected_elements) * std::log(false_positive_rate)) / (0.4804530139182014); // ln(2)^2
    if (m_bits < 0.0) m_bits = 0.0;
    return static_cast<size_t>(m_bits + 0.5); // round to nearest bit
}

// Helper to compute total bits for RegisterBlockedGloomFilter
inline size_t total_bits_used(const RegisterBlockedGloomFilter& /* f */) {
    // RegisterBlockedGloomFilter doesn't expose bit count directly, so we estimate
    // This is a placeholder - in practice you'd need to add a method to expose bit count
    return 0; // Will be calculated from parameters
}

// Benchmark for RegisterBlockedGloomFilter
void run_register_blocked_gloom_benchmark_with_data(const std::string& filter_name,
                                                   const BenchmarkTestData& test_data,
                                                   int num_threads,
                                                   double false_positive_rate) {
    std::cout << "\n=== " << filter_name << " (" << num_threads << " threads) ===" << std::endl;

    // Create filter
    RegisterBlockedGloomFilter filter(num_threads, test_data.insert_data.size(), false_positive_rate);

    // Pre-partition work by target thread using the same mapping as RegisterBlockedGloomFilter
    std::vector<std::vector<std::string>> thread_data(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        thread_data[i].reserve(test_data.insert_data.size() / num_threads + 8);
    }
    
    // Partition data by hash to target thread
    for (const auto& s : test_data.insert_data) {
        // Use XXHash64 to match the hash function used internally
        uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
        uint32_t h1 = static_cast<uint32_t>(hash1);
        size_t target_thread = (static_cast<unsigned>(h1) >> 16) & (num_threads - 1);
        thread_data[target_thread].push_back(s);
    }

    // Insert phase
    auto insert_start = std::chrono::high_resolution_clock::now();
    {
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (int tid = 0; tid < num_threads; ++tid) {
            threads.emplace_back([&, tid]() {
                for (const auto& s : thread_data[tid]) {
                    uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
                    uint64_t hash2 = XXH64(s.c_str(), s.length(), 0x87654321ULL);
                    uint32_t h1 = static_cast<uint32_t>(hash1);
                    uint32_t h2 = static_cast<uint32_t>(hash2) | 1; // Ensure odd
                    filter.insert_with_hash(h1, h2, tid);
                }
            });
        }
        for (auto& t : threads) t.join();
    }
    auto insert_end = std::chrono::high_resolution_clock::now();
    double insert_time_ms = std::chrono::duration<double, std::milli>(insert_end - insert_start).count();

    // Contains phase
    auto contains_start = std::chrono::high_resolution_clock::now();
    size_t found_total = 0;
    size_t tp_total = 0;
    size_t fp_total = 0;
    size_t fn_total = 0;
    {
        struct ThreadCounts { size_t found; size_t tp; size_t fp; size_t fn; };
        std::vector<ThreadCounts> counters(num_threads, ThreadCounts{0,0,0,0});
        std::vector<std::thread> threads;
        size_t chunk_size = test_data.test_data.size() / static_cast<size_t>(num_threads);
        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = static_cast<size_t>(i) * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.test_data.size() : (static_cast<size_t>(i + 1) * chunk_size);
            threads.emplace_back([&, i, start_idx, end_idx]() {
                size_t local_found = 0, local_tp = 0, local_fp = 0, local_fn = 0;
                for (size_t j = start_idx; j < end_idx; ++j) {
                    const auto& s = test_data.test_data[j];
                    uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
                    uint64_t hash2 = XXH64(s.c_str(), s.length(), 0x87654321ULL);
                    uint32_t h1 = static_cast<uint32_t>(hash1);
                    uint32_t h2 = static_cast<uint32_t>(hash2) | 1; // Ensure odd
                    bool present = filter.contains_with_hash(h1, h2);
                    bool is_positive = test_data.positives.find(s) != test_data.positives.end();
                    if (present) { local_found++; if (is_positive) local_tp++; else local_fp++; }
                    else { if (is_positive) local_fn++; }
                }
                counters[i] = ThreadCounts{local_found, local_tp, local_fp, local_fn};
            });
        }
        for (auto& t : threads) t.join();
        for (const auto& c : counters) {
            found_total += c.found;
            tp_total += c.tp;
            fp_total += c.fp;
            fn_total += c.fn;
        }
    }
    auto contains_end = std::chrono::high_resolution_clock::now();
    double contains_time_ms = std::chrono::duration<double, std::milli>(contains_end - contains_start).count();

    // Print results
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Insert time:      " << insert_time_ms << " ms" << std::endl;
    std::cout << "Contains time:    " << contains_time_ms << " ms" << std::endl;
    std::cout << "Elements/sec:     " << (test_data.insert_data.size() / insert_time_ms * 1000.0) << std::endl;
    std::cout << "Contains/sec:     " << (test_data.test_data.size() / contains_time_ms * 1000.0) << std::endl;

    size_t negatives = test_data.test_data.size() - test_data.expected_inserted_count;
    double fp_rate = negatives ? (static_cast<double>(fp_total) / static_cast<double>(negatives)) : 0.0;
    double fn_rate = test_data.expected_inserted_count ? (static_cast<double>(fn_total) / static_cast<double>(test_data.expected_inserted_count)) : 0.0;
    std::cout << "Found total:      " << found_total << " (TP=" << tp_total << ", FP=" << fp_total << ")" << std::endl;
    std::cout << "False positive %: " << (fp_rate * 100.0) << "%" << std::endl;
    std::cout << "False negative %: " << (fn_rate * 100.0) << "%" << std::endl;

    // Persist TSV (estimate total bits from parameters)
    size_t total_bits = total_bits_theoretical(test_data.insert_data.size(), false_positive_rate);
    write_tsv_row("benchmark_results.tsv", filter_name, num_threads,
                  test_data.insert_data.size(), test_data.test_data.size(), test_data.expected_inserted_count,
                  insert_time_ms, contains_time_ms, tp_total, fp_total, fn_total,
                  total_bits);
}

// Benchmark for GloomFilter2 (clean) with pre-partitioned inserts to avoid cross-shard enqueues
void run_gloom_clean_benchmark_with_data(const std::string& filter_name,
                                        const BenchmarkTestData& test_data,
                                        int num_threads,
                                        double false_positive_rate) {
    std::cout << "\n=== " << filter_name << " (" << num_threads << " threads) ===" << std::endl;

    // Create filter (using the clean version from gloom_clean.h)
    fbloom_clean::fbloom::GloomFilter2 filter(num_threads, test_data.insert_data.size(), false_positive_rate);

    // Pre-partition work by target shard using the same mapping as Gloom
    std::vector<std::vector<std::string>> shard_data(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        shard_data[i].reserve(test_data.insert_data.size() / num_threads + 8);
    }
    
    // Partition data by hash to target shard
    for (const auto& s : test_data.insert_data) {
        // Use XXHash64 to match the hash function used internally
        uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
        uint64_t hash2 = XXH64(s.c_str(), s.length(), 0x87654321ULL);
        uint32_t h1 = static_cast<uint32_t>(hash1);
        uint32_t h2 = static_cast<uint32_t>(hash2) | 1; // Ensure odd
        unsigned target = (static_cast<unsigned>(h1) >> 16) & (num_threads - 1);
        (void)h2; // Suppress unused variable warning - h2 is used in the actual filter operations
        shard_data[target].push_back(s);
    }

    // Insert phase
    auto insert_start = std::chrono::high_resolution_clock::now();
    {
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (int tid = 0; tid < num_threads; ++tid) {
            threads.emplace_back([&, tid]() {
                for (const auto& s : shard_data[tid]) {
                    uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
                    uint64_t hash2 = XXH64(s.c_str(), s.length(), 0x87654321ULL);
                    uint32_t h1 = static_cast<uint32_t>(hash1);
                    uint32_t h2 = static_cast<uint32_t>(hash2) | 1; // Ensure odd
                    filter.Insert(h1, h2, tid);
                }
            });
        }
        for (auto& t : threads) t.join();
    }
    auto insert_end = std::chrono::high_resolution_clock::now();
    double insert_time_ms = std::chrono::duration<double, std::milli>(insert_end - insert_start).count();

    // Contains phase
    auto contains_start = std::chrono::high_resolution_clock::now();
    size_t found_total = 0;
    size_t tp_total = 0;
    size_t fp_total = 0;
    size_t fn_total = 0;
    {
        struct ThreadCounts { size_t found; size_t tp; size_t fp; size_t fn; };
        std::vector<ThreadCounts> counters(num_threads, ThreadCounts{0,0,0,0});
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        size_t chunk_size = test_data.test_data.size() / static_cast<size_t>(num_threads);
        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = static_cast<size_t>(i) * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.test_data.size() : (static_cast<size_t>(i + 1) * chunk_size);
            threads.emplace_back([&, i, start_idx, end_idx]() {
                size_t local_found = 0, local_tp = 0, local_fp = 0, local_fn = 0;
                for (size_t j = start_idx; j < end_idx; ++j) {
                    const auto& s = test_data.test_data[j];
                    uint64_t hash1 = XXH64(s.c_str(), s.length(), 0ULL);
                    uint64_t hash2 = XXH64(s.c_str(), s.length(), 0x87654321ULL);
                    uint32_t h1 = static_cast<uint32_t>(hash1);
                    uint32_t h2 = static_cast<uint32_t>(hash2) | 1; // Ensure odd
                    bool present = filter.Contains(h1, h2);
                    bool is_positive = test_data.positives.find(s) != test_data.positives.end();
                    if (present) { local_found++; if (is_positive) local_tp++; else local_fp++; }
                    else { if (is_positive) local_fn++; }
                }
                counters[i] = ThreadCounts{local_found, local_tp, local_fp, local_fn};
            });
        }
        for (auto& t : threads) t.join();
        for (const auto& c : counters) {
            found_total += c.found;
            tp_total += c.tp;
            fp_total += c.fp;
            fn_total += c.fn;
        }
    }
    auto contains_end = std::chrono::high_resolution_clock::now();
    double contains_time_ms = std::chrono::duration<double, std::milli>(contains_end - contains_start).count();

    // Print results
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Insert time:      " << insert_time_ms << " ms" << std::endl;
    std::cout << "Contains time:    " << contains_time_ms << " ms" << std::endl;
    std::cout << "Elements/sec:     " << (test_data.insert_data.size() / insert_time_ms * 1000.0) << std::endl;
    std::cout << "Contains/sec:     " << (test_data.test_data.size() / contains_time_ms * 1000.0) << std::endl;

    size_t negatives = test_data.test_data.size() - test_data.expected_inserted_count;
    double fp_rate = negatives ? (static_cast<double>(fp_total) / static_cast<double>(negatives)) : 0.0;
    double fn_rate = test_data.expected_inserted_count ? (static_cast<double>(fn_total) / static_cast<double>(test_data.expected_inserted_count)) : 0.0;
    std::cout << "Found total:      " << found_total << " (TP=" << tp_total << ", FP=" << fp_total << ")" << std::endl;
    std::cout << "False positive %: " << (fp_rate * 100.0) << "%" << std::endl;
    std::cout << "False negative %: " << (fn_rate * 100.0) << "%" << std::endl;

    // Persist TSV (compute total bits using the filter's method)
    // Calculate total bits for GloomFilter2 (clean)
    size_t total_bits = filter.TotalBitsUsed();
    write_tsv_row("benchmark_results.tsv", filter_name, num_threads,
                  test_data.insert_data.size(), test_data.test_data.size(), test_data.expected_inserted_count,
                  insert_time_ms, contains_time_ms, tp_total, fp_total, fn_total,
                  total_bits);
}

// Benchmark for GloomFilter with pre-partitioned inserts to avoid cross-shard enqueues
void run_gloom_benchmark_with_data(const std::string& filter_name,
                                   const BenchmarkTestData& test_data,
                                   int num_threads,
                                   double false_positive_rate,
                                   uint64_t (*hash1_ptr)(const void*, size_t),
                                   uint64_t (*hash2_ptr)(const void*, size_t)) {
    std::cout << "\n=== " << filter_name << " (" << num_threads << " threads) ===" << std::endl;

    // Create filter with explicit apples-to-apples hash functions
    fbloom::GloomFilter filter(num_threads, test_data.insert_data.size(), false_positive_rate, hash1_ptr, hash2_ptr);

    // Pre-partition work by target shard using the same mapping as Gloom
    std::vector<std::vector<std::string>> shard_data(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        shard_data[i].reserve(test_data.insert_data.size() / num_threads + 8);
    }
    for (const auto& s : test_data.insert_data) {
        auto hv = filter.get_hash(s);
        unsigned target = (static_cast<unsigned>(hv.first) >> 16) & (num_threads - 1);
        shard_data[target].push_back(s);
    }

    // Insert phase
    auto insert_start = std::chrono::high_resolution_clock::now();
    {
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (int tid = 0; tid < num_threads; ++tid) {
            threads.emplace_back([&, tid]() {
                for (const auto& s : shard_data[tid]) {
                    filter.insert(s, tid);
                }
            });
        }
        for (auto& t : threads) t.join();
    }
    auto insert_end = std::chrono::high_resolution_clock::now();
    double insert_time_ms = std::chrono::duration<double, std::milli>(insert_end - insert_start).count();
    // Ensure all forwarded inserts are applied before contains
    filter.flush();

    // Contains phase
    auto contains_start = std::chrono::high_resolution_clock::now();
    size_t found_total = 0;
    size_t tp_total = 0;
    size_t fp_total = 0;
    size_t fn_total = 0;
    {
        struct ThreadCounts { size_t found; size_t tp; size_t fp; size_t fn; };
        std::vector<ThreadCounts> counters(num_threads, ThreadCounts{0,0,0,0});
        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        size_t chunk_size = test_data.test_data.size() / static_cast<size_t>(num_threads);
        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = static_cast<size_t>(i) * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.test_data.size() : (static_cast<size_t>(i + 1) * chunk_size);
            threads.emplace_back([&, i, start_idx, end_idx]() {
                size_t local_found = 0, local_tp = 0, local_fp = 0, local_fn = 0;
                for (size_t j = start_idx; j < end_idx; ++j) {
                    const auto& s = test_data.test_data[j];
                    bool present = filter.contains(s);
                    bool is_positive = test_data.positives.find(s) != test_data.positives.end();
                    if (present) { local_found++; if (is_positive) local_tp++; else local_fp++; }
                    else { if (is_positive) local_fn++; }
                }
                counters[i] = ThreadCounts{local_found, local_tp, local_fp, local_fn};
            });
        }
        for (auto& t : threads) t.join();
        for (const auto& c : counters) {
            found_total += c.found;
            tp_total += c.tp;
            fp_total += c.fp;
            fn_total += c.fn;
        }
    }
    auto contains_end = std::chrono::high_resolution_clock::now();
    double contains_time_ms = std::chrono::duration<double, std::milli>(contains_end - contains_start).count();

    // Print results
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Insert time:      " << insert_time_ms << " ms" << std::endl;
    std::cout << "Contains time:    " << contains_time_ms << " ms" << std::endl;
    std::cout << "Elements/sec:     " << (test_data.insert_data.size() / insert_time_ms * 1000.0) << std::endl;
    std::cout << "Contains/sec:     " << (test_data.test_data.size() / contains_time_ms * 1000.0) << std::endl;

    size_t negatives = test_data.test_data.size() - test_data.expected_inserted_count;
    double fp_rate = negatives ? (static_cast<double>(fp_total) / static_cast<double>(negatives)) : 0.0;
    double fn_rate = test_data.expected_inserted_count ? (static_cast<double>(fn_total) / static_cast<double>(test_data.expected_inserted_count)) : 0.0;
    std::cout << "Found total:      " << found_total << " (TP=" << tp_total << ", FP=" << fp_total << ")" << std::endl;
    std::cout << "False positive %: " << (fp_rate * 100.0) << "%" << std::endl;
    std::cout << "False negative %: " << (fn_rate * 100.0) << "%" << std::endl;

    // Persist TSV (compute per-shard bits EXACTLY as Gloom allocates)
    // Calculate total bits for GloomFilter
    double bits_per_element = -1.44 * std::log2(false_positive_rate);
    size_t total_bits = static_cast<size_t>(bits_per_element * test_data.insert_data.size() + 0.5);
    write_tsv_row("benchmark_results.tsv", filter_name, num_threads,
                  test_data.insert_data.size(), test_data.test_data.size(), test_data.expected_inserted_count,
                  insert_time_ms, contains_time_ms, tp_total, fp_total, fn_total,
                  total_bits);
}

// Generate unified test data for both implementations
BenchmarkTestData generate_unified_test_data(size_t num_elements) {
    BenchmarkTestData data;

    // Generate insertion data
    data.insert_data = generate_test_data(num_elements);

    // Generate test data (mix of inserted and new items)
    size_t test_size = num_elements / 10;
    data.test_data.reserve(test_size);

    // First half: items that were inserted (should be found)
    size_t inserted_items = test_size / 2;
    for (size_t i = 0; i < inserted_items && i < data.insert_data.size(); ++i) {
        const auto& s = data.insert_data[i];
        data.test_data.push_back(s);
        data.positives.insert(s);
    }

    // Second half: new random items (should produce false positives)
    auto new_random_data = generate_test_data(test_size - inserted_items);
    data.test_data.insert(data.test_data.end(), new_random_data.begin(), new_random_data.end());
    for (const auto& s : new_random_data) data.negatives.insert(s);

    data.expected_inserted_count = data.positives.size();
    return data;
}

// Unified benchmark function for both BloomFilter types
template<typename BloomFilterType>
void run_unified_benchmark(const std::string& filter_name,
                           const BenchmarkTestData& test_data,
                           int num_threads,
                           fbloom_hash_func_t hash1_ptr,
                           fbloom_hash_func_t hash2_ptr) {
    std::cout << "\n=== " << filter_name << " (" << num_threads << " thread" << (num_threads > 1 ? "s" : "") << ") ===" << std::endl;

    // Create bloom filter with explicit apples-to-apples hash functions
    BloomFilterType filter(test_data.insert_data.size(), 0.01, hash1_ptr, hash2_ptr);

    // Measure insertion time
    auto insert_start = std::chrono::high_resolution_clock::now();

    if (num_threads == 1) {
        // Single-threaded insertion
        for (const auto& item : test_data.insert_data) {
            filter.insert(item);
        }
    } else {
        // Multi-threaded insertion
        std::vector<std::thread> threads;
        size_t chunk_size = test_data.insert_data.size() / num_threads;

        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = i * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.insert_data.size() : (i + 1) * chunk_size;

            WorkChunk chunk(&test_data.insert_data, start_idx, end_idx);
            threads.emplace_back([&, start_idx, end_idx]() {
                for (size_t j = start_idx; j < end_idx; ++j) {
                    filter.insert(test_data.insert_data[j]);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }

    auto insert_end = std::chrono::high_resolution_clock::now();
    double insert_time_ms = std::chrono::duration<double, std::milli>(insert_end - insert_start).count();

    // Measure contains time
    auto contains_start = std::chrono::high_resolution_clock::now();
    size_t found_total = 0;
    size_t tp_total = 0;
    size_t fp_total = 0;
    size_t fn_total = 0;

    if (num_threads == 1) {
        // Single-threaded contains
        size_t local_true_count = 0;
        size_t local_tp = 0;
        size_t local_fp = 0;
        size_t local_fn = 0;
        for (size_t j = 0; j < test_data.test_data.size(); ++j) {
            const auto& s = test_data.test_data[j];
            bool present = filter.contains(s);
            bool is_positive = test_data.positives.find(s) != test_data.positives.end();
            if (present) {
                local_true_count++;
                if (is_positive) local_tp++; else local_fp++;
            } else {
                if (is_positive) local_fn++;
            }
        }
        found_total = local_true_count;
        tp_total = local_tp;
        fp_total = local_fp;
        fn_total = local_fn;
    } else {
        // Multi-threaded contains
        struct ThreadCounts { size_t found; size_t tp; size_t fp; size_t fn; };
        std::vector<ThreadCounts> counters(num_threads, ThreadCounts{0,0,0,0});
        std::vector<std::thread> threads;
        size_t chunk_size = test_data.test_data.size() / num_threads;

        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = i * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.test_data.size() : (i + 1) * chunk_size;

            threads.emplace_back([&, start_idx, end_idx, i]() {
                size_t local_true_count = 0;
                size_t local_tp = 0;
                size_t local_fp = 0;
                size_t local_fn = 0;
                for (size_t j = start_idx; j < end_idx; ++j) {
                    const auto& s = test_data.test_data[j];
                    bool present = filter.contains(s);
                    bool is_positive = test_data.positives.find(s) != test_data.positives.end();
                    if (present) {
                        local_true_count++;
                        if (is_positive) local_tp++; else local_fp++;
                    } else {
                        if (is_positive) local_fn++;
                    }
                }
                counters[i] = ThreadCounts{local_true_count, local_tp, local_fp, local_fn};
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
        for (const auto& c : counters) {
            found_total += c.found;
            tp_total += c.tp;
            fp_total += c.fp;
            fn_total += c.fn;
        }
    }

    auto contains_end = std::chrono::high_resolution_clock::now();
    double contains_time_ms = std::chrono::duration<double, std::milli>(contains_end - contains_start).count();

    // Print results
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Insert time:      " << insert_time_ms << " ms" << std::endl;
    std::cout << "Contains time:    " << contains_time_ms << " ms" << std::endl;
    std::cout << "Elements/sec:     " << (test_data.insert_data.size() / insert_time_ms * 1000.0) << std::endl;
    std::cout << "Contains/sec:     " << (test_data.test_data.size() / contains_time_ms * 1000.0) << std::endl;

    // Validation & quality metrics
    size_t negatives = test_data.test_data.size() - test_data.expected_inserted_count;
    double fp_rate = negatives ? (static_cast<double>(fp_total) / static_cast<double>(negatives)) : 0.0;
    double fn_rate = test_data.expected_inserted_count ? (static_cast<double>(fn_total) / static_cast<double>(test_data.expected_inserted_count)) : 0.0;
    std::cout << "Found total:      " << found_total << " (TP=" << tp_total << ", FP=" << fp_total << ")" << std::endl;
    std::cout << "False positive %: " << (fp_rate * 100.0) << "%" << std::endl;
    std::cout << "False negative %: " << (fn_rate * 100.0) << "%" << std::endl;

    // Persist result row for later visualization
    write_tsv_row("benchmark_results.tsv", filter_name, num_threads,
                  test_data.insert_data.size(), test_data.test_data.size(), test_data.expected_inserted_count,
                  insert_time_ms, contains_time_ms, tp_total, fp_total, fn_total,
                  total_bits_used(filter));
}

// Benchmark function that uses pre-generated test data
void run_simple_benchmark_with_data(const std::string& hash_name, int num_threads, const BenchmarkTestData& test_data) {
    std::cout << "\n=== " << hash_name << " (" << num_threads << " thread" << (num_threads > 1 ? "s" : "") << ") ===" << std::endl;

    // Setup hash functions for BloomFilter
    fbloom_hash_func_t hash1_ptr = nullptr, hash2_ptr = nullptr;
    if (!select_hash_pair(hash_name, hash1_ptr, hash2_ptr)) { std::cerr << "Unknown hash function: " << hash_name << std::endl; return; }

    // Create bloom filter with hash functions
    BloomFilter filter( test_data.insert_data.size(), 0.01, hash1_ptr, hash2_ptr);

    // Measure insertion time
    auto insert_start = std::chrono::high_resolution_clock::now();

    if (num_threads == 1) {
        // Single-threaded insertion
        for (const auto& item : test_data.insert_data) {
            filter.insert(item);
        }
    } else {
        // Multi-threaded insertion
        std::vector<std::thread> threads;
        size_t chunk_size = test_data.insert_data.size() / num_threads;

        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = i * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.insert_data.size() : (i + 1) * chunk_size;

            threads.emplace_back([&, start_idx, end_idx]() {
                for (size_t j = start_idx; j < end_idx; ++j) {
                    filter.insert(test_data.insert_data[j]);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }

    auto insert_end = std::chrono::high_resolution_clock::now();
    double insert_time_ms = std::chrono::duration<double, std::milli>(insert_end - insert_start).count();

    // Measure contains time
    auto contains_start = std::chrono::high_resolution_clock::now();
    // Per-thread aggregation (no atomics to avoid perturbation)
    size_t found_total = 0;
    size_t tp_total = 0;
    size_t fp_total = 0;
    size_t fn_total = 0;

    if (num_threads == 1) {
        // Single-threaded contains (set-based ground truth)
        size_t local_true_count = 0;
        size_t local_tp = 0;
        size_t local_fp = 0;
        size_t local_fn = 0;
        for (size_t j = 0; j < test_data.test_data.size(); ++j) {
            const auto& s = test_data.test_data[j];
            bool present = filter.contains(s);
            bool is_positive = test_data.positives.find(s) != test_data.positives.end();
            if (present) {
                local_true_count++;
                if (is_positive) local_tp++; else local_fp++;
            } else {
                if (is_positive) local_fn++;
            }
        }
        found_total = local_true_count;
        tp_total = local_tp;
        fp_total = local_fp;
        fn_total = local_fn;
    } else {
        // Multi-threaded contains - aggregate per-thread (set-based ground truth)
        struct ThreadCounts { size_t found; size_t tp; size_t fp; size_t fn; };
        std::vector<ThreadCounts> counters(num_threads, ThreadCounts{0,0,0,0});
        std::vector<std::thread> threads;
        size_t chunk_size = test_data.test_data.size() / num_threads;

        for (int i = 0; i < num_threads; ++i) {
            size_t start_idx = i * chunk_size;
            size_t end_idx = (i == num_threads - 1) ? test_data.test_data.size() : (i + 1) * chunk_size;

            threads.emplace_back([&, start_idx, end_idx, i]() {
                size_t local_true_count = 0;
                size_t local_tp = 0;
                size_t local_fp = 0;
                size_t local_fn = 0;
                for (size_t j = start_idx; j < end_idx; ++j) {
                    const auto& s = test_data.test_data[j];
                    bool present = filter.contains(s);
                    bool is_positive = test_data.positives.find(s) != test_data.positives.end();
                    if (present) { local_true_count++; if (is_positive) local_tp++; else local_fp++; }
                    else { if (is_positive) local_fn++; }
                }
                counters[i] = ThreadCounts{local_true_count, local_tp, local_fp, local_fn};
            });
        }

        for (auto& thread : threads) thread.join();
        for (const auto& c : counters) {
            found_total += c.found;
            tp_total += c.tp;
            fp_total += c.fp;
            fn_total += c.fn;
        }
    }

    auto contains_end = std::chrono::high_resolution_clock::now();
    double contains_time_ms = std::chrono::duration<double, std::milli>(contains_end - contains_start).count();

    // Print results
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Insert time:      " << insert_time_ms << " ms" << std::endl;
    std::cout << "Contains time:    " << contains_time_ms << " ms" << std::endl;
    std::cout << "Elements/sec:     " << (test_data.insert_data.size() / insert_time_ms * 1000.0) << std::endl;
    std::cout << "Contains/sec:     " << (test_data.test_data.size() / contains_time_ms * 1000.0) << std::endl;

    // Validation & quality metrics
    size_t negatives = test_data.test_data.size() - test_data.expected_inserted_count;
    double fp_rate = negatives ? (static_cast<double>(fp_total) / static_cast<double>(negatives)) : 0.0;
    double fn_rate = test_data.expected_inserted_count ? (static_cast<double>(fn_total) / static_cast<double>(test_data.expected_inserted_count)) : 0.0;
    std::cout << "Found total:      " << found_total << " (TP=" << tp_total << ", FP=" << fp_total << ")" << std::endl;
    std::cout << "False positive %: " << (fp_rate * 100.0) << "%" << std::endl;
    std::cout << "False negative %: " << (fn_rate * 100.0) << "%" << std::endl;

    // Persist TSV
    write_tsv_row("benchmark_results.tsv", std::string("BloomFilter-") + hash_name, num_threads,
                  test_data.insert_data.size(), test_data.test_data.size(), test_data.expected_inserted_count,
                  insert_time_ms, contains_time_ms, tp_total, fp_total, fn_total,
                  total_bits_used(filter));
}

// Run benchmark for ParallelBloomFilter1 with pre-generated test data
template<int N, typename mutex_type>
void run_parallel_benchmark_with_data(const std::string& filter_name, int num_threads, const BenchmarkTestData& test_data, fbloom_hash_func_t hash1_ptr, fbloom_hash_func_t hash2_ptr) {
    // Use unified benchmark with ParallelBloomFilter1 and explicit hash functions
    run_unified_benchmark<ParallelBloomFilter1<N, mutex_type>>(filter_name, test_data, num_threads, hash1_ptr, hash2_ptr);
}

int main() {
    std::cout << "Unified Bloom Filter Benchmark - Same Data, Fair Comparison" << std::endl;
    std::cout << "===========================================================" << std::endl;

    // Generate test data ONCE for all benchmarks - ensures fair comparison
    std::cout << "Generating unified test data..." << std::endl;
    auto test_data = generate_unified_test_data(2500000); // Smaller dataset for testing: 500K insert, 50K test
    std::cout << "Test data generated: " << test_data.insert_data.size() << " insert items, "
              << test_data.test_data.size() << " test items" << std::endl;
    std::cout << "Expected inserted items in test data: " << test_data.expected_inserted_count << std::endl;

    // Apples-to-apples for both BloomFilter and ParallelBloomFilter1 across hashes and threads
    std::vector<std::string> hash_functions = {"XXHash64"};
    std::vector<int> thread_counts = {2, 4, 8 };

    for (const auto& hash_func : hash_functions) {
        // Plain Bloom
        for (int threads : thread_counts) {
            run_simple_benchmark_with_data(hash_func, threads, test_data);
        }

        // Parallel Bloom, null_mutex and std::mutex
        fbloom_hash_func_t h1=nullptr, h2=nullptr; if (!select_hash_pair(hash_func, h1, h2)) continue;
        std::cout << "\nParallel Bloom Filter Benchmarks (" << hash_func << ")" << std::endl;
        std::cout << "================================" << std::endl;
        std::cout << "\n--- Testing with null_mutex (no locking) ---" << std::endl;
        for (int threads : thread_counts) {
            run_parallel_benchmark_with_data<8, null_mutex>(std::string("ParallelBloomFilter1<8, null_mutex>-")+hash_func, threads, test_data, h1, h2);
        }
        std::cout << "\n--- Testing with std::mutex (with locking) ---" << std::endl;
        for (int threads : thread_counts) {
            run_parallel_benchmark_with_data<8, std::mutex>(std::string("ParallelBloomFilter1<8, std::mutex>-")+hash_func, threads, test_data, h1, h2);
        }
        std::cout << "\n--- Testing with spinlock (lightweight locking) ---" << std::endl;
        for (int threads : thread_counts) {
            run_parallel_benchmark_with_data<8, spinlock>(std::string("ParallelBloomFilter1<8, spinlock>-")+hash_func, threads, test_data, h1, h2);
        }
        // LockedBloomFilter (std::mutex) single-shard baseline
        std::cout << "\n--- Testing LockedBloomFilter (std::mutex) ---" << std::endl;
        for (int threads : thread_counts) {
            run_unified_benchmark<LockedBloomFilter<std::mutex>>(std::string("LockedBloomFilter<std::mutex>-")+hash_func, test_data, threads, h1, h2);
        }
    }

    // GloomFilter benchmarks (use same hash pair as above)
    std::cout << "\nGloom Filter Benchmarks (apples-to-apples)" << std::endl;
    std::cout << "===============================" << std::endl;
    for (const auto& hash_func : hash_functions) {
        fbloom_hash_func_t h1=nullptr, h2=nullptr; if (!select_hash_pair(hash_func, h1, h2)) continue;
        for (int threads : thread_counts) {
            run_gloom_benchmark_with_data(std::string("GloomFilter-")+hash_func, test_data, threads, 0.01, xxhash64_hash_u64_s0, xxhash64_hash_u64_s1);
        }
    }

    // RegisterBlockedGloomFilter benchmarks
    std::cout << "\nRegisterBlockedGloomFilter Benchmarks (apples-to-apples)" << std::endl;
    std::cout << "===============================================" << std::endl;
    for (const auto& hash_func : hash_functions) {
        for (int threads : thread_counts) {
            run_register_blocked_gloom_benchmark_with_data(std::string("RegisterBlockedGloomFilter-")+hash_func, test_data, threads, 0.01);
        }
    }

    // GloomFilter2 (clean) benchmarks
    std::cout << "\nGloomFilter2 (clean) Benchmarks (apples-to-apples)" << std::endl;
    std::cout << "===============================================" << std::endl;
    for (const auto& hash_func : hash_functions) {
        for (int threads : thread_counts) {
                run_gloom_clean_benchmark_with_data(std::string("GloomFilter2-clean-")+hash_func, test_data, threads, 0.01);
        }
    }

    std::cout << "\nBenchmark completed!" << std::endl;
    return 0;
}
