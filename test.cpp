#define FBLOOM_IMPLEMENTATION
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <cassert>
#include <algorithm>
#include <random>
#include <set>
#include "fbloom/bloom.h"
extern "C" {
#include "fbloom/external/xxhash.h"
}

using namespace fbloom;


static uint32_t cpp_custom_hash1(const void* data, size_t len, uint32_t seed) {
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    uint32_t hash = seed ^ 0x9e3779b9;
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= 0x85ebca6b;
    }
    return hash;
}

static uint32_t cpp_custom_hash2(const void* data, size_t len, uint32_t seed) {
    const unsigned char* bytes = static_cast<const unsigned char*>(data);
    uint32_t hash = seed;
    for (size_t i = 0; i < len; ++i) {
        hash = hash * 33 + bytes[i];
    }
    return hash;
}


void test_cpp_basic_functionality() {
    std::cout << "=== Testing C++ Basic Functionality ===" << std::endl;
    
    BloomFilter filter(1000, 0.01);
    
    std::vector<std::string> test_items = {
        "apple", "banana", "cherry", "date", "elderberry", "fig", "grape"
    };
    
    std::cout << "Bloom filter initialized successfully" << std::endl;
    std::cout << "   - Bit array size: " << filter.bit_array_size() << " bytes" << std::endl;
    std::cout << "   - Hash functions: " << filter.num_hash_functions() << std::endl;
    
    std::cout << "\nInserting " << test_items.size() << " items:" << std::endl;
    for (const auto& item : test_items) {
        bool success = filter.insert(item);
        std::cout << "   " << item << ": " << (success ? "OK" : "FAIL") << std::endl;
        assert(success);
    }
    
    std::cout << "   Inserted elements count: " << filter.inserted_elements() << std::endl;
    
    std::cout << "\nTesting contains for inserted items:" << std::endl;
    for (const auto& item : test_items) {
        bool found = filter.contains(item);
        std::cout << "   " << item << ": " << (found ? "might be in set" : "definitely not in set") << std::endl;
        assert(found);
    }
    
    std::vector<std::string> non_inserted = {"mango", "orange", "pear", "kiwi"};
    std::cout << "\nTesting contains for non-inserted items:" << std::endl;
    for (const auto& item : non_inserted) {
        bool found = filter.contains(item);
        std::cout << "   " << item << ": " << (found ? "false positive" : "correctly not found") << std::endl;
    }
    
    std::cout << "C++ basic functionality test completed successfully" << std::endl;
}

void test_cpp_raii_and_move_semantics() {
    std::cout << "\n=== Testing C++ RAII and Move Semantics ===" << std::endl;
    
    std::vector<BloomFilter> filters;
    
    {
        BloomFilter temp_filter(100, 0.05);
        temp_filter.insert("test_item");
        assert(temp_filter.contains("test_item"));
        
        filters.emplace_back(std::move(temp_filter));
    }
    
    assert(filters[0].contains("test_item"));
    
    auto moved_filter = std::move(filters[0]);
    assert(moved_filter.contains("test_item"));
    
    std::cout << "RAII and move semantics work correctly" << std::endl;
}

void test_cpp_stl_integration() {
    std::cout << "\n=== Testing STL Integration ===" << std::endl;
    
    BloomFilter filter(10000, 0.01);
    
    std::vector<std::string> words;
    std::set<std::string> inserted_words;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(5, 15);
    
    for (int i = 0; i < 1000; ++i) {
        std::string word = "word_" + std::to_string(i);
        words.push_back(word);
        if (i % 2 == 0) {
            filter.insert(word);
            inserted_words.insert(word);
        }
    }
    
    std::cout << "Inserted " << inserted_words.size() << " words into bloom filter" << std::endl;
    
    size_t true_positives = 0;
    size_t false_positives = 0;
    
    for (const auto& word : words) {
        bool in_filter = filter.contains(word);
        bool actually_inserted = inserted_words.count(word) > 0;
        
        if (actually_inserted && in_filter) {
            true_positives++;
        } else if (!actually_inserted && in_filter) {
            false_positives++;
        }
    }
    
    std::cout << "True positives: " << true_positives << "/" << inserted_words.size() << std::endl;
    std::cout << "False positives: " << false_positives << "/" << (words.size() - inserted_words.size()) << std::endl;
    
    double false_positive_rate = static_cast<double>(false_positives) / (words.size() - inserted_words.size());
    std::cout << "False positive rate: " << (false_positive_rate * 100.0) << "%" << std::endl;
    
    assert(true_positives == inserted_words.size());
    assert(false_positive_rate < 0.05);
    
    std::cout << "STL integration test completed successfully" << std::endl;
}

void test_cpp_custom_hash_functions() {
    std::cout << "\n=== Testing C++ Custom Hash Functions ===" << std::endl;
    
    BloomFilter filter(1000, 0.01, cpp_custom_hash1, cpp_custom_hash2);
    
    std::vector<std::string> items = {"cpp_test1", "cpp_test2", "cpp_test3", "cpp_test4"};
    
    std::cout << "Using custom C++ hash functions" << std::endl;
    std::cout << "   - Bit array size: " << filter.bit_array_size() << " bytes" << std::endl;
    std::cout << "   - Hash functions: " << filter.num_hash_functions() << std::endl;
    
    for (const auto& item : items) {
        bool success = filter.insert(item);
        std::cout << "   Insert " << item << ": " << (success ? "OK" : "FAIL") << std::endl;
        assert(success);
    }
    
    for (const auto& item : items) {
        bool found = filter.contains(item);
        std::cout << "   Contains " << item << ": " << (found ? "might be in set" : "definitely not in set") << std::endl;
        assert(found);
    }
    
    bool found = filter.contains("not_inserted_cpp");
    std::cout << "   Contains not_inserted_cpp: " << (found ? "false positive" : "correctly not found") << std::endl;
    
    std::cout << "C++ custom hash functions test completed successfully" << std::endl;
}

void test_cpp_external_hash_functions() {
    std::cout << "\n=== Testing C++ Default Hash Functions (MurmurHash) ===" << std::endl;
    
    BloomFilter default_filter(1000, 0.01);
    
    std::vector<std::string> items = {"default_cpp1", "default_cpp2", "default_cpp3"};
    
    std::cout << "Using default hash functions (MurmurHash)" << std::endl;
    std::cout << "   - Bit array size: " << default_filter.bit_array_size() << " bytes" << std::endl;
    std::cout << "   - Hash functions: " << default_filter.num_hash_functions() << std::endl;
    
    for (const auto& item : items) {
        bool success = default_filter.insert(item);
        std::cout << "   Insert " << item << ": " << (success ? "OK" : "FAIL") << std::endl;
        assert(success);
    }
    
    for (const auto& item : items) {
        bool found = default_filter.contains(item);
        std::cout << "   Contains " << item << ": " << (found ? "might be in set" : "definitely not in set") << std::endl;
        assert(found);
    }
    
    std::cout << "C++ default hash functions test completed successfully" << std::endl;
}

void test_cpp_performance() {
    std::cout << "\n=== C++ Performance Test ===" << std::endl;
    
    constexpr size_t num_operations = 10000;
    BloomFilter filter(num_operations * 2, 0.01);
    
    std::vector<std::string> items;
    items.reserve(num_operations);
    for (size_t i = 0; i < num_operations; ++i) {
        items.emplace_back("perf_item_" + std::to_string(i));
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (const auto& item : items) {
        filter.insert(item);
    }
    
    auto insert_end = std::chrono::high_resolution_clock::now();
    
    size_t found_count = 0;
    for (const auto& item : items) {
        if (filter.contains(item)) {
            found_count++;
        }
    }
    
    auto lookup_end = std::chrono::high_resolution_clock::now();
    
    auto insert_duration = std::chrono::duration_cast<std::chrono::microseconds>(insert_end - start);
    auto lookup_duration = std::chrono::duration_cast<std::chrono::microseconds>(lookup_end - insert_end);
    
    std::cout << "Performance test completed:" << std::endl;
    std::cout << "   - Inserted: " << num_operations << " items" << std::endl;
    std::cout << "   - Found: " << found_count << " items" << std::endl;
    std::cout << "   - Insert time: " << insert_duration.count() << " μs" << std::endl;
    std::cout << "   - Lookup time: " << lookup_duration.count() << " μs" << std::endl;
    std::cout << "   - Insert rate: " << (num_operations * 1000000.0 / insert_duration.count()) << " ops/sec" << std::endl;
    std::cout << "   - Lookup rate: " << (num_operations * 1000000.0 / lookup_duration.count()) << " ops/sec" << std::endl;
    
    assert(found_count == num_operations);
    
    std::cout << "C++ performance test completed successfully" << std::endl;
}

void test_cpp_pod_types() {
    std::cout << "\n=== Testing C++ POD Types ===" << std::endl;
    
    BloomFilter filter(1000, 0.01);
    
    // Test integers
    std::cout << "Testing integer types:" << std::endl;
    int int_val = 42;
    uint64_t uint64_val = 0xDEADBEEFCAFEBABE;
    double double_val = 3.14159;
    
    assert(filter.insert(int_val));
    assert(filter.insert(uint64_val));
    assert(filter.insert(double_val));
    
    assert(filter.contains(int_val));
    assert(filter.contains(uint64_val));
    assert(filter.contains(double_val));
    
    std::cout << "   int(42): " << (filter.contains(int_val) ? "found" : "not found") << std::endl;
    std::cout << "   uint64_t: " << (filter.contains(uint64_val) ? "found" : "not found") << std::endl;
    std::cout << "   double(3.14159): " << (filter.contains(double_val) ? "found" : "not found") << std::endl;
    
    // Test different values of same type
    int different_int = 43;
    assert(!filter.contains(different_int) || true); // might be false positive
    std::cout << "   int(43): " << (filter.contains(different_int) ? "false positive" : "correctly not found") << std::endl;
    
    // Test struct
    struct TestStruct {
        int a;
        float b;
        char c;
    };
    
    TestStruct struct1{123, 4.56f, 'X'};
    TestStruct struct2{124, 4.56f, 'X'};
    
    assert(filter.insert(struct1));
    assert(filter.contains(struct1));
    std::cout << "   TestStruct{123,4.56,'X'}: " << (filter.contains(struct1) ? "found" : "not found") << std::endl;
    std::cout << "   TestStruct{124,4.56,'X'}: " << (filter.contains(struct2) ? "false positive" : "correctly not found") << std::endl;
    
    // Test C-style strings
    const char* cstr = "hello world";
    assert(filter.insert(cstr));
    assert(filter.contains(cstr));
    std::cout << "   C-string 'hello world': " << (filter.contains(cstr) ? "found" : "not found") << std::endl;
    
    const char* different_cstr = "hello world!";
    std::cout << "   C-string 'hello world!': " << (filter.contains(different_cstr) ? "false positive" : "correctly not found") << std::endl;
    
    std::cout << "POD types test completed successfully" << std::endl;
}

void test_cpp_exception_safety() {
    std::cout << "\n=== Testing C++ Exception Safety ===" << std::endl;
    
    try {
        BloomFilter filter(0, 0.01);
        assert(false && "Should have thrown an exception");
    } catch (const std::runtime_error& e) {
        std::cout << "   Invalid filter creation threw exception correctly: " << e.what() << std::endl;
    }
    
    try {
        BloomFilter valid_filter(100, 0.01);
        valid_filter.insert("test");
        assert(valid_filter.contains("test"));
        std::cout << "   Valid filter operations work correctly" << std::endl;
    } catch (...) {
        assert(false && "Unexpected exception thrown for valid operations");
    }
    
    std::cout << "Exception safety test completed successfully" << std::endl;
}

int main() {
    std::cout << "C++ Bloom Filter Test Suite" << std::endl;
    std::cout << "============================" << std::endl;
    
    try {
        test_cpp_basic_functionality();
        test_cpp_raii_and_move_semantics();
        test_cpp_stl_integration();
        test_cpp_custom_hash_functions();
        test_cpp_external_hash_functions();
        test_cpp_performance();
        test_cpp_pod_types();
        test_cpp_exception_safety();
        
        std::cout << "\nAll C++ tests passed!" << std::endl;
        std::cout << "The bloom filter works perfectly with C++ features!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
    
    return 0;
}
