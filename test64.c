#define FBLOOM_PREFIX fbloom64_
#define FBLOOM_INT_TYPE uint64_t
#define FBLOOM_IMPLEMENTATION
#define MURMURHASH_IMPLEMENTATION
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "fbloom/bloom.h"
#include "fbloom/external/xxhash.h"

void test_64bit_basic_functionality(void);
void test_64bit_clear_functionality(void);
void test_64bit_edge_cases(void);
void test_64bit_custom_hash_functions(void);
void test_64bit_external_hash_functions(void);
void test_64bit_performance(void);

uint64_t custom_hash1_64bit_impl(const void* data, size_t len, uint64_t seed);
uint64_t custom_hash2_64bit_impl(const void* data, size_t len, uint64_t seed);

static uint64_t custom_hash1_64bit(const void* data, size_t len, uint64_t seed) { return custom_hash1_64bit_impl(data, len, seed); }
static uint64_t custom_hash2_64bit(const void* data, size_t len, uint64_t seed) { return custom_hash2_64bit_impl(data, len, seed); }
static uint64_t xxhash_wrapper1_64bit(const void* data, size_t len, uint64_t seed) { return XXH64(data, len, seed); }
static uint64_t xxhash_wrapper2_64bit(const void* data, size_t len, uint64_t seed) { return XXH64(data, len, seed ^ 0x87654321ULL); }

void test_64bit_basic_functionality(void) {
    fbloom64_filter filter;
    const char* test_items[] = {
        "apple", "banana", "cherry", "date", "elderberry"
    };
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    const char* non_inserted[] = {"mango", "orange", "pear"};
    size_t num_non_inserted = sizeof(non_inserted) / sizeof(non_inserted[0]);
    size_t i;
    bool success;
    bool found;
    
    printf("=== Testing 64-bit Basic Functionality ===\n");
    
    if (!fbloom64_init(&filter, 1000, 0.01)) {
        printf("Failed to initialize 64-bit bloom filter\n");
        return;
    }
    
    printf("64-bit bloom filter initialized successfully\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)filter.bit_array_size);
    printf("   - Total bits: %lu\n", (unsigned long)filter.num_bits);
    printf("   - Hash functions: %lu\n", (unsigned long)filter.num_hash_functions);
    printf("   - Using 64-bit hash functions (FBLOOM_INT_TYPE = uint64_t)\n");
    
    printf("\nInserting %lu items:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom64_insert(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("   Inserted elements count: %lu\n", (unsigned long)filter.inserted_elements);
    
    printf("\nTesting contains for inserted items:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom64_contains(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found); /* All inserted items should be found */
    }
    
    printf("\nTesting contains for non-inserted items:\n");
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom64_contains(&filter, non_inserted[i], strlen(non_inserted[i]));
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    fbloom64_free(&filter);
    printf("64-bit bloom filter cleaned up\n");
}

void test_64bit_clear_functionality(void) {
    fbloom64_filter filter;
    const char* items[] = {"test1", "test2", "test3"};
    size_t i;
    bool found;
    
    printf("\n=== Testing 64-bit Clear Functionality ===\n");
    
    fbloom64_init(&filter, 100, 0.05);
    
    for (i = 0; i < 3; i++) {
        fbloom64_insert(&filter, items[i], strlen(items[i]));
    }
    
    printf("Before clear: %lu elements\n", (unsigned long)filter.inserted_elements);
    assert(filter.inserted_elements == 3);
    assert(fbloom64_contains(&filter, "test1", 5));
    
    fbloom64_clear(&filter);
    printf("After clear: %lu elements\n", (unsigned long)filter.inserted_elements);
    assert(filter.inserted_elements == 0);
    
    found = fbloom64_contains(&filter, "test1", 5);
    printf("'test1' after clear: %s\n", found ? "still found" : "correctly not found");
    assert(!found);
    
    fbloom64_free(&filter);
    printf("64-bit clear functionality works correctly\n");
}

void test_64bit_edge_cases(void) {
    fbloom64_filter filter;
    bool result;
    bool found;
    
    printf("\n=== Testing 64-bit Edge Cases ===\n");
    
    printf("Testing invalid parameters:\n");
    result = fbloom64_init(&filter, 0, 0.01);  /* 0 expected elements */
    printf("   fbloom64_init with 0 elements: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    fbloom64_init(&filter, 10, 0.1);
    
    result = fbloom64_insert(&filter, NULL, 5);
    printf("   insert with NULL item: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    result = fbloom64_insert(&filter, "test", 0);
    printf("   insert with 0 size: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    found = fbloom64_contains(&filter, NULL, 5);
    printf("   contains with NULL item: %s\n", found ? "should be false" : "correctly false");
    assert(!found);
    
    found = fbloom64_contains(&filter, "test", 0);
    printf("   contains with 0 size: %s\n", found ? "should be false" : "correctly false");
    assert(!found);
    
    fbloom64_free(&filter);
    printf("64-bit edge cases handled correctly\n");
}

void test_64bit_custom_hash_functions(void) {
    fbloom64_filter filter;
    const char* test_items[] = {"custom1", "custom2", "custom3"};
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    size_t i;
    bool success;
    bool found;
    
    printf("\n=== Testing 64-bit Custom Hash Functions ===\n");
    
    if (!fbloom64_init_with_hash(&filter, 100, 0.05, custom_hash1_64bit, custom_hash2_64bit)) {
        printf("Failed to initialize 64-bit bloom filter with custom hash functions\n");
        return;
    }
    
    printf("64-bit bloom filter initialized with custom hash functions\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)filter.num_hash_functions);
    
    printf("\nInserting %lu items with 64-bit custom hash functions:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom64_insert(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("\nTesting contains with 64-bit custom hash functions:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom64_contains(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found); /* All inserted items should be found */
    }
    
    found = fbloom64_contains(&filter, "notfound", 8);
    printf("   notfound: %s\n", found ? "false positive" : "correctly not found");
    
    fbloom64_free(&filter);
    printf("64-bit custom hash function test completed successfully\n");
}

void test_64bit_external_hash_functions(void) {
    fbloom64_filter murmur_filter, xxhash_filter;
    const char* test_items[] = {"external1", "external2", "external3", "external4", "external5"};
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    const char* non_inserted[] = {"missing1", "missing2"};
    size_t num_non_inserted = sizeof(non_inserted) / sizeof(non_inserted[0]);
    size_t i;
    bool success;
    bool found;
    size_t murmur_false_positives = 0;
    size_t xxhash_false_positives = 0;
    
    printf("\n=== Testing 64-bit External Hash Functions ===\n");
    
    printf("\n--- Testing 64-bit Default Hash Functions (MurmurHash) ---\n");
    if (!fbloom64_init(&murmur_filter, 1000, 0.01)) {
        printf("Failed to initialize 64-bit bloom filter with default hash functions\n");
        return;
    }
    
    printf("64-bit default hash functions (MurmurHash) bloom filter initialized\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)murmur_filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)murmur_filter.num_hash_functions);
    
    printf("Inserting %lu items with 64-bit default hash functions:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom64_insert(&murmur_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("Testing contains with 64-bit default hash functions:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom64_contains(&murmur_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found);
    }
    
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom64_contains(&murmur_filter, non_inserted[i], strlen(non_inserted[i]));
        if (found) murmur_false_positives++;
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    printf("\n--- Testing 64-bit xxHash64 ---\n");
    if (!fbloom64_init_with_hash(&xxhash_filter, 1000, 0.01, xxhash_wrapper1_64bit, xxhash_wrapper2_64bit)) {
        printf("Failed to initialize 64-bit bloom filter with xxHash\n");
        fbloom64_free(&murmur_filter);
        return;
    }
    
    printf("64-bit xxHash bloom filter initialized\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)xxhash_filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)xxhash_filter.num_hash_functions);
    
    printf("Inserting %lu items with 64-bit xxHash:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom64_insert(&xxhash_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("Testing contains with 64-bit xxHash:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom64_contains(&xxhash_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found);
    }
    
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom64_contains(&xxhash_filter, non_inserted[i], strlen(non_inserted[i]));
        if (found) xxhash_false_positives++;
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    printf("\n--- 64-bit External Hash Function Summary ---\n");
    printf("Default hash functions (MurmurHash) false positives: %lu/%lu\n", (unsigned long)murmur_false_positives, (unsigned long)num_non_inserted);
    printf("xxHash false positives: %lu/%lu\n", (unsigned long)xxhash_false_positives, (unsigned long)num_non_inserted);
    
    fbloom64_free(&murmur_filter);
    fbloom64_free(&xxhash_filter);
    printf("64-bit external hash function tests completed successfully\n");
}

void test_64bit_performance(void) {
    fbloom64_filter filter;
    const size_t num_operations = 1000; /* Reduced for C89 compatibility */
    char item_buffer[32];
    size_t i;
    size_t found_count = 0;
    
    printf("\n=== 64-bit Performance Test ===\n");
    
    fbloom64_init(&filter, 10000, 0.01);
    
    printf("Performing %lu insert and lookup operations with 64-bit hashing...\n", (unsigned long)num_operations);
    
    for (i = 0; i < num_operations; i++) {
        sprintf(item_buffer, "item_%lu", (unsigned long)i);
        fbloom64_insert(&filter, item_buffer, strlen(item_buffer));
    }
    
    for (i = 0; i < num_operations; i++) {
        sprintf(item_buffer, "item_%lu", (unsigned long)i);
        if (fbloom64_contains(&filter, item_buffer, strlen(item_buffer))) {
            found_count++;
        }
    }
    
    printf("64-bit performance test completed\n");
    printf("   - Inserted: %lu items\n", (unsigned long)num_operations);
    printf("   - Found: %lu items\n", (unsigned long)found_count);
    printf("   - Filter stats: %lu elements, %lu bytes\n",
           (unsigned long)filter.inserted_elements, (unsigned long)filter.bit_array_size);
    
    assert(found_count == num_operations); /* All items should be found */
    
    fbloom64_free(&filter);
}

uint64_t custom_hash1_64bit_impl(const void* data, size_t len, uint64_t seed) {
    const unsigned char* bytes = (const unsigned char*)data;
    uint64_t hash = seed ^ 14695981039346656037ULL; /* FNV-1a 64-bit offset basis with seed */
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL; /* FNV-1a 64-bit prime */
    }
    return hash;
}

uint64_t custom_hash2_64bit_impl(const void* data, size_t len, uint64_t seed) {
    const unsigned char* bytes = (const unsigned char*)data;
    uint64_t hash = seed;
    size_t i;
    for (i = 0; i < len; i++) {
        hash = hash * 31 + bytes[i]; /* Simple polynomial hash */
    }
    return hash;
}

int main(void) {
    printf("64-bit Bloom Filter Test Suite\n");
    printf("===============================\n");
    
    test_64bit_basic_functionality();
    test_64bit_clear_functionality();
    test_64bit_edge_cases();
    test_64bit_custom_hash_functions();
    test_64bit_external_hash_functions();
    test_64bit_performance();
    
    printf("\nAll 64-bit tests passed!\n");
    printf("The 64-bit bloom filter implementation (fbloom64_) is working correctly.\n");
    
    return 0;
}
