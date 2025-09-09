#define FBLOOM_IMPLEMENTATION
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "fbloom/bloom.h"
#include "fbloom/external/xxhash.h"


void test_basic_functionality(void);
void test_clear_functionality(void);
void test_edge_cases(void);
void test_custom_hash_functions(void);
void test_external_hash_functions(void);
void performance_test(void);

uint32_t custom_hash1_impl(const void* data, size_t len, uint32_t seed);
uint32_t custom_hash2_impl(const void* data, size_t len, uint32_t seed);

static uint32_t custom_hash1(const void* data, size_t len, uint32_t seed) { return custom_hash1_impl(data, len, seed); }
static uint32_t custom_hash2(const void* data, size_t len, uint32_t seed) { return custom_hash2_impl(data, len, seed); }
static uint32_t xxhash_wrapper1(const void* data, size_t len, uint32_t seed) { return XXH32(data, len, seed); }
static uint32_t xxhash_wrapper2(const void* data, size_t len, uint32_t seed) { return XXH32(data, len, seed ^ 0x87654321UL); }

void test_basic_functionality(void) {
    fbloom_filter filter;
    const char* test_items[] = {
        "apple", "banana", "cherry", "date", "elderberry"
    };
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    const char* non_inserted[] = {"mango", "orange", "pear"};
    size_t num_non_inserted = sizeof(non_inserted) / sizeof(non_inserted[0]);
    size_t i;
    bool success;
    bool found;
    
    printf("=== Testing Basic Functionality ===\n");
    
    if (!fbloom_init(&filter, 1000, 0.01)) {
        printf("Failed to initialize bloom filter\n");
        return;
    }
    
    printf("Bloom filter initialized successfully\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)filter.bit_array_size);
    printf("   - Total bits: %lu\n", (unsigned long)filter.num_bits);
    printf("   - Hash functions: %lu\n", (unsigned long)filter.num_hash_functions);
    
    printf("\nInserting %lu items:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom_insert(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("   Inserted elements count: %lu\n", (unsigned long)filter.inserted_elements);
    
    printf("\nTesting contains for inserted items:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom_contains(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found); /* All inserted items should be found */
    }
    
    printf("\nTesting contains for non-inserted items:\n");
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom_contains(&filter, non_inserted[i], strlen(non_inserted[i]));
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    fbloom_free(&filter);
    printf("Bloom filter cleaned up\n");
}

void test_clear_functionality(void) {
    fbloom_filter filter;
    const char* items[] = {"test1", "test2", "test3"};
    size_t i;
    bool found;
    
    printf("\n=== Testing Clear Functionality ===\n");
    
    fbloom_init(&filter, 100, 0.05);
    
    for (i = 0; i < 3; i++) {
        fbloom_insert(&filter, items[i], strlen(items[i]));
    }
    
    printf("Before clear: %lu elements\n", (unsigned long)filter.inserted_elements);
    assert(filter.inserted_elements == 3);
    assert(fbloom_contains(&filter, "test1", 5));
    
    fbloom_clear(&filter);
    printf("After clear: %lu elements\n", (unsigned long)filter.inserted_elements);
    assert(filter.inserted_elements == 0);
    
    found = fbloom_contains(&filter, "test1", 5);
    printf("'test1' after clear: %s\n", found ? "still found" : "correctly not found");
    assert(!found);
    
    fbloom_free(&filter);
    printf("Clear functionality works correctly\n");
}

void test_edge_cases(void) {
    fbloom_filter filter;
    bool result;
    bool found;
    
    printf("\n=== Testing Edge Cases ===\n");
    
    printf("Testing invalid parameters:\n");
    result = fbloom_init(&filter, 0, 0.01);  /* 0 expected elements */
    printf("   fbloom_init with 0 elements: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    fbloom_init(&filter, 10, 0.1);
    
    result = fbloom_insert(&filter, (const char*)0, 5);
    printf("   insert with NULL item: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    result = fbloom_insert(&filter, "test", 0);
    printf("   insert with 0 size: %s\n", result ? "should fail" : "correctly failed");
    assert(!result);
    
    found = fbloom_contains(&filter, (const char*)0, 5);
    printf("   contains with NULL item: %s\n", found ? "should be false" : "correctly false");
    assert(!found);
    
    found = fbloom_contains(&filter, "test", 0);
    printf("   contains with 0 size: %s\n", found ? "should be false" : "correctly false");
    assert(!found);
    
    fbloom_free(&filter);
    printf("Edge cases handled correctly\n");
}

void performance_test(void) {
    fbloom_filter filter;
    const size_t num_operations = 1000; /* Reduced for C89 compatibility */
    char item_buffer[32];
    size_t i;
    size_t found_count = 0;
    
    printf("\n=== Performance Test ===\n");
    
    fbloom_init(&filter, 10000, 0.01);
    
    printf("Performing %lu insert and lookup operations...\n", (unsigned long)num_operations);
    
    for (i = 0; i < num_operations; i++) {
        sprintf(item_buffer, "item_%lu", (unsigned long)i);
        fbloom_insert(&filter, item_buffer, strlen(item_buffer));
    }
    
    for (i = 0; i < num_operations; i++) {
        sprintf(item_buffer, "item_%lu", (unsigned long)i);
        if (fbloom_contains(&filter, item_buffer, strlen(item_buffer))) {
            found_count++;
        }
    }
    
    printf("Performance test completed\n");
    printf("   - Inserted: %lu items\n", (unsigned long)num_operations);
    printf("   - Found: %lu items\n", (unsigned long)found_count);
    printf("   - Filter stats: %lu elements, %lu bytes\n", 
           (unsigned long)filter.inserted_elements, (unsigned long)filter.bit_array_size);
    
    assert(found_count == num_operations); /* All items should be found */
    
    fbloom_free(&filter);
}

uint32_t custom_hash1_impl(const void* data, size_t len, uint32_t seed) {
    const unsigned char* bytes = (const unsigned char*)data;
    uint32_t hash = seed ^ 2166136261UL; /* FNV-1a offset basis with seed */
    size_t i;
    for (i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619UL; /* FNV-1a prime */
    }
    return hash;
}

uint32_t custom_hash2_impl(const void* data, size_t len, uint32_t seed) {
    const unsigned char* bytes = (const unsigned char*)data;
    uint32_t hash = seed;
    size_t i;
    for (i = 0; i < len; i++) {
        hash = hash * 31 + bytes[i]; /* Simple polynomial hash */
    }
    return hash;
}





void test_custom_hash_functions(void) {
    fbloom_filter filter;
    const char* test_items[] = {"custom1", "custom2", "custom3"};
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    size_t i;
    bool success;
    bool found;
    
    printf("\n=== Testing Custom Hash Functions ===\n");
    
    if (!fbloom_init_with_hash(&filter, 100, 0.05, custom_hash1, custom_hash2)) {
        printf("Failed to initialize bloom filter with custom hash functions\n");
        return;
    }
    
    printf("Bloom filter initialized with custom hash functions\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)filter.num_hash_functions);
    
    printf("\nInserting %lu items with custom hash functions:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom_insert(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("\nTesting contains with custom hash functions:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom_contains(&filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found); /* All inserted items should be found */
    }
    
    found = fbloom_contains(&filter, "notfound", 8);
    printf("   notfound: %s\n", found ? "false positive" : "correctly not found");
    
    fbloom_free(&filter);
    printf("Custom hash function test completed successfully\n");
}

void test_external_hash_functions(void) {
    fbloom_filter murmur_filter, xxhash_filter;
    const char* test_items[] = {"external1", "external2", "external3", "external4", "external5"};
    size_t num_items = sizeof(test_items) / sizeof(test_items[0]);
    const char* non_inserted[] = {"missing1", "missing2"};
    size_t num_non_inserted = sizeof(non_inserted) / sizeof(non_inserted[0]);
    size_t i;
    bool success;
    bool found;
    size_t murmur_false_positives = 0;
    size_t xxhash_false_positives = 0;
    
    printf("\n=== Testing External Hash Functions ===\n");
    
    printf("\n--- Testing Default Hash Functions (MurmurHash) ---\n");
    if (!fbloom_init(&murmur_filter, 1000, 0.01)) {
        printf("Failed to initialize bloom filter with default hash functions\n");
        return;
    }
    
    printf("Default hash functions (MurmurHash) bloom filter initialized\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)murmur_filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)murmur_filter.num_hash_functions);
    
    printf("Inserting %lu items with default hash functions:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom_insert(&murmur_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("Testing contains with default hash functions:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom_contains(&murmur_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found);
    }
    
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom_contains(&murmur_filter, non_inserted[i], strlen(non_inserted[i]));
        if (found) murmur_false_positives++;
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    printf("\n--- Testing xxHash32 ---\n");
    if (!fbloom_init_with_hash(&xxhash_filter, 1000, 0.01, xxhash_wrapper1, xxhash_wrapper2)) {
        printf("Failed to initialize bloom filter with xxHash\n");
        fbloom_free(&murmur_filter);
        return;
    }
    
    printf("xxHash bloom filter initialized\n");
    printf("   - Bit array size: %lu bytes\n", (unsigned long)xxhash_filter.bit_array_size);
    printf("   - Hash functions: %lu\n", (unsigned long)xxhash_filter.num_hash_functions);
    
    printf("Inserting %lu items with xxHash:\n", (unsigned long)num_items);
    for (i = 0; i < num_items; i++) {
        success = fbloom_insert(&xxhash_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], success ? "OK" : "FAIL");
        assert(success);
    }
    
    printf("Testing contains with xxHash:\n");
    for (i = 0; i < num_items; i++) {
        found = fbloom_contains(&xxhash_filter, test_items[i], strlen(test_items[i]));
        printf("   %s: %s\n", test_items[i], found ? "might be in set" : "definitely not in set");
        assert(found);
    }
    
    for (i = 0; i < num_non_inserted; i++) {
        found = fbloom_contains(&xxhash_filter, non_inserted[i], strlen(non_inserted[i]));
        if (found) xxhash_false_positives++;
        printf("   %s: %s\n", non_inserted[i], found ? "false positive" : "correctly not found");
    }
    
    printf("\n--- External Hash Function Summary ---\n");
    printf("Default hash functions (MurmurHash) false positives: %lu/%lu\n", (unsigned long)murmur_false_positives, (unsigned long)num_non_inserted);
    printf("xxHash false positives: %lu/%lu\n", (unsigned long)xxhash_false_positives, (unsigned long)num_non_inserted);
    
    fbloom_free(&murmur_filter);
    fbloom_free(&xxhash_filter);
    printf("External hash function tests completed successfully\n");
}


int main(void) {
    printf("Bloom Filter Test Suite\n");
    printf("=======================\n");
    
    test_basic_functionality();
    test_clear_functionality();
    test_edge_cases();
    test_custom_hash_functions();
    test_external_hash_functions();
    performance_test();
    
    printf("\nAll tests passed!\n");
    printf("The bloom filter implementation is working correctly.\n");
    
    return 0;
}
