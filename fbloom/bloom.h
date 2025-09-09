#ifndef BLOOM_H
#define BLOOM_H

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FBLOOM_SCOPE
#define FBLOOM_SCOPE
#endif
#ifndef FBLOOM_INT_TYPE
#define FBLOOM_INT_TYPE uint32_t
#endif
#ifndef FBLOOM_PREFIX
#define FBLOOM_PREFIX fbloom_
#endif
#ifndef FBLOOM_ALLOC
#define FBLOOM_ALLOC(size) malloc(size)
#endif



#define _FBLOOM_CONCAT(prefix, name) prefix ## name
#define _FBLOOM_CONCAT_EVAL(prefix, name) _FBLOOM_CONCAT(prefix, name)
#define FBLOOM_NAME(name) _FBLOOM_CONCAT_EVAL(FBLOOM_PREFIX, name)

typedef FBLOOM_INT_TYPE (*FBLOOM_NAME(hash_func_t))(const void *data, size_t len, FBLOOM_INT_TYPE seed);

typedef struct FBLOOM_NAME(filter) {
  unsigned char *bit_array;
  size_t bit_array_size;
  size_t num_bits;
  size_t num_hash_functions;
  size_t inserted_elements;
  FBLOOM_NAME(hash_func_t) hash1;
  FBLOOM_NAME(hash_func_t) hash2;
} FBLOOM_NAME(filter);

FBLOOM_SCOPE bool FBLOOM_NAME(init)(FBLOOM_NAME(filter) *filter,
                                    size_t expected_elements,
                                    double false_positive_rate);
FBLOOM_SCOPE bool FBLOOM_NAME(init_with_hash)(FBLOOM_NAME(filter) *filter,
                                              size_t expected_elements,
                                              double false_positive_rate,
                                              FBLOOM_NAME(hash_func_t) hash1,
                                              FBLOOM_NAME(hash_func_t) hash2);
FBLOOM_SCOPE void FBLOOM_NAME(free)(FBLOOM_NAME(filter) *filter);
FBLOOM_SCOPE bool FBLOOM_NAME(contains)(FBLOOM_NAME(filter) *filter, const void *item,
                                        size_t item_size);
FBLOOM_SCOPE bool FBLOOM_NAME(insert)(FBLOOM_NAME(filter) *filter, const void *item,
                                      size_t item_size);
FBLOOM_SCOPE void FBLOOM_NAME(clear)(FBLOOM_NAME(filter) *filter);



#define FBLOOM_MURMURHASH_VERSION "0.2.0"

#ifdef __cplusplus
extern "C" {
#endif
 /**
 * `Taken from https://github.com/jwerle/murmurhash.c/ 
 *  - murmurhash -
 * copyright (c) 2014-2025 joseph werle <joseph.werle@gmail.com>
 */
  uint32_t FBLOOM_NAME(murmurhash) (const char*, uint32_t, uint32_t);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#define FBLOOM_NAMESPACE_BEGIN namespace fbloom{
#define FBLOOM_NAMESPACE_END }
#include <string>
#include <stdexcept>
#include <type_traits>
#include <cstring>

FBLOOM_NAMESPACE_BEGIN
class BloomFilter {
private:
    FBLOOM_NAME(filter) filter_;

public:
    BloomFilter(size_t expected_elements, double false_positive_rate);
    
    template<typename HashFunc1, typename HashFunc2>
    BloomFilter(size_t expected_elements, double false_positive_rate, 
               HashFunc1 hash1, HashFunc2 hash2);

    ~BloomFilter();

    BloomFilter(const BloomFilter&) = delete;
    BloomFilter& operator=(const BloomFilter&) = delete;

    BloomFilter(BloomFilter&& other) noexcept;
    BloomFilter& operator=(BloomFilter&& other) noexcept;

    template<typename T>
    bool insert(const T& item);
    
    template<typename T>
    bool contains(const T& item) const;
    void clear();

    size_t inserted_elements() const;
    size_t bit_array_size() const;
    size_t num_hash_functions() const;
};
FBLOOM_NAMESPACE_END
#endif /* __cplusplus */

#ifdef FBLOOM_IMPLEMENTATION


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#if MURMURHASH_WANTS_HTOLE32
#define MURMURHASH_HAS_HTOLE32 1
#ifndef htole32
static uint32_t htole32 (uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  value = (
    ((value & 0xFF000000) >> 24) |
    ((value & 0x00FF0000) >> 8)  |
    ((value & 0x0000FF00) << 8)  |
    ((value & 0x000000FF) << 24)
  );
#endif
  return value;
}
#endif
#endif

uint32_t FBLOOM_NAME(murmurhash) (const char *key, uint32_t len, uint32_t seed) {
   /**
 * `Taken from https://github.com/jwerle/murmurhash.c/ 
 *  - murmurhash -
 * copyright (c) 2014-2025 joseph werle <joseph.werle@gmail.com>
 */
  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;
  uint32_t r1 = 15;
  uint32_t r2 = 13;
  uint32_t m = 5;
  uint32_t n = 0xe6546b64;
  uint32_t h = 0;
  uint32_t k = 0;
  uint8_t *d = (uint8_t *) key; // 32 bit extract from `key'
  const uint32_t *chunks = NULL;
  const uint8_t *tail = NULL; // tail - last 8 bytes
  int i = 0;
  int l = len / 4; // chunk length

  h = seed;

  chunks = (const uint32_t *) (d + l * 4); // body
  tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

  // for each 4 byte chunk of `key'
  for (i = -l; i != 0; ++i) {
    // next 4 byte chunk of `key'
  #if MURMURHASH_HAS_HTOLE32
    k = htole32(chunks[i]);
  #else
    k = chunks[i];
  #endif

    // encode next 4 byte chunk of `key'
    k *= c1;
    k = (k << r1) | (k >> (32 - r1));
    k *= c2;

    // append to hash
    h ^= k;
    h = (h << r2) | (h >> (32 - r2));
    h = h * m + n;
  }

  k = 0;

  // remainder
  switch (len & 3) { // `len % 4'
    case 3: k ^= (tail[2] << 16);
    case 2: k ^= (tail[1] << 8);

    case 1:
      k ^= tail[0];
      k *= c1;
      k = (k << r1) | (k >> (32 - r1));
      k *= c2;
      h ^= k;
  }

  h ^= len;

  h ^= (h >> 16);
  h *= 0x85ebca6b;
  h ^= (h >> 13);
  h *= 0xc2b2ae35;
  h ^= (h >> 16);

  return h;
}
static size_t calculate_hash_functions(size_t num_bits,
                                       size_t expected_elements) {
  size_t k;
  if (expected_elements == 0)
    return 1;
  k = (size_t)((double)num_bits / expected_elements * 0.693147);
  return k > 0 ? k : 1;
}

static size_t calculate_bit_array_size(size_t expected_elements,
                                       double false_positive_rate) {
  double m;
  if (expected_elements == 0 || false_positive_rate <= 0.0 ||
      false_positive_rate >= 1.0) {
    return 1024;
  }
  m = -(expected_elements * log(false_positive_rate)) /
      (0.480453 * 0.480453);
  return (size_t)(m / 8) + 1;
}

static FBLOOM_INT_TYPE murmur_hash1(const void *data, size_t len, FBLOOM_INT_TYPE seed) {
  return FBLOOM_NAME(murmurhash)((const char*)data, (uint32_t)len, seed);
}

static FBLOOM_INT_TYPE murmur_hash2(const void *data, size_t len, FBLOOM_INT_TYPE seed) {
  return FBLOOM_NAME(murmurhash)((const char*)data, (uint32_t)len, seed ^ 0x87654321UL);
}

// Legacy hash functions (kept for backward compatibility)
static FBLOOM_INT_TYPE hash1(const void *data, size_t len, FBLOOM_INT_TYPE seed) {
  const unsigned char *bytes = (const unsigned char *)data;
  FBLOOM_INT_TYPE hash = seed ^ 5381;
  size_t i;
  for (i = 0; i < len; i++) {
    hash = ((hash << 5) + hash) + bytes[i];
  }
  return hash;
}

static FBLOOM_INT_TYPE hash2(const void *data, size_t len, FBLOOM_INT_TYPE seed) {
  const unsigned char *bytes = (const unsigned char *)data;
  FBLOOM_INT_TYPE hash = seed;
  size_t i;
  for (i = 0; i < len; i++) {
    hash = bytes[i] + (hash << 6) + (hash << 16) - hash;
  }
  return hash;
}

static FBLOOM_INT_TYPE get_hash(const void *data, size_t len, size_t i,
                                 size_t num_bits, FBLOOM_NAME(hash_func_t) hash_func1,
                                 FBLOOM_NAME(hash_func_t) hash_func2) {
  FBLOOM_INT_TYPE h1;
  FBLOOM_INT_TYPE h2;
  h1 = hash_func1(data, len, 0x9E3779B1UL);
  h2 = hash_func2(data, len, 0x85EBCA6BUL);
  return (h1 + i * h2) % num_bits;
}

static void set_bit(unsigned char *bit_array, size_t bit_index) {
  size_t byte_index;
  size_t bit_offset;
  byte_index = bit_index / 8;
  bit_offset = bit_index % 8;
  bit_array[byte_index] |= (1 << bit_offset);
}

static bool is_bit_set(const unsigned char *bit_array, size_t bit_index) {
  size_t byte_index;
  size_t bit_offset;
  byte_index = bit_index / 8;
  bit_offset = bit_index % 8;
  return (bit_array[byte_index] & (1 << bit_offset)) != 0;
}

FBLOOM_SCOPE bool FBLOOM_NAME(init)(FBLOOM_NAME(filter) *filter,
                                    size_t expected_elements,
                                    double false_positive_rate) {
  return FBLOOM_NAME(init_with_hash)(filter, expected_elements, false_positive_rate,
                                     murmur_hash1, murmur_hash2);
}

FBLOOM_SCOPE bool FBLOOM_NAME(init_with_hash)(FBLOOM_NAME(filter) *filter,
                                              size_t expected_elements,
                                              double false_positive_rate,
                                              FBLOOM_NAME(hash_func_t) hash_func1,
                                              FBLOOM_NAME(hash_func_t) hash_func2) {
  if (!filter || expected_elements == 0 || !hash_func1 || !hash_func2) {
    return false;
  }

  filter->bit_array_size =
      calculate_bit_array_size(expected_elements, false_positive_rate);
  filter->num_bits = filter->bit_array_size * 8;
  filter->num_hash_functions =
      calculate_hash_functions(filter->num_bits, expected_elements);
  filter->inserted_elements = 0;
  filter->hash1 = hash_func1;
  filter->hash2 = hash_func2;

  filter->bit_array =
      (unsigned char *)FBLOOM_ALLOC(filter->bit_array_size * sizeof(unsigned char));
  if (!filter->bit_array) {
    return false;
  }
  memset(filter->bit_array, 0, filter->bit_array_size);

  return true;
}

FBLOOM_SCOPE void FBLOOM_NAME(free)(FBLOOM_NAME(filter) *filter) {
  if (filter && filter->bit_array) {
    free(filter->bit_array);
    filter->bit_array = NULL;
    filter->bit_array_size = 0;
    filter->num_bits = 0;
    filter->num_hash_functions = 0;
    filter->inserted_elements = 0;
    filter->hash1 = NULL;
    filter->hash2 = NULL;
  }
}

FBLOOM_SCOPE bool FBLOOM_NAME(contains)(FBLOOM_NAME(filter) *filter, const void *item,
                                        size_t item_size) {
  size_t i;
  FBLOOM_INT_TYPE bit_index;

  if (!filter || !item || item_size == 0 || !filter->hash1 || !filter->hash2) {
    return false;
  }

  for (i = 0; i < filter->num_hash_functions; i++) {
    bit_index = get_hash(item, item_size, i, filter->num_bits, filter->hash1,
                         filter->hash2);
    if (!is_bit_set(filter->bit_array, (size_t)bit_index)) {
      return false;
    }
  }
  return true;
}

FBLOOM_SCOPE bool FBLOOM_NAME(insert)(FBLOOM_NAME(filter) *filter, const void *item,
                                      size_t item_size) {
  size_t i;
  FBLOOM_INT_TYPE bit_index;

  if (!filter || !item || item_size == 0 || !filter->hash1 || !filter->hash2) {
    return false;
  }

  for (i = 0; i < filter->num_hash_functions; i++) {
    bit_index = get_hash(item, item_size, i, filter->num_bits, filter->hash1,
                         filter->hash2);
    set_bit(filter->bit_array, (size_t)bit_index);
  }

  filter->inserted_elements++;
  return true;
}

FBLOOM_SCOPE void FBLOOM_NAME(clear)(FBLOOM_NAME(filter) *filter) {
  if (!filter || !filter->bit_array) {
    return;
  }

  memset(filter->bit_array, 0, filter->bit_array_size);
  filter->inserted_elements = 0;
}

#ifdef __cplusplus
FBLOOM_NAMESPACE_BEGIN
inline BloomFilter::BloomFilter(size_t expected_elements, double false_positive_rate) {
    if (!FBLOOM_NAME(init_with_hash)(&filter_, expected_elements, false_positive_rate, 
                                     murmur_hash1, murmur_hash2)) {
        throw std::runtime_error("Failed to initialize bloom filter");
    }
}

template<typename HashFunc1, typename HashFunc2>
inline BloomFilter::BloomFilter(size_t expected_elements, double false_positive_rate, 
                               HashFunc1 hash1, HashFunc2 hash2) {
    if (!FBLOOM_NAME(init_with_hash)(&filter_, expected_elements, false_positive_rate, hash1, hash2)) {
        throw std::runtime_error("Failed to initialize bloom filter with custom hash functions");
    }
}

inline BloomFilter::~BloomFilter() {
    FBLOOM_NAME(free)(&filter_);
}

inline BloomFilter::BloomFilter(BloomFilter&& other) noexcept : filter_(other.filter_) {
    other.filter_.bit_array = nullptr;
}

inline BloomFilter& BloomFilter::operator=(BloomFilter&& other) noexcept {
    if (this != &other) {
        FBLOOM_NAME(free)(&filter_);
        filter_ = other.filter_;
        other.filter_.bit_array = nullptr;
    }
    return *this;
}

template<typename T>
inline bool BloomFilter::insert(const T& item) {
    if constexpr (std::is_same_v<T, std::string>) {
        return FBLOOM_NAME(insert)(&filter_, item.c_str(), item.length());
    } else if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
        return FBLOOM_NAME(insert)(&filter_, item, std::strlen(item));
    } else if constexpr (std::is_trivially_copyable_v<T>) {
        return FBLOOM_NAME(insert)(&filter_, reinterpret_cast<const void*>(&item), sizeof(T));
    } else {
        static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable or std::string");
        return false;
    }
}

template<typename T>
inline bool BloomFilter::contains(const T& item) const {
    if constexpr (std::is_same_v<T, std::string>) {
        return FBLOOM_NAME(contains)(const_cast<FBLOOM_NAME(filter)*>(&filter_), item.c_str(), item.length());
    } else if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
        return FBLOOM_NAME(contains)(const_cast<FBLOOM_NAME(filter)*>(&filter_), item, std::strlen(item));
    } else if constexpr (std::is_trivially_copyable_v<T>) {
        return FBLOOM_NAME(contains)(const_cast<FBLOOM_NAME(filter)*>(&filter_), reinterpret_cast<const void*>(&item), sizeof(T));
    } else {
        static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable or std::string");
        return false;
    }
}

inline void BloomFilter::clear() {
    FBLOOM_NAME(clear)(&filter_);
}

inline size_t BloomFilter::inserted_elements() const {
    return filter_.inserted_elements;
}

inline size_t BloomFilter::bit_array_size() const {
    return filter_.bit_array_size;
}

inline size_t BloomFilter::num_hash_functions() const {
    return filter_.num_hash_functions;
}
FBLOOM_NAMESPACE_END
#endif /* __cplusplus */
#endif /* FBLOOM_IMPLEMENTATION */

#undef FBLOOM_NAME
#undef FBLOOM_PREFIX
#undef FBLOOM_INT_TYPE
#undef FBLOOM_CONCAT
#undef FBLOOM_ALLOC
#undef FBLOOM_CONCAT_EVAL
#undef FBLOOM_SCOPE
#undef FBLOOM_NAMESPACE_BEGIN
#undef FBLOOM_NAMESPACE_END
#endif /* BLOOM_H */
