// MIT License

// Copyright (c) 2023 Sasha Krassovsky

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// https://save-buffer.github.io/bloom_filter.html

#pragma once
#include <cmath>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <random>
#include "simde/simde/x86/avx2.h"

struct BasicBloomFilter
{
    BasicBloomFilter(int n, float eps) : n(n), epsilon(eps)
    {
        m = ComputeNumBits();
        k = ComputeNumHashFns();
        bv.resize((m + 7) / 8);
    }

    int ComputeNumBits()
    {
        return static_cast<int>(-1.44 * n * std::log2(epsilon) + 0.5);
    }

    int ComputeNumHashFns()
    {
        return static_cast<int>(-std::log2(epsilon) + 0.5);
    }

    void Insert(uint32_t h1, uint32_t h2)
    {
        for(int i = 0; i < k; i++)
        {
            uint32_t hash = (h1 + i * h2) % m;
            uint64_t bit_idx = hash % 8;
            uint64_t byte_idx = hash / 8;
            bv[byte_idx] |= (1 << bit_idx);
        }
    }

    bool Query(uint32_t h1, uint32_t h2)
    {
        bool result = true;
        for(int i = 0; i < k; i++)
        {
            uint32_t hash = (h1 + i * h2) % m;
            uint64_t bit_idx = hash % 8;
            uint64_t byte_idx = hash / 8;
            result &= (bv[byte_idx] >> bit_idx) & 1;
        }
        return result;
    }

    void Reset()
    {
        std::fill(bv.begin(), bv.end(), 0);
    }

    int n;
    float epsilon;

    int m;
    int k;
    std::vector<uint8_t> bv;
};

constexpr int CACHE_LINE_BITS = 256;
constexpr int CACHE_LINE_BYTES = CACHE_LINE_BITS / 8;

struct BlockedBloomFilter
{
    BlockedBloomFilter(int n, float eps) : n(n), epsilon(eps)
    {
        m = ComputeNumBits();
        k = ComputeNumHashFns();
        num_blocks = (m + CACHE_LINE_BITS - 1) / CACHE_LINE_BITS;
        bv.resize(num_blocks * CACHE_LINE_BYTES);
    }

    int ComputeNumBits()
    {
        return static_cast<int>(-1.44 * n * std::log2(epsilon) + 0.5);
    }

    int ComputeNumHashFns()
    {
        return static_cast<int>(-std::log2(epsilon) + 0.5);
    }

    uint8_t *GetBlock(uint32_t h1, uint32_t h2)
    {
        uint32_t block_idx = h1 % num_blocks;
        uint32_t byte_idx = block_idx * CACHE_LINE_BYTES;
        return bv.data() + byte_idx;
    }

    void Insert(uint32_t h1, uint32_t h2)
    {
        uint8_t *block = GetBlock(h1, h2);
        for(int i = 1; i < k; i++)
        {
            uint32_t bit_pos = (h1 + i * h2) % CACHE_LINE_BITS;
            uint64_t bit_idx = bit_pos % 8;
            uint64_t byte_idx = bit_pos / 8;
            block[byte_idx] |= (1 << bit_idx);
        }
    }

    bool Query(uint32_t h1, uint32_t h2)
    {
        bool result = true;
        uint8_t *block = GetBlock(h1, h2);
        for(int i = 1; i < k; i++)
        {
            uint32_t bit_pos = (h1 + i * h2) % CACHE_LINE_BITS;
            uint64_t bit_idx = bit_pos % 8;
            uint64_t byte_idx = bit_pos / 8;
            result &= (block[byte_idx] >> bit_idx) & 1;
        }
        return result;
    }

    void Reset()
    {
        std::fill(bv.begin(), bv.end(), 0);
    }

    int n;
    float epsilon;

    int num_blocks;
    int m;
    int k;
    std::vector<uint8_t> bv;
};

template <int Compensation>
struct RegisterBlockedBloomFilter
{
    RegisterBlockedBloomFilter(int n, float eps) : n(n), epsilon(eps)
    {
        m = ComputeNumBits();
        k = ComputeNumHashFns();
        num_blocks = (m + 64 - 1) / 64;
        bv.resize(num_blocks);
    }

    int ComputeNumBits()
    {
        auto bits_per_val = -1.44 * std::log2(epsilon) + Compensation;
        return static_cast<int>(bits_per_val * n + 0.5);
    }

    int ComputeNumHashFns()
    {
        return static_cast<int>(-std::log2(epsilon) + 0.5);
    }

    uint64_t *GetBlock(uint32_t h1, uint32_t h2)
    {
        uint32_t block_idx = h1 % num_blocks;
        return &bv[block_idx];
    }

    uint64_t ConstructMask(uint32_t h1, uint32_t h2)
    {
        uint64_t mask = 0;
        for(int i = 1; i < k; i++)
        {
            uint32_t bit_pos = (h1 + i * h2) % 64;
            mask |= (1ull << bit_pos);
        }
        return mask;
    }

    void Insert(uint32_t h1, uint32_t h2)
    {
        uint64_t *block = GetBlock(h1, h2);
        *block |= ConstructMask(h1, h2);
    }

    bool Query(uint32_t h1, uint32_t h2)
    {
        uint64_t *block = GetBlock(h1, h2);
        uint64_t mask = ConstructMask(h1, h2);
        return (*block & mask) == mask;
    }

    void Reset()
    {
        std::fill(bv.begin(), bv.end(), 0);
    }

    int n;
    float epsilon;

    int num_blocks;
    int m;
    int k;
    std::vector<uint64_t> bv;
};

struct SimdBloomFilter
{
    SimdBloomFilter(int n, float eps) : n(n), epsilon(eps)
    {
        m = ComputeNumBits();
        k = ComputeNumHashFns();
        int log_num_blocks = 32 - __builtin_clz(m) - 6;
        num_blocks = (1 << log_num_blocks);
        bv.resize(num_blocks);
    }

    uint64_t ComputeNumBits()
    {
        double bits_per_val = -1.44 * std::log2(epsilon);
        return static_cast<uint64_t>(bits_per_val * n + 0.5);
    }

    int ComputeNumHashFns()
    {
        return static_cast<int>(-std::log2(epsilon) + 0.5);
    }

    void GetBlockIdx(simde__m256i &vecBlockIdx, simde__m256i &vecH1, simde__m256i &vecH2)
    {
        simde__m256i vecNumBlocksMask = simde_mm256_set1_epi64x(num_blocks - 1);
        vecBlockIdx = simde_mm256_and_si256(vecH1, vecNumBlocksMask);
    }

    void ConstructMask(
        simde__m256i &vecMask,
        simde__m256i &vecH1,
        simde__m256i &vecH2)
    {
        simde__m256i vecShiftMask = simde_mm256_set1_epi64x((1 << 6) - 1);
        simde__m256i vecOnes = simde_mm256_set1_epi64x(1);
        for(int i = 1; i < k; i++)
        {
            simde__m256i vecI = simde_mm256_set1_epi64x(i);
            simde__m256i vecMulH2 = simde_mm256_mul_epi32(vecI, vecH2);
            simde__m256i vecHash = simde_mm256_add_epi64(vecH1, vecMulH2);
            simde__m256i vecShift = simde_mm256_and_si256(vecHash, vecShiftMask);
            simde__m256i vecPartial = simde_mm256_sllv_epi64(vecOnes, vecShift);
            vecMask = simde_mm256_or_si256(vecMask, vecPartial);
        }
    }

    void Insert(uint32_t *h1, uint32_t *h2)
    {
        simde__m256i vecH1A = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h1 + 0)));
        simde__m256i vecH1B = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h1 + 4)));
        simde__m256i vecH2A = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h2 + 0)));
        simde__m256i vecH2B = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h2 + 4)));

        simde__m256i vecMaskA = simde_mm256_setzero_si256();
        simde__m256i vecMaskB = simde_mm256_setzero_si256();
        ConstructMask(vecMaskA, vecH1A, vecH2A);
        ConstructMask(vecMaskB, vecH1B, vecH2B);

        simde__m256i vecBlockIdxA;
        simde__m256i vecBlockIdxB;
        GetBlockIdx(vecBlockIdxA, vecH1A, vecH2A);
        GetBlockIdx(vecBlockIdxB, vecH1B, vecH2B);

        uint64_t block0 = simde_mm256_extract_epi64(vecBlockIdxA, 0);
        uint64_t block1 = simde_mm256_extract_epi64(vecBlockIdxA, 1);
        uint64_t block2 = simde_mm256_extract_epi64(vecBlockIdxA, 2);
        uint64_t block3 = simde_mm256_extract_epi64(vecBlockIdxA, 3);
        uint64_t block4 = simde_mm256_extract_epi64(vecBlockIdxB, 0);
        uint64_t block5 = simde_mm256_extract_epi64(vecBlockIdxB, 1);
        uint64_t block6 = simde_mm256_extract_epi64(vecBlockIdxB, 2);
        uint64_t block7 = simde_mm256_extract_epi64(vecBlockIdxB, 3);

        // Uncomment to generate histogram of block distribution
        // printf("%d, %d, %d, %d, %d, %d, %d, %d,\n", block0, block1, block2, block3, block4, block5, block6, block7);

        bv[block0] |= simde_mm256_extract_epi64(vecMaskA, 0);
        bv[block1] |= simde_mm256_extract_epi64(vecMaskA, 1);
        bv[block2] |= simde_mm256_extract_epi64(vecMaskA, 2);
        bv[block3] |= simde_mm256_extract_epi64(vecMaskA, 3);
        bv[block4] |= simde_mm256_extract_epi64(vecMaskB, 0);
        bv[block5] |= simde_mm256_extract_epi64(vecMaskB, 1);
        bv[block6] |= simde_mm256_extract_epi64(vecMaskB, 2);
        bv[block7] |= simde_mm256_extract_epi64(vecMaskB, 3);
    }

    uint8_t Query(uint32_t *h1, uint32_t *h2)
    {
        simde__m256i vecH1A = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h1 + 0)));
        simde__m256i vecH1B = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h1 + 4)));
        simde__m256i vecH2A = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h2 + 0)));
        simde__m256i vecH2B = simde_mm256_cvtepi32_epi64(simde_mm_loadu_si128(reinterpret_cast<simde__m128i *>(h2 + 4)));

        simde__m256i vecMaskA = simde_mm256_setzero_si256();
        simde__m256i vecMaskB = simde_mm256_setzero_si256();
        ConstructMask(vecMaskA, vecH1A, vecH2A);
        ConstructMask(vecMaskB, vecH1B, vecH2B);

        simde__m256i vecBlockIdxA;
        simde__m256i vecBlockIdxB;
        GetBlockIdx(vecBlockIdxA, vecH1A, vecH2A);
        GetBlockIdx(vecBlockIdxB, vecH1B, vecH2B);

        simde__m256i vecBloomA = simde_mm256_i64gather_epi64((const long long *)bv.data(), vecBlockIdxA, sizeof(uint64_t));
        simde__m256i vecBloomB = simde_mm256_i64gather_epi64((const long long *)bv.data(), vecBlockIdxB, sizeof(uint64_t));
        simde__m256i vecCmpA = simde_mm256_cmpeq_epi64(simde_mm256_and_si256(vecMaskA, vecBloomA), vecMaskA);
        simde__m256i vecCmpB = simde_mm256_cmpeq_epi64(simde_mm256_and_si256(vecMaskB, vecBloomB), vecMaskB);
        uint32_t res_a = static_cast<uint32_t>(simde_mm256_movemask_epi8(vecCmpA));
        uint32_t res_b = static_cast<uint32_t>(simde_mm256_movemask_epi8(vecCmpB));
        uint64_t res_bytes = res_a | (static_cast<uint64_t>(res_b) << 32);
        uint8_t res_bits = static_cast<uint8_t>(simde_mm256_movemask_epi8(simde_mm256_set1_epi64x(res_bytes)) & 0xff);
        return res_bits;
    }

    void Reset()
    {
        std::fill(bv.begin(), bv.end(), 0);
    }

    int n;
    float epsilon;

    uint64_t num_blocks;
    int m;
    int k;
    std::vector<uint64_t> bv;
};

struct MaskTable
{
    MaskTable()
    {
        std::memset(masks, 0, sizeof(masks));
        std::random_device rd;
        std::default_random_engine gen(rd());
        std::uniform_int_distribution<int> first_mask_distrib(min_bits_set, max_bits_set);
        std::uniform_int_distribution<int> bit_pos_distrib(0, bits_per_mask - 1);
        std::uniform_int_distribution<int> bit_set_distrib(0, bits_per_mask * 2 - 1);

        int num_set_in_first_mask = first_mask_distrib(gen);
        for(int i = 0; i < num_set_in_first_mask; i++)
        {
            int bit_pos;
            do
            {
                bit_pos = bit_pos_distrib(gen);
            } while((masks[bit_pos / 8] >> (bit_pos % 8)) & 1);
            masks[bit_pos / 8] |= (1 << (bit_pos) % 8);
        }

        int total_bits = num_masks + bits_per_mask - 1;
        int num_set_in_current_mask = num_set_in_first_mask;
        for(int i = bits_per_mask; i < total_bits; i++)
        {
            int leaving_bit_idx = i - bits_per_mask;
            int leaving_bit = (masks[leaving_bit_idx / 8] >> (leaving_bit_idx % 8)) & 1;
            if(leaving_bit == 1 && num_set_in_current_mask == min_bits_set)
            {
                masks[i / 8] |= (1 << (i % 8));
                continue;
            }
            if(leaving_bit == 0 && num_set_in_current_mask == max_bits_set)
            {
                continue;
            }

            if(bit_set_distrib(gen) < min_bits_set + max_bits_set)
            {
                masks[i / 8] |= (1 << (i % 8));
                if(leaving_bit == 0)
                    num_set_in_current_mask += 1;
            }
            else
            {
                if(leaving_bit == 1)
                    num_set_in_current_mask -= 1;
            }
        }
    }

    static constexpr int bits_per_mask = 57;
    static constexpr int min_bits_set = 4;
    static constexpr int max_bits_set = 5;

    static constexpr int log_num_masks = 10;
    static constexpr int num_masks = 1 << log_num_masks;
    static constexpr int mask_bytes = (num_masks + 64) / 8;
    uint8_t masks[mask_bytes];
};

struct PatternedSimdBloomFilter
{
    PatternedSimdBloomFilter(int n, float eps) : n(n), epsilon(eps)
    {
        m = ComputeNumBits();
        int log_num_blocks = 32 - __builtin_clz(m) - rotate_bits;
        num_blocks = (1ULL << log_num_blocks);
        bv.resize(num_blocks);
    }

    uint64_t ComputeNumBits()
    {
        return std::max(512, 8 * n);
    }

    void GetBlockIdx(simde__m256i &vecBlockIdx, simde__m256i &vecHash)
    {
        simde__m256i vecNumBlocksMask = simde_mm256_set1_epi64x(num_blocks - 1);
        vecBlockIdx = simde_mm256_srli_epi64(vecHash, mask_idx_bits + rotate_bits);
        vecBlockIdx = simde_mm256_and_si256(vecBlockIdx, vecNumBlocksMask);
    }

    void ConstructMask(
        simde__m256i &vecMask,
        simde__m256i &vecHash)
    {
        simde__m256i vecMaskIdxMask = simde_mm256_set1_epi64x((1 << mask_idx_bits) - 1);
        simde__m256i vecMaskMask = simde_mm256_set1_epi64x((1ull << MaskTable::bits_per_mask) - 1);
        simde__m256i vec64 = simde_mm256_set1_epi64x(64);

        simde__m256i vecMaskIdx = simde_mm256_and_si256(vecHash, vecMaskIdxMask);
        simde__m256i vecMaskByteIdx = simde_mm256_srli_epi64(vecMaskIdx, 3);
        simde__m256i vecMaskBitIdx = simde_mm256_and_si256(vecMaskIdx, simde_mm256_set1_epi64x(0x7));
        simde__m256i vecRawMasks = simde_mm256_i64gather_epi64((const long long *)masks.masks, vecMaskByteIdx, 1);
        simde__m256i vecUnrotated = simde_mm256_and_si256(simde_mm256_srlv_epi64(vecRawMasks, vecMaskBitIdx), vecMaskMask);

        simde__m256i vecRotation = simde_mm256_and_si256(simde_mm256_srli_epi64(vecHash, mask_idx_bits), simde_mm256_set1_epi64x((1 << rotate_bits) - 1));
        simde__m256i vecShiftUp = simde_mm256_sllv_epi64(vecUnrotated, vecRotation);
        simde__m256i vecShiftDown = simde_mm256_srlv_epi64(vecUnrotated, simde_mm256_sub_epi64(vec64, vecRotation));
        vecMask = simde_mm256_or_si256(vecShiftDown, vecShiftUp);
    }

    void Insert(uint64_t *hash)
    {
        simde__m256i vecHashA = simde_mm256_loadu_si256(reinterpret_cast<simde__m256i *>(hash + 0));
        simde__m256i vecHashB = simde_mm256_loadu_si256(reinterpret_cast<simde__m256i *>(hash + 4));

        simde__m256i vecMaskA = simde_mm256_setzero_si256();
        simde__m256i vecMaskB = simde_mm256_setzero_si256();
        ConstructMask(vecMaskA, vecHashA);
        ConstructMask(vecMaskB, vecHashB);

        simde__m256i vecBlockIdxA;
        simde__m256i vecBlockIdxB;
        GetBlockIdx(vecBlockIdxA, vecHashA);
        GetBlockIdx(vecBlockIdxB, vecHashB);

        uint64_t block0 = simde_mm256_extract_epi64(vecBlockIdxA, 0);
        uint64_t block1 = simde_mm256_extract_epi64(vecBlockIdxA, 1);
        uint64_t block2 = simde_mm256_extract_epi64(vecBlockIdxA, 2);
        uint64_t block3 = simde_mm256_extract_epi64(vecBlockIdxA, 3);
        uint64_t block4 = simde_mm256_extract_epi64(vecBlockIdxB, 0);
        uint64_t block5 = simde_mm256_extract_epi64(vecBlockIdxB, 1);
        uint64_t block6 = simde_mm256_extract_epi64(vecBlockIdxB, 2);
        uint64_t block7 = simde_mm256_extract_epi64(vecBlockIdxB, 3);

        // Uncomment to generate histogram of block distribution
        // printf("%d, %d, %d, %d, %d, %d, %d, %d,\n", block0, block1, block2, block3, block4, block5, block6, block7);

        bv[block0] |= simde_mm256_extract_epi64(vecMaskA, 0);
        bv[block1] |= simde_mm256_extract_epi64(vecMaskA, 1);
        bv[block2] |= simde_mm256_extract_epi64(vecMaskA, 2);
        bv[block3] |= simde_mm256_extract_epi64(vecMaskA, 3);
        bv[block4] |= simde_mm256_extract_epi64(vecMaskB, 0);
        bv[block5] |= simde_mm256_extract_epi64(vecMaskB, 1);
        bv[block6] |= simde_mm256_extract_epi64(vecMaskB, 2);
        bv[block7] |= simde_mm256_extract_epi64(vecMaskB, 3);
    }

    uint8_t Query(uint64_t *hash)
    {
        simde__m256i vecHashA = simde_mm256_loadu_si256(reinterpret_cast<simde__m256i *>(hash + 0));
        simde__m256i vecHashB = simde_mm256_loadu_si256(reinterpret_cast<simde__m256i *>(hash + 4));

        simde__m256i vecMaskA = simde_mm256_setzero_si256();
        simde__m256i vecMaskB = simde_mm256_setzero_si256();
        ConstructMask(vecMaskA, vecHashA);
        ConstructMask(vecMaskB, vecHashB);

        simde__m256i vecBlockIdxA;
        simde__m256i vecBlockIdxB;
        GetBlockIdx(vecBlockIdxA, vecHashA);
        GetBlockIdx(vecBlockIdxB, vecHashB);

        simde__m256i vecBloomA = simde_mm256_i64gather_epi64((const long long *)bv.data(), vecBlockIdxA, sizeof(uint64_t));
        simde__m256i vecBloomB = simde_mm256_i64gather_epi64((const long long *)bv.data(), vecBlockIdxB, sizeof(uint64_t));
        simde__m256i vecCmpA = simde_mm256_cmpeq_epi64(simde_mm256_and_si256(vecMaskA, vecBloomA), vecMaskA);
        simde__m256i vecCmpB = simde_mm256_cmpeq_epi64(simde_mm256_and_si256(vecMaskB, vecBloomB), vecMaskB);
        uint32_t res_a = static_cast<uint32_t>(simde_mm256_movemask_epi8(vecCmpA));
        uint32_t res_b = static_cast<uint32_t>(simde_mm256_movemask_epi8(vecCmpB));
        uint64_t res_bytes = res_a | (static_cast<uint64_t>(res_b) << 32);
        uint8_t res_bits = static_cast<uint8_t>(simde_mm256_movemask_epi8(simde_mm256_set1_epi64x(res_bytes)) & 0xff);
        return res_bits;
    }

    void Reset()
    {
        std::fill(bv.begin(), bv.end(), 0);
    }

    int n;
    float epsilon;

    uint64_t num_blocks;
    uint64_t m;
    MaskTable masks;
    std::vector<uint64_t> bv;    

    static constexpr int mask_idx_bits = MaskTable::log_num_masks;
    static constexpr int rotate_bits = 6;
};
