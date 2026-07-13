#include <string.h>

#include "unity.h"
#include "mbedtls/sha256.h"
#include "sha256d.h"
#include "utils.h"

// Deterministic pseudorandom fill so failures are reproducible
static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed)
{
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)(x >> 24);
    }
}

static void reference_double_sha256(const uint8_t *data, size_t len, uint8_t dest[32])
{
    uint8_t first[32];
    mbedtls_sha256(data, len, first, 0);
    mbedtls_sha256(first, 32, dest, 0);
}

TEST_CASE("sha256_32 matches mbedtls", "[sha256d]")
{
    for (uint32_t seed = 0; seed < 8; seed++) {
        uint8_t data[32], expected[32], got[32];
        fill_pattern(data, sizeof(data), seed);
        mbedtls_sha256(data, sizeof(data), expected, 0);
        sha256_32(data, got);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, got, 32);
    }
}

TEST_CASE("sha256d_64 matches mbedtls double SHA-256", "[sha256d]")
{
    for (uint32_t seed = 0; seed < 8; seed++) {
        uint8_t data[64], expected[32], got[32];
        fill_pattern(data, sizeof(data), 100 + seed);
        reference_double_sha256(data, sizeof(data), expected);
        sha256d_64(data, got);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, got, 32);
    }
}

TEST_CASE("sha256 midstate resume matches one-shot double SHA-256", "[sha256d]")
{
    // midstate + remainder must produce the same digest as one-shot SHA-256
    for (uint32_t seed = 0; seed < 4; seed++) {
        uint8_t data[80], expected[32], got[32];
        fill_pattern(data, sizeof(data), 200 + seed);

        reference_double_sha256(data, sizeof(data), expected);

        uint32_t midstate[8];
        sha256_midstate_words(data, midstate);
        sha256d_80_from_midstate(midstate, data + 64, got);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, got, 32);
    }
}

TEST_CASE("midstate_sha256_bin matches pinned bm1397 verifier vector", "[sha256d]")
{
    // Pinned vector: midstate of the block header prefix from the
    // "Validate bm job construction" test in test_mining.c
    uint8_t midstate_data[64];
    uint8_t prev_block_hash[32];
    uint8_t merkle_root[32];
    uint32_t version = 0x20000004;

    hex2bin("bf44fd3513dc7b837d60e5c628b572b448d204a8000007490000000000000000", prev_block_hash, 32);
    reverse_endianness_per_word(prev_block_hash);
    hex2bin("cd1be82132ef0d12053dcece1fa0247fcfdb61d4dbd3eb32ea9ef9b4c604a846", merkle_root, 32);

    memcpy(midstate_data, &version, 4);
    memcpy(midstate_data + 4, prev_block_hash, 32);
    memcpy(midstate_data + 36, merkle_root, 28);

    uint8_t midstate[32];
    midstate_sha256_bin(midstate_data, 64, midstate);

    // The pinned vector (from verifiers/bm1397.py) lists the state words in
    // little-endian byte order; midstate_sha256_bin serializes them big-endian.
    uint8_t expected[32];
    hex2bin("91DFEA528A9F73683D0D495DD6DD7415E1CA21CB411759E3E05D7D5FF285314D", expected, 32);
    reverse_endianness_per_word(expected);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, midstate, 32);
}
