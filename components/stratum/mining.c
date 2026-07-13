#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "mining.h"
#include "utils.h"
#include "sha256d.h"
#include "mbedtls/sha256.h"
#include "esp_log.h"

void free_bm_job(bm_job *job)
{
    free(job->jobid);
    free(job->extranonce2);
    free(job);
}

void calculate_coinbase_tx_hash(const char *coinbase_1, const char *coinbase_2, const char *extranonce, const char *extranonce_2, uint8_t dest[32])
{
    size_t len1 = strlen(coinbase_1);
    size_t len2 = strlen(extranonce);
    size_t len3 = strlen(extranonce_2);
    size_t len4 = strlen(coinbase_2);

    size_t coinbase_tx_bin_len = (len1 + len2 + len3 + len4) / 2;

    uint8_t coinbase_tx_bin[coinbase_tx_bin_len];

    size_t bin_offset = 0;
    bin_offset += hex2bin(coinbase_1, coinbase_tx_bin + bin_offset, coinbase_tx_bin_len - bin_offset);
    bin_offset += hex2bin(extranonce, coinbase_tx_bin + bin_offset, coinbase_tx_bin_len - bin_offset);
    bin_offset += hex2bin(extranonce_2, coinbase_tx_bin + bin_offset, coinbase_tx_bin_len - bin_offset);
    bin_offset += hex2bin(coinbase_2, coinbase_tx_bin + bin_offset, coinbase_tx_bin_len - bin_offset);

    double_sha256_bin(coinbase_tx_bin, coinbase_tx_bin_len, dest);
}

void calculate_coinbase_tx_hash_bin(const uint8_t *prefix, size_t prefix_len,
                                    const uint8_t *extranonce_prefix, size_t ep_len,
                                    const uint8_t *extranonce_2, size_t e2_len,
                                    const uint8_t *suffix, size_t suffix_len,
                                    uint8_t dest[32])
{
    size_t total_len = prefix_len + ep_len + e2_len + suffix_len;
    uint8_t *buf = malloc(total_len);
    if (!buf) return;

    size_t offset = 0;
    memcpy(buf + offset, prefix, prefix_len);   offset += prefix_len;
    memcpy(buf + offset, extranonce_prefix, ep_len); offset += ep_len;
    memcpy(buf + offset, extranonce_2, e2_len); offset += e2_len;
    memcpy(buf + offset, suffix, suffix_len);

    double_sha256_bin(buf, total_len, dest);
    free(buf);
}

bool coinbase_hasher_init(coinbase_hasher_t *hasher, const char *coinbase_1,
                          const char *extranonce_1, const char *coinbase_2)
{
    coinbase_hasher_free(hasher);

    size_t prefix_len = (strlen(coinbase_1) + strlen(extranonce_1)) / 2;
    uint8_t *prefix_bin = malloc(prefix_len > 0 ? prefix_len : 1);
    if (prefix_bin == NULL) {
        return false;
    }
    size_t offset = hex2bin(coinbase_1, prefix_bin, prefix_len);
    offset += hex2bin(extranonce_1, prefix_bin + offset, prefix_len - offset);

    hasher->coinbase_2_len = strlen(coinbase_2) / 2;
    hasher->coinbase_2_bin = malloc(hasher->coinbase_2_len > 0 ? hasher->coinbase_2_len : 1);
    if (hasher->coinbase_2_bin == NULL) {
        free(prefix_bin);
        return false;
    }
    hex2bin(coinbase_2, hasher->coinbase_2_bin, hasher->coinbase_2_len);

    mbedtls_sha256_init(&hasher->prefix_ctx);
    mbedtls_sha256_starts(&hasher->prefix_ctx, 0);
    mbedtls_sha256_update(&hasher->prefix_ctx, prefix_bin, offset);
    free(prefix_bin);

    hasher->valid = true;
    return true;
}

void coinbase_hasher_hash(const coinbase_hasher_t *hasher, const uint8_t *extranonce_2,
                          size_t extranonce_2_len, uint8_t dest[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, &hasher->prefix_ctx);
    mbedtls_sha256_update(&ctx, extranonce_2, extranonce_2_len);
    mbedtls_sha256_update(&ctx, hasher->coinbase_2_bin, hasher->coinbase_2_len);

    uint8_t first_hash[32];
    mbedtls_sha256_finish(&ctx, first_hash);
    mbedtls_sha256_free(&ctx);

    sha256_32(first_hash, dest);
}

void coinbase_hasher_free(coinbase_hasher_t *hasher)
{
    if (!hasher->valid) {
        return;
    }
    mbedtls_sha256_free(&hasher->prefix_ctx);
    free(hasher->coinbase_2_bin);
    hasher->coinbase_2_bin = NULL;
    hasher->coinbase_2_len = 0;
    hasher->valid = false;
}

void calculate_merkle_root_hash(const uint8_t coinbase_tx_hash[32], const uint8_t merkle_branches[][32], const int num_merkle_branches, uint8_t dest[32])
{
    uint8_t both_merkles[64];
    memcpy(both_merkles, coinbase_tx_hash, 32);
    for (int i = 0; i < num_merkle_branches; i++) {
        memcpy(both_merkles + 32, merkle_branches[i], 32);
        double_sha256_bin(both_merkles, 64, both_merkles);
    }

    memcpy(dest, both_merkles, 32);
}

// Compute the midstate(s) covering block header bytes 0-63: version(4B) +
// prev_block_hash(32B) + merkle_root[0:28]. Inputs are in header byte order;
// the stored midstates are word-reversed for the BM job packet.
void bm_job_compute_midstates(bm_job *job, const uint8_t prev_block_hash[32],
                              const uint8_t merkle_root[32], uint32_t version_mask)
{
    uint8_t midstate_data[64];
    memcpy(midstate_data, &job->version, 4);
    memcpy(midstate_data + 4, prev_block_hash, 32);
    memcpy(midstate_data + 36, merkle_root, 28);

    uint8_t midstate[32];
    midstate_sha256_bin(midstate_data, 64, midstate);
    reverse_32bit_words(midstate, job->midstate);

    if (version_mask != 0)
    {
        uint8_t *extra_midstates[3] = {job->midstate1, job->midstate2, job->midstate3};
        uint32_t rolled_version = job->version;
        for (int i = 0; i < 3; i++)
        {
            rolled_version = increment_bitmask(rolled_version, version_mask);
            memcpy(midstate_data, &rolled_version, 4);
            midstate_sha256_bin(midstate_data, 64, midstate);
            reverse_32bit_words(midstate, extra_midstates[i]);
        }
        job->num_midstates = 4;
    }
    else
    {
        job->num_midstates = 1;
    }
}

// take a mining_notify struct with ascii hex strings and convert it to a bm_job struct
void construct_bm_job(mining_notify *params, const uint8_t merkle_root[32], const uint32_t version_mask, const double difficulty, bm_job *new_job)
{
    new_job->version = params->version;
    new_job->target = params->target;
    new_job->ntime = params->ntime;
    new_job->starting_nonce = 0;
    new_job->pool_diff = difficulty;
    reverse_32bit_words(merkle_root, new_job->merkle_root);

    uint8_t prev_block_hash[32];
    hex2bin(params->prev_block_hash, prev_block_hash, 32);
    reverse_endianness_per_word(prev_block_hash);
    reverse_32bit_words(prev_block_hash, new_job->prev_block_hash);

    bm_job_compute_midstates(new_job, prev_block_hash, merkle_root, version_mask);
}

void extranonce_2_generate(uint64_t extranonce_2, uint32_t length, char dest[static length * 2 + 1])
{
    // Allocate buffer to hold the extranonce_2 value in bytes
    uint8_t extranonce_2_bytes[length];
    memset(extranonce_2_bytes, 0, length);
    
    // Copy the extranonce_2 value into the buffer, handling endianness
    // Copy up to the size of uint64_t or the requested length, whichever is smaller
    size_t copy_len = (length < sizeof(uint64_t)) ? length : sizeof(uint64_t);
    memcpy(extranonce_2_bytes, &extranonce_2, copy_len);
    
    // Convert the bytes to hex string
    bin2hex(extranonce_2_bytes, length, dest, length * 2 + 1);
}

double hash_to_pdiff(const uint8_t hash[32])
{
    double s64 = le256todouble(hash);
    if (s64 == 0.0) return (double)UINT32_MAX;
    return truediffone / s64;
}

// Recover the raw SHA-256 state words from a midstate stored in the job.
// Stored midstates are in BM job packet order: word-order-reversed,
// big-endian state words (see bm_job_compute_midstates / midstate_sha256_bin).
static void unpack_stored_midstate(const uint8_t stored[32], uint32_t state[8])
{
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = stored + 4 * (7 - i);
        state[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
}

// Look up the stored midstate matching rolled_version, if any. job->midstate
// always covers job->version; midstate1-3 cover the next rolled versions when
// the job was built with 4 midstates (BM1397 with version rolling).
static bool job_cached_midstate(const bm_job *job, const uint32_t rolled_version, uint32_t state[8])
{
    if (rolled_version == job->version) {
        unpack_stored_midstate(job->midstate, state);
        return true;
    }
    if (job->num_midstates == 4) {
        const uint8_t *extra_midstates[3] = {job->midstate1, job->midstate2, job->midstate3};
        uint32_t version = job->version;
        for (int i = 0; i < 3; i++) {
            version = increment_bitmask(version, job->version_mask);
            if (rolled_version == version) {
                unpack_stored_midstate(extra_midstates[i], state);
                return true;
            }
        }
    }
    return false;
}

///////cgminer nonce testing
/* testing a nonce and return the diff - 0 means invalid */
double test_nonce_value(const bm_job *job, const uint32_t nonce, const uint32_t rolled_version)
{
    // Resume the double SHA-256 of the 80-byte header from the midstate of
    // its first 64 bytes: reuse the midstate already computed for the job
    // when the version matches, otherwise recompute just that first block.
    uint32_t midstate[8];
    if (!job_cached_midstate(job, rolled_version, midstate)) {
        uint8_t block0[64];
        uint8_t merkle_root[32]; // header byte order
        memcpy(block0, &rolled_version, 4);
        reverse_32bit_words(job->prev_block_hash, block0 + 4);
        reverse_32bit_words(job->merkle_root, merkle_root);
        memcpy(block0 + 36, merkle_root, 28);
        sha256_midstate_words(block0, midstate);
    }

    // Header bytes 64-79: last merkle root word (== job->merkle_root[0..3],
    // since the stored merkle root is word-order-reversed), ntime, nbits, nonce.
    uint8_t tail[16];
    memcpy(tail, job->merkle_root, 4);
    memcpy(tail + 4, &job->ntime, 4);
    memcpy(tail + 8, &job->target, 4);
    memcpy(tail + 12, &nonce, 4);

    uint8_t hash_result[32];
    sha256d_80_from_midstate(midstate, tail, hash_result);

    return hash_to_pdiff(hash_result);
}

uint32_t increment_bitmask(const uint32_t value, const uint32_t mask)
{
    // Treat the masked bits as a counter and increment it in constant time:
    // setting every non-mask bit to 1 lets the +1 carry ripple across gaps in
    // a non-contiguous mask in a single add. Bits outside the mask are always
    // preserved, and the counter wraps around within the mask on overflow
    // (never leaking a carry into version bits the pool didn't negotiate).
    // With mask == 0 this reduces to the original value.
    return (((value | ~mask) + 1) & mask) | (value & ~mask);
}
