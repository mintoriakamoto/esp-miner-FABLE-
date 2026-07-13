#ifndef SHA256D_H_
#define SHA256D_H_

#include <stdint.h>

// Specialized software SHA-256 primitives for the fixed-size hashes on the
// mining hot paths (job generation and nonce checking). Unlike the generic
// streaming mbedTLS API these operate on whole blocks with no context
// setup, buffering or padding work per call, and exploit the fixed message
// layouts (constant padding blocks, known lengths) of each call site.

// SHA-256 compression of the first 64-byte block over the standard IV.
// state_out holds the raw hash state as host-endian words (the "midstate"
// fed to Bitmain ASICs and resumable via sha256d_80_from_midstate).
void sha256_midstate_words(const uint8_t block[64], uint32_t state_out[8]);

// Single SHA-256 of a 32-byte input — the second hash of a double-SHA.
void sha256_32(const uint8_t data[32], uint8_t dest[32]);

// SHA-256(SHA-256(data)) of a 64-byte input (one merkle-branch step).
// The final block of the first hash is all padding, so its message
// schedule is a precomputed constant.
void sha256d_64(const uint8_t data[64], uint8_t dest[32]);

// Finish SHA-256(SHA-256(header)) of an 80-byte block header given the
// midstate of its first 64 bytes (from sha256_midstate_words) and the last
// 16 header bytes: merkle-root tail, ntime, nbits, nonce.
void sha256d_80_from_midstate(const uint32_t midstate[8], const uint8_t tail[16], uint8_t dest[32]);

#endif /* SHA256D_H_ */
