#include "sha256d.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// Fully expanded message schedule of the padding-only block that terminates
// the first hash of a 64-byte message (0x80, zeros, bit length 512). The
// message is constant, so the 48 schedule-expansion steps are precomputed.
static const uint32_t PAD64_W[64] = {
    0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000200, 0x80000000, 0x01400000,
    0x00205000, 0x00005088, 0x22000800, 0x22550014, 0x05089742, 0xa0000020,
    0x5a880000, 0x005c9400, 0x0016d49d, 0xfa801f00, 0xd33225d0, 0x11675959,
    0xf6e6bfda, 0xb30c1549, 0x08b2b050, 0x9d7c4c27, 0x0ce2a393, 0x88e6e1ea,
    0xa52b4335, 0x67a16f49, 0xd732016f, 0x4eeb2e91, 0x5dbf55e5, 0x8eee2335,
    0xe2bc5ec2, 0xa83f4394, 0x45ad78f7, 0x36f3d0cd, 0xd99c05e8, 0xb0511dc7,
    0x69bc7ac4, 0xbd11375b, 0xe3ba71e5, 0x3b209ff2, 0x18feee17, 0xe25ad9e7,
    0x13375046, 0x0515089d, 0x4f0d0f04, 0x2627484e, 0x310128d2, 0xc668b434,
    0x420841cc, 0x62d311b8, 0xe59ba771, 0x85a7a484,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

#define ROUND(a, b, c, d, e, f, g, h, k, w)              \
    do {                                                 \
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + k + w; \
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);           \
        d += t1;                                         \
        h = t1 + t2;                                     \
    } while (0)

static inline uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// One compression with schedule expansion. w[0..15] is the block in
// host-endian words and is clobbered by the in-place rolling expansion.
static void sha256_compress(uint32_t state[8], uint32_t w[16])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int t = 0; t < 64; t += 16) {
        if (t >= 16) {
            // In-place rolling expansion; must run in order because
            // w[t-2] can be a word produced earlier in this same group.
            for (int i = 0; i < 16; i++) {
                w[i] += SSIG0(w[(i + 1) & 15]) + w[(i + 9) & 15] + SSIG1(w[(i + 14) & 15]);
            }
        }
        ROUND(a, b, c, d, e, f, g, h, K[t + 0], w[0]);
        ROUND(h, a, b, c, d, e, f, g, K[t + 1], w[1]);
        ROUND(g, h, a, b, c, d, e, f, K[t + 2], w[2]);
        ROUND(f, g, h, a, b, c, d, e, K[t + 3], w[3]);
        ROUND(e, f, g, h, a, b, c, d, K[t + 4], w[4]);
        ROUND(d, e, f, g, h, a, b, c, K[t + 5], w[5]);
        ROUND(c, d, e, f, g, h, a, b, K[t + 6], w[6]);
        ROUND(b, c, d, e, f, g, h, a, K[t + 7], w[7]);
        ROUND(a, b, c, d, e, f, g, h, K[t + 8], w[8]);
        ROUND(h, a, b, c, d, e, f, g, K[t + 9], w[9]);
        ROUND(g, h, a, b, c, d, e, f, K[t + 10], w[10]);
        ROUND(f, g, h, a, b, c, d, e, K[t + 11], w[11]);
        ROUND(e, f, g, h, a, b, c, d, K[t + 12], w[12]);
        ROUND(d, e, f, g, h, a, b, c, K[t + 13], w[13]);
        ROUND(c, d, e, f, g, h, a, b, K[t + 14], w[14]);
        ROUND(b, c, d, e, f, g, h, a, K[t + 15], w[15]);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// One compression with a fully precomputed 64-word schedule (constant block).
static void sha256_compress_const(uint32_t state[8], const uint32_t w[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int t = 0; t < 64; t += 8) {
        ROUND(a, b, c, d, e, f, g, h, K[t + 0], w[t + 0]);
        ROUND(h, a, b, c, d, e, f, g, K[t + 1], w[t + 1]);
        ROUND(g, h, a, b, c, d, e, f, K[t + 2], w[t + 2]);
        ROUND(f, g, h, a, b, c, d, e, K[t + 3], w[t + 3]);
        ROUND(e, f, g, h, a, b, c, d, K[t + 4], w[t + 4]);
        ROUND(d, e, f, g, h, a, b, c, K[t + 5], w[t + 5]);
        ROUND(c, d, e, f, g, h, a, b, K[t + 6], w[t + 6]);
        ROUND(b, c, d, e, f, g, h, a, K[t + 7], w[t + 7]);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_midstate_words(const uint8_t block[64], uint32_t state_out[8])
{
    uint32_t w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = be32(block + 4 * i);
    }
    memcpy(state_out, IV, sizeof(IV));
    sha256_compress(state_out, w);
}

// Second hash of a double-SHA on raw state words: input is the 8 state
// words of the first hash, single block with fixed 32-byte-message padding.
static void sha256_32_words(const uint32_t in[8], uint32_t state_out[8])
{
    uint32_t w[16] = {
        in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7],
        0x80000000, 0, 0, 0, 0, 0, 0, 256,
    };
    memcpy(state_out, IV, sizeof(IV));
    sha256_compress(state_out, w);
}

void sha256_32(const uint8_t data[32], uint8_t dest[32])
{
    uint32_t in[8], out[8];
    for (int i = 0; i < 8; i++) {
        in[i] = be32(data + 4 * i);
    }
    sha256_32_words(in, out);
    for (int i = 0; i < 8; i++) {
        put_be32(dest + 4 * i, out[i]);
    }
}

void sha256d_64(const uint8_t data[64], uint8_t dest[32])
{
    uint32_t w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = be32(data + 4 * i);
    }

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));
    sha256_compress(state, w);
    sha256_compress_const(state, PAD64_W);

    uint32_t out[8];
    sha256_32_words(state, out);
    for (int i = 0; i < 8; i++) {
        put_be32(dest + 4 * i, out[i]);
    }
}

void sha256d_80_from_midstate(const uint32_t midstate[8], const uint8_t tail[16], uint8_t dest[32])
{
    // Final block of the first hash: last 16 header bytes plus fixed
    // padding for an 80-byte message.
    uint32_t w[16] = {
        be32(tail), be32(tail + 4), be32(tail + 8), be32(tail + 12),
        0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640,
    };

    uint32_t state[8];
    memcpy(state, midstate, 8 * sizeof(uint32_t));
    sha256_compress(state, w);

    uint32_t out[8];
    sha256_32_words(state, out);
    for (int i = 0; i < 8; i++) {
        put_be32(dest + 4 * i, out[i]);
    }
}
