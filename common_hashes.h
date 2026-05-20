#ifndef COMMON_HASHES_H
#define COMMON_HASHES_H

/**
 * common_hashes.h — High-level inline façade over the Yarrow-256 CSPRNG
 *
 * All functions are inline — no separate compilation unit required.
 * Just #include "common_hashes.h" alongside yarrow.h.
 *
 * Dependencies: yarrow.h, libsodium (sodium.h), standard C99 headers.
 *
 * Sections:
 *   1. Web / token         — hex, base64url, UUID v4
 *   2. Cryptographic       — keys, nonces, salts, OTP
 *   3. Numeric / general   — unbiased range, double, shuffle
 */

#include "yarrow.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sodium.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * §1  Web / token helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * yarrow_random_hex
 *
 * Fill `out` with a lowercase hex string representing `bytes` random bytes.
 * Output length: 2*bytes + 1 (null-terminated).
 *
 * Typical use: session tokens, CSRF tokens, API keys.
 *
 *   char token[65];
 *   yarrow_random_hex(&y, token, 32);   // 256-bit token
 */
static inline void yarrow_random_hex(yarrow_t *y, char *out, size_t bytes) {
    uint8_t buf[bytes];
    yarrow_next_bytes(y, buf, bytes);
    /* sodium_bin2hex always null-terminates */
    sodium_bin2hex(out, bytes * 2 + 1, buf, bytes);
    sodium_memzero(buf, bytes);
}

/**
 * yarrow_random_base64url
 *
 * Fill `out` with a URL-safe base64 (no padding) string of `bytes` random bytes.
 * Output length: sodium_base64_ENCODED_LEN(bytes, sodium_base64_VARIANT_URLSAFE_NO_PADDING).
 *
 * Use SODIUM_BASE64_ENCODED_LEN(bytes, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
 * to size your buffer at compile time.
 *
 * Typical use: OAuth state params, JWT jti, short-lived link tokens.
 *
 *   char token[SODIUM_BASE64_ENCODED_LEN(32, sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
 *   yarrow_random_base64url(&y, token, 32);
 */
static inline void yarrow_random_base64url(yarrow_t *y, char *out, size_t bytes) {
    uint8_t buf[bytes];
    yarrow_next_bytes(y, buf, bytes);
    sodium_bin2base64(out,
                      sodium_base64_ENCODED_LEN(bytes,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING),
                      buf, bytes,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    sodium_memzero(buf, bytes);
}

/**
 * yarrow_random_uuid4
 *
 * Write a RFC 4122 UUID v4 string into `out` (37 bytes including null terminator).
 * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 *         where y is one of 8, 9, a, b (variant 1).
 *
 * Typical use: database primary keys, idempotency keys, resource identifiers.
 *
 *   char uuid[37];
 *   yarrow_random_uuid4(&y, uuid);
 */
static inline void yarrow_random_uuid4(yarrow_t *y, char *out) {
    uint8_t b[16];
    yarrow_next_bytes(y, b, 16);

    /* Set version bits: version 4 */
    b[6] = (b[6] & 0x0f) | 0x40;
    /* Set variant bits: variant 1 (10xx) */
    b[8] = (b[8] & 0x3f) | 0x80;

    snprintf(out, 37,
        "%02x%02x%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x%02x%02x%02x%02x",
        b[0],  b[1],  b[2],  b[3],
        b[4],  b[5],
        b[6],  b[7],
        b[8],  b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §2  Cryptographic helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * yarrow_random_key
 *
 * Fill `key` with `len` bytes of key material.
 * Named explicitly so audit trails and grep results are unambiguous.
 *
 * Typical use: AES-256 key (32 bytes), ChaCha20 key (32 bytes),
 *              HMAC-SHA-256 key (32 bytes).
 *
 *   uint8_t aes_key[32];
 *   yarrow_random_key(&y, aes_key, sizeof(aes_key));
 */
static inline void yarrow_random_key(yarrow_t *y, uint8_t *key, size_t len) {
    yarrow_next_bytes(y, key, len);
}

/**
 * yarrow_random_nonce
 *
 * Fill `nonce` with `len` bytes suitable for use as a cipher nonce / IV.
 * Named separately from yarrow_random_key so intent is clear in code review.
 *
 * Common sizes: 8 bytes (ChaCha20/original), 12 bytes (ChaCha20-IETF / AES-GCM),
 *               16 bytes (AES-CBC IV).
 *
 *   uint8_t nonce[12];
 *   yarrow_random_nonce(&y, nonce, sizeof(nonce));
 */
static inline void yarrow_random_nonce(yarrow_t *y, uint8_t *nonce, size_t len) {
    yarrow_next_bytes(y, nonce, len);
}

/**
 * yarrow_random_salt
 *
 * Fill `salt` with `len` bytes suitable for password hashing.
 * Named separately for the same audit-trail reason as above.
 *
 * Common sizes: 16 bytes (bcrypt), 16 bytes (Argon2), 32 bytes (scrypt).
 *
 *   uint8_t salt[crypto_pwhash_SALTBYTES];
 *   yarrow_random_salt(&y, salt, sizeof(salt));
 */
static inline void yarrow_random_salt(yarrow_t *y, uint8_t *salt, size_t len) {
    yarrow_next_bytes(y, salt, len);
}

/**
 * yarrow_random_bytes_ct
 *
 * Constant-time fill: identical to yarrow_next_bytes() but named explicitly
 * for contexts where the name matters for readability or auditing (e.g.
 * filling a blinding factor or masking value in a side-channel-sensitive path).
 *
 *   uint8_t mask[32];
 *   yarrow_random_bytes_ct(&y, mask, sizeof(mask));
 */
static inline void yarrow_random_bytes_ct(yarrow_t *y, uint8_t *buf, size_t len) {
    yarrow_next_bytes(y, buf, len);
}

/**
 * yarrow_otp_t
 *
 * Handle returned by yarrow_otp_create().
 * Treat this as opaque — access via the provided functions only.
 *
 * Memory layout: [size: 8 bytes][pad bytes: size bytes]
 * The pad is locked in memory with sodium_mlock() to prevent it being
 * swapped to disk, and zeroed with sodium_memzero() on free.
 */
typedef struct {
    uint8_t *pad;    /* the random key material                   */
    size_t   size;   /* length of the pad in bytes                */
} yarrow_otp_t;

/**
 * yarrow_otp_create
 *
 * Allocate and fill a one-time pad of `size_in_bytes` bytes.
 *
 * The returned pad is:
 *   - Filled with cryptographically secure random bytes from Yarrow.
 *   - Locked in memory (sodium_mlock) — the OS will not swap it to disk.
 *   - Zeroed automatically when freed via yarrow_otp_free().
 *
 * Returns a yarrow_otp_t with pad == NULL on allocation failure.
 * Caller MUST call yarrow_otp_free() when done.
 *
 *   yarrow_otp_t otp = yarrow_otp_create(&y, 1024);
 *   if (!otp.pad) { ... handle error ... }
 *   // XOR otp.pad[i] ^ plaintext[i] to encrypt / decrypt
 *   yarrow_otp_free(&otp);
 */
static inline yarrow_otp_t yarrow_otp_create(yarrow_t *y, size_t size_in_bytes) {
    yarrow_otp_t otp = { .pad = NULL, .size = 0 };

    uint8_t *pad = (uint8_t *)sodium_malloc(size_in_bytes);
    if (!pad)
        return otp;

    /* sodium_malloc() pages are already mlock'd and guard-page protected. */
    yarrow_next_bytes(y, pad, size_in_bytes);

    otp.pad  = pad;
    otp.size = size_in_bytes;
    return otp;
}

/**
 * yarrow_otp_encrypt / yarrow_otp_decrypt
 *
 * XOR `len` bytes of `in` with the OTP starting at byte `offset`, writing
 * the result into `out`.  Encryption and decryption are the same operation.
 *
 * Asserts (via return value) that the requested range fits within the pad.
 * Returns 0 on success, -1 if offset + len > otp->size (range overflow).
 *
 * `in` and `out` may alias (in-place XOR is safe).
 *
 *   // encrypt
 *   yarrow_otp_encrypt(&otp, plaintext, ciphertext, 0, message_len);
 *   // decrypt (identical call)
 *   yarrow_otp_encrypt(&otp, ciphertext, plaintext, 0, message_len);
 */
static inline int yarrow_otp_encrypt(const yarrow_otp_t *otp,
                                     const uint8_t *in,
                                     uint8_t       *out,
                                     size_t         offset,
                                     size_t         len) {
    if (offset + len > otp->size)
        return -1;
    const uint8_t *key = otp->pad + offset;
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key[i];
    return 0;
}
#define yarrow_otp_decrypt yarrow_otp_encrypt   /* same operation */

/**
 * yarrow_otp_free
 *
 * Zero and free the one-time pad.
 * sodium_free() zeroes and munlocks the memory before releasing it.
 * Sets otp->pad = NULL and otp->size = 0 to prevent double-free.
 */
static inline void yarrow_otp_free(yarrow_otp_t *otp) {
    if (otp->pad) {
        sodium_free(otp->pad);   /* zeroes, munlocks, and frees */
        otp->pad  = NULL;
        otp->size = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * §3  Numeric / general helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * yarrow_random_range
 *
 * Return a uniformly distributed uint64_t in [min, max).
 * Uses rejection sampling to eliminate modulo bias — the standard
 * "bitmask + reject" technique (Daniel Lemire, 2018).
 *
 * Precondition: max > min.
 *
 *   uint64_t roll = yarrow_random_range(&y, 1, 7);   // fair d6
 */
static inline uint64_t yarrow_random_range(yarrow_t *y,
                                           uint64_t  min,
                                           uint64_t  max) {
    uint64_t range = max - min;
    /* Largest multiple of range that fits in uint64_t */
    uint64_t limit = -range % range;   /* equiv: (2^64 - range) % range */
    uint64_t v;
    do { v = yarrow_next_uint64(y); } while (v < limit);
    return min + (v % range);
}

/**
 * yarrow_random_double
 *
 * Return a uniform double in [0.0, 1.0).
 * Uses 53 random bits (the mantissa width of IEEE 754 double) to give
 * the maximum possible resolution without bias.
 *
 *   double p = yarrow_random_double(&y);
 */
static inline double yarrow_random_double(yarrow_t *y) {
    /* 53-bit integer → double in [0, 2^53) → divide → [0.0, 1.0) */
    uint64_t v = yarrow_next_uint64(y) >> 11;   /* keep top 53 bits */
    return (double)v / (double)(UINT64_C(1) << 53);
}

/**
 * yarrow_shuffle
 *
 * In-place Fisher-Yates shuffle of an array of `n` elements, each
 * `elem_size` bytes wide.  Uses yarrow_random_range() for unbiased picks.
 *
 * Works on any element type: pass sizeof(your_type) as elem_size.
 *
 *   int deck[52]; // ... fill ...
 *   yarrow_shuffle(&y, deck, 52, sizeof(int));
 */
static inline void yarrow_shuffle(yarrow_t *y,
                                  void     *arr,
                                  size_t    n,
                                  size_t    elem_size) {
    if (n < 2) return;
    uint8_t *base = (uint8_t *)arr;
    uint8_t  tmp[elem_size];
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)yarrow_random_range(y, 0, (uint64_t)(i + 1));
        /* swap base[i] and base[j] */
        memcpy(tmp,              base + i * elem_size, elem_size);
        memcpy(base + i * elem_size, base + j * elem_size, elem_size);
        memcpy(base + j * elem_size, tmp,              elem_size);
    }
}

#endif /* COMMON_HASHES_H */
