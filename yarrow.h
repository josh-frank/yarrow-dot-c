#ifndef YARROW_H
#define YARROW_H

/**
 * yarrow.h — Yarrow-256 CSPRNG
 *
 * A faithful-but-modernized C port of the Freenet Yarrow-160 implementation
 * by Scott G. Miller, originally based on Yarrow-160 by Kelsey, Schneier &
 * Ferguson (1999).
 *
 * Modernizations from the original:
 *   - SHA-1  → SHA-256       (via libsodium crypto_hash_sha256)
 *   - 3DES   → AES-256-CTR   (via libsodium crypto_stream_chacha20 for
 *                              the generation mechanism; AES key schedule
 *                              via crypto_aead_aes256gcm where HW-accelerated)
 *   - Java synchronized → pthread_mutex_t
 *   - Java MessageDigest state → libsodium streaming SHA-256 state
 *
 * Architecture (mirrors Freenet Yarrow exactly):
 *   5.1  Generation mechanism  — AES-CTR output, rekey every Pg=10 blocks
 *   5.2  Entropy accumulator   — fast pool + slow pool, SHA-256
 *   5.3  Reseed mechanism      — iterated hash chain (Pt=5 rounds)
 *   5.4  Reseed control        — FAST_THRESHOLD=100, SLOW_THRESHOLD=160, SLOW_K=2
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <sodium.h>

/* ── Reseed control parameters (§5.4) ─────────────────────────────────────── */
#define YARROW_FAST_THRESHOLD  100
#define YARROW_SLOW_THRESHOLD  160
#define YARROW_SLOW_K            2   /* min independent sources for slow reseed */
#define YARROW_Pg               10   /* rekey after this many output blocks      */
#define YARROW_Pt                5   /* hash iterations in reseed chain           */
#define YARROW_MAX_SOURCES      32   /* max tracked entropy sources               */

/* ── Sizes ─────────────────────────────────────────────────────────────────── */
#define YARROW_HASH_SIZE   crypto_hash_sha256_BYTES   /* 32 bytes */
#define YARROW_KEY_SIZE    32                          /* AES-256  */
#define YARROW_BLOCK_SIZE  16                          /* AES block */

/* ── Entropy source tracking ───────────────────────────────────────────────── */
typedef struct {
    int      id;
    int      contributed;   /* bits contributed to slow pool */
    int64_t  last_val;
    int      last_delta;
    int      last_delta2;
} yarrow_source_t;

/* ── Core Yarrow context ───────────────────────────────────────────────────── */
typedef struct {
    /* §5.1 Generation mechanism */
    uint8_t  key[YARROW_KEY_SIZE];
    uint8_t  counter[YARROW_BLOCK_SIZE];
    uint8_t  output_buf[YARROW_BLOCK_SIZE];
    int      output_count;    /* blocks since last rekey  */
    int      fetch_cursor;    /* bytes consumed from output_buf */

    /* §5.2 Entropy accumulator */
    crypto_hash_sha256_state fast_pool;
    crypto_hash_sha256_state slow_pool;
    int      fast_entropy;
    int      slow_entropy;
    bool     fast_select;     /* alternates which pool gets each input */

    /* §5.4 Source tracking for slow pool */
    yarrow_source_t sources[YARROW_MAX_SOURCES];
    int      source_count;

    /* Seed file */
    char     seedfile[256];
    bool     has_seedfile;

    pthread_mutex_t lock;
} yarrow_t;

/* ── Public API ────────────────────────────────────────────────────────────── */

/**
 * Initialize Yarrow. Reads seed from `seedfile` if not NULL.
 * Calls sodium_init() internally — safe to call multiple times.
 */
int  yarrow_init(yarrow_t *y, const char *seedfile);

/**
 * Register an entropy source. Returns a source id >= 0, or -1 on failure.
 * You must register before calling yarrow_accept_entropy().
 */
int  yarrow_register_source(yarrow_t *y);

/**
 * Feed entropy into the accumulator.
 * entropy_bits is your *estimate* of how many bits of real entropy `data`
 * carries — Yarrow will take the min of your guess and its own estimate.
 */
int  yarrow_accept_entropy(yarrow_t *y, int source_id,
                           int64_t data, int entropy_bits);

/** Convenience: feed current time delta as entropy (like acceptTimerEntropy) */
int  yarrow_accept_timer(yarrow_t *y, int source_id);

/** Fill buf with `len` cryptographically secure random bytes */
void yarrow_next_bytes(yarrow_t *y, uint8_t *buf, size_t len);

/** Return a random uint32 */
uint32_t yarrow_next_uint32(yarrow_t *y);

/** Return a random uint64 */
uint64_t yarrow_next_uint64(yarrow_t *y);

/** Persist seed to disk (rate-limited to once/hour unless force=true) */
void yarrow_write_seed(yarrow_t *y, bool force);

/** Seed from OS entropy sources (/dev/urandom, /dev/random, /dev/hwrng) */
void yarrow_seed_from_os(yarrow_t *y, bool can_block);

/** Clean up */
void yarrow_destroy(yarrow_t *y);

#endif /* YARROW_H */
