/**
 * yarrow.c — Yarrow-256 CSPRNG implementation
 *
 * Faithful-but-modernized C port of Freenet's Yarrow-160 (Scott G. Miller).
 * See yarrow.h for full design notes.
 *
 * Nonce-counter fix (see yarrow.h for rationale):
 *   The original code stored both the ChaCha20 nonce and block-counter in a
 *   single 16-byte `counter[]` array, and reset it on every rekey.  This
 *   could produce (nonce, key) collisions at rekey boundaries.
 *
 *   This version keeps them separate:
 *     - y->nonce[8]       set once from OS entropy at init; never modified.
 *     - y->block_counter  uint64_t; incremented before every ChaCha20 call
 *                         and never reset, even across rekeys.
 *
 *   Every call to chacha20_block() is therefore:
 *     crypto_stream_chacha20_xor_ic(out, in, len, nonce, block_counter, key)
 *   guaranteeing a unique (nonce, IC) pair for every block ever produced.
 */

#include "yarrow.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

/* ── Internal forward declarations ─────────────────────────────────────────── */
static void fast_pool_reseed(yarrow_t *y);
static void slow_pool_reseed(yarrow_t *y);
static void rekey(yarrow_t *y, const uint8_t *new_key);
static void generate_output_unlocked(yarrow_t *y);
static int  estimate_entropy(yarrow_source_t *src, int64_t new_val);
static void consume_bytes(yarrow_t *y, const uint8_t *buf, size_t len);
static void read_seed_file(yarrow_t *y, const char *path);

/* ── §5.1 Generation mechanism ─────────────────────────────────────────────── */

/*
 * Emit one YARROW_BLOCK_SIZE-byte keystream block into y->output_buf.
 *
 * Key change from the original:
 *   Before: counter_inc() mutated an in-place 16-byte array that doubled as
 *           the nonce; it was zeroed on every rekey().
 *   After:  y->block_counter is incremented unconditionally and encoded into
 *           the `ic` (initial counter) argument of chacha20_xor_ic.  The
 *           8-byte y->nonce is never touched after init.
 *
 * crypto_stream_chacha20_xor_ic signature (libsodium):
 *   int crypto_stream_chacha20_xor_ic(
 *       unsigned char *c,          // ciphertext out
 *       const unsigned char *m,    // plaintext in  (zeros → pure keystream)
 *       unsigned long long mlen,
 *       const unsigned char *n,    // 8-byte nonce
 *       uint64_t ic,               // initial block counter (little-endian)
 *       const unsigned char *k);   // 32-byte key
 */
static void generate_output_unlocked(yarrow_t *y) {
    /* Advance the block counter before use — never reuse a position. */
    y->block_counter++;

    uint8_t zero_block[YARROW_BLOCK_SIZE] = {0};
    crypto_stream_chacha20_xor_ic(
        y->output_buf,
        zero_block,
        YARROW_BLOCK_SIZE,
        y->nonce,
        y->block_counter,
        y->key
    );

    y->output_count++;

    /* §5.1  Rekey every Pg blocks for forward secrecy. */
    if (y->output_count >= YARROW_Pg) {
        y->output_count = 0;

        /* Derive a new 32-byte key from the next two keystream blocks.
         * Each block is YARROW_BLOCK_SIZE (64) bytes; we take the first
         * 16 bytes of each to fill the 32-byte key.                      */
        uint8_t new_key[YARROW_KEY_SIZE] = {0};

        for (int k = 0; k < 2; k++) {
            y->block_counter++;
            uint8_t tmp_in[YARROW_KEY_SIZE / 2]  = {0};
            uint8_t raw   [YARROW_KEY_SIZE / 2];
            crypto_stream_chacha20_xor_ic(
                raw,
                tmp_in,
                YARROW_KEY_SIZE / 2,
                y->nonce,
                y->block_counter,
                y->key
            );
            memcpy(new_key + k * (YARROW_KEY_SIZE / 2), raw, YARROW_KEY_SIZE / 2);
            sodium_memzero(raw, sizeof(raw));
        }

        rekey(y, new_key);
        sodium_memzero(new_key, sizeof(new_key));
        /* Note: rekey() does NOT reset block_counter — that is the whole fix.
         * The caller re-invokes generate_output_unlocked() on next fetch.   */
    }
}

/*
 * Install a new key.
 *
 * Key change from the original:
 *   The old rekey() reset the counter to Encrypt(key, 0...0) which
 *   re-derived nonce bytes from the key, enabling collisions.
 *
 *   The new rekey() only updates y->key and marks output_buf stale.
 *   y->nonce and y->block_counter are deliberately left untouched.
 */
static void rekey(yarrow_t *y, const uint8_t *new_key) {
    memcpy(y->key, new_key, YARROW_KEY_SIZE);
    /* Invalidate the output buffer so the next fetch triggers a fresh block. */
    y->fetch_cursor = YARROW_BLOCK_SIZE;
}

/* ── §5.2 Entropy accumulator ───────────────────────────────────────────────── */

/*
 * Third-order delta entropy estimator — direct port of Freenet's
 * estimateEntropy().  Unchanged from the original.
 */
static int estimate_entropy(yarrow_source_t *src, int64_t new_val) {
    int delta  = (int)(new_val - src->last_val);
    int delta2 = delta - src->last_delta;
    src->last_delta = delta;
    int delta3 = delta2 - src->last_delta2;
    src->last_delta2 = delta2;

    if (delta  < 0) delta  = -delta;
    if (delta2 < 0) delta2 = -delta2;
    if (delta3 < 0) delta3 = -delta3;

    if (delta > delta2) delta = delta2;
    if (delta > delta3) delta = delta3;

    delta >>= 1;
    delta  &= (1 << 12) - 1;

    delta |= delta >> 8;
    delta |= delta >> 4;
    delta |= delta >> 2;
    delta |= delta >> 1;
    delta >>= 1;

    delta -= (delta >> 1) & 0x555;
    delta  = (delta & 0x333) + ((delta >> 2) & 0x333);
    delta += (delta >> 4);
    delta += (delta >> 8);

    src->last_val = new_val;
    return delta & 15;
}

/*
 * Feed raw bytes into whichever pool is currently selected.
 * Alternates fast/slow on each call (mirrors Java's consumeBytes).
 */
static void consume_bytes(yarrow_t *y, const uint8_t *buf, size_t len) {
    if (y->fast_select)
        crypto_hash_sha256_update(&y->fast_pool, buf, len);
    else
        crypto_hash_sha256_update(&y->slow_pool, buf, len);
    y->fast_select = !y->fast_select;
}

/* ── §5.3 Reseed mechanism ──────────────────────────────────────────────────── */

static void fast_pool_reseed(yarrow_t *y) {
    crypto_hash_sha256_state pool_copy = y->fast_pool;
    uint8_t v0[YARROW_HASH_SIZE];
    crypto_hash_sha256_final(&pool_copy, v0);

    crypto_hash_sha256_init(&y->fast_pool);

    uint8_t vi[YARROW_HASH_SIZE];
    memcpy(vi, v0, YARROW_HASH_SIZE);

    for (uint8_t i = 0; i < YARROW_Pt; i++) {
        crypto_hash_sha256_state round;
        crypto_hash_sha256_init(&round);
        crypto_hash_sha256_update(&round, vi, YARROW_HASH_SIZE);
        crypto_hash_sha256_update(&round, v0, YARROW_HASH_SIZE);
        crypto_hash_sha256_update(&round, &i,  1);
        crypto_hash_sha256_final(&round, vi);
    }

    rekey(y, vi);   /* installs vi as new key; block_counter keeps counting */
    sodium_memzero(v0, sizeof(v0));
    sodium_memzero(vi, sizeof(vi));
    y->fast_entropy = 0;
}

static void slow_pool_reseed(yarrow_t *y) {
    crypto_hash_sha256_state pool_copy = y->slow_pool;
    uint8_t slow_hash[YARROW_HASH_SIZE];
    crypto_hash_sha256_final(&pool_copy, slow_hash);

    crypto_hash_sha256_init(&y->slow_pool);
    crypto_hash_sha256_update(&y->fast_pool, slow_hash, YARROW_HASH_SIZE);
    sodium_memzero(slow_hash, sizeof(slow_hash));

    fast_pool_reseed(y);

    y->slow_entropy = 0;
    for (int i = 0; i < y->source_count; i++)
        y->sources[i].contributed = 0;
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

int yarrow_init(yarrow_t *y, const char *seedfile) {
    if (sodium_init() < 0)
        return -1;

    memset(y, 0, sizeof(*y));
    pthread_mutex_init(&y->lock, NULL);

    crypto_hash_sha256_init(&y->fast_pool);
    crypto_hash_sha256_init(&y->slow_pool);
    y->fast_select = true;
    y->fetch_cursor = YARROW_BLOCK_SIZE;  /* trigger generate on first use */

    /* Key: random 32 bytes. */
    randombytes_buf(y->key, YARROW_KEY_SIZE);

    /*
     * Nonce: random 8 bytes, set once here, NEVER changed again.
     * This is the heart of the fix: a stable, unique nonce per yarrow_t
     * instance means that the monotonically-increasing block_counter is
     * the sole source of position uniqueness.
     */
    randombytes_buf(y->nonce, YARROW_NONCE_SIZE);

    /*
     * block_counter: start at 0.  The first generate_output_unlocked() call
     * will increment it to 1 before any keystream bytes are produced, so
     * position 0 is never used (matches standard practice of 1-based IC).
     */
    y->block_counter = 0;

    if (seedfile) {
        strncpy(y->seedfile, seedfile, sizeof(y->seedfile) - 1);
        y->has_seedfile = true;
        read_seed_file(y, seedfile);
    }

    yarrow_seed_from_os(y, false);

    pthread_mutex_lock(&y->lock);
    fast_pool_reseed(y);
    slow_pool_reseed(y);
    pthread_mutex_unlock(&y->lock);

    return 0;
}

int yarrow_register_source(yarrow_t *y) {
    pthread_mutex_lock(&y->lock);
    if (y->source_count >= YARROW_MAX_SOURCES) {
        pthread_mutex_unlock(&y->lock);
        return -1;
    }
    int id = y->source_count++;
    memset(&y->sources[id], 0, sizeof(yarrow_source_t));
    y->sources[id].id = id;
    pthread_mutex_unlock(&y->lock);
    return id;
}

int yarrow_accept_entropy(yarrow_t *y, int source_id,
                          int64_t data, int entropy_bits) {
    if (source_id < 0 || source_id >= y->source_count)
        return 0;

    pthread_mutex_lock(&y->lock);

    yarrow_source_t *src = &y->sources[source_id];
    int estimated = estimate_entropy(src, data);
    int actual    = (entropy_bits < estimated ? entropy_bits : estimated);
    if (actual > 32) actual = 32;

    uint8_t buf[8];
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)(data >> (i * 8));

    // Remove the manual toggle. Just peek at fast_select before the call.
    bool went_to_fast = y->fast_select; // fast_select is true → next consume goes to fast pool
    consume_bytes(y, buf, 8);           // consume_bytes routes, then flips fast_select

    bool did_reseed = false;

    if (went_to_fast) {
        y->fast_entropy += actual;
        if (y->fast_entropy >= YARROW_FAST_THRESHOLD) {
            fast_pool_reseed(y);
            did_reseed = true;
        }
    } else {
        y->slow_entropy += actual;
        src->contributed += actual;
        if (y->slow_entropy >= YARROW_SLOW_THRESHOLD * 2) {
            int qualifying = 0;
            for (int i = 0; i < y->source_count; i++)
                if (y->sources[i].contributed > YARROW_SLOW_THRESHOLD)
                    qualifying++;
            if (qualifying >= YARROW_SLOW_K) {
                slow_pool_reseed(y);
                did_reseed = true;
            }
        }
    }

    pthread_mutex_unlock(&y->lock);

    if (did_reseed && y->has_seedfile)
        yarrow_write_seed(y, false);

    return actual;
}

int yarrow_accept_timer(yarrow_t *y, int source_id) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    return yarrow_accept_entropy(y, source_id, now, 32);
}

void yarrow_next_bytes(yarrow_t *y, uint8_t *buf, size_t len) {
    pthread_mutex_lock(&y->lock);

    size_t written = 0;
    while (written < len) {
        if (y->fetch_cursor >= YARROW_BLOCK_SIZE) {
            y->fetch_cursor = 0;
            generate_output_unlocked(y);
        }
        size_t available = YARROW_BLOCK_SIZE - y->fetch_cursor;
        size_t take = (len - written < available) ? (len - written) : available;
        memcpy(buf + written, y->output_buf + y->fetch_cursor, take);
        y->fetch_cursor += (int)take;
        written += take;
    }

    pthread_mutex_unlock(&y->lock);
}

uint32_t yarrow_next_uint32(yarrow_t *y) {
    uint32_t v;
    yarrow_next_bytes(y, (uint8_t *)&v, sizeof(v));
    return v;
}

uint64_t yarrow_next_uint64(yarrow_t *y) {
    uint64_t v;
    yarrow_next_bytes(y, (uint8_t *)&v, sizeof(v));
    return v;
}

/* ── Seed file I/O ──────────────────────────────────────────────────────────── */

static void read_seed_file(yarrow_t *y, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;

    int src = yarrow_register_source(y);
    if (src < 0) { fclose(f); return; }

    uint64_t val;
    for (int i = 0; i < 32; i++) {
        if (fread(&val, sizeof(val), 1, f) != 1) break;
        yarrow_accept_entropy(y, src, (int64_t)val, 64);
    }
    fclose(f);

    pthread_mutex_lock(&y->lock);
    fast_pool_reseed(y);
    pthread_mutex_unlock(&y->lock);
}

void yarrow_write_seed(yarrow_t *y, bool force) {
    if (!y->has_seedfile) return;

    static time_t last_write = 0;
    time_t now = time(NULL);
    if (!force && (now - last_write) < 3600) return;
    last_write = now;

    FILE *f = fopen(y->seedfile, "wb");
    if (!f) return;

    for (int i = 0; i < 32; i++) {
        uint64_t v = yarrow_next_uint64(y);
        fwrite(&v, sizeof(v), 1, f);
    }
    fclose(f);
}

/* ── OS entropy sourcing ────────────────────────────────────────────────────── */

void yarrow_seed_from_os(yarrow_t *y, bool can_block) {
    uint8_t buf[32];

    FILE *hwrng = fopen("/dev/hwrng", "rb");
    if (hwrng) {
        if (fread(buf, 1, sizeof(buf), hwrng) == sizeof(buf)) consume_bytes(y, buf, sizeof(buf));
        if (fread(buf, 1, sizeof(buf), hwrng) == sizeof(buf)) consume_bytes(y, buf, sizeof(buf));
        fclose(hwrng);
    }

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        if (fread(buf, 1, sizeof(buf), urandom) == sizeof(buf)) consume_bytes(y, buf, sizeof(buf));
        if (fread(buf, 1, sizeof(buf), urandom) == sizeof(buf)) consume_bytes(y, buf, sizeof(buf));
        fclose(urandom);
    }

    {
        int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) consume_bytes(y, buf, (size_t)n);
            close(fd);
        }
        (void)can_block;
    }

    randombytes_buf(buf, sizeof(buf));
    consume_bytes(y, buf, sizeof(buf));

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    consume_bytes(y, (uint8_t *)&ts, sizeof(ts));

    sodium_memzero(buf, sizeof(buf));
}

void yarrow_destroy(yarrow_t *y) {
    pthread_mutex_lock(&y->lock);
    sodium_memzero(y->key,        sizeof(y->key));
    sodium_memzero(y->nonce,      sizeof(y->nonce));
    sodium_memzero(y->output_buf, sizeof(y->output_buf));
    y->block_counter = 0;
    pthread_mutex_unlock(&y->lock);
    pthread_mutex_destroy(&y->lock);
    memset(y, 0, sizeof(*y));
}
