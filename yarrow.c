/**
 * yarrow.c — Yarrow-256 CSPRNG implementation
 *
 * Faithful-but-modernized C port of Freenet's Yarrow-160 (Scott G. Miller).
 * See yarrow.h for full design notes.
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
static void generate_output(yarrow_t *y);
static int  estimate_entropy(yarrow_source_t *src, int64_t new_val);
static void consume_bytes(yarrow_t *y, const uint8_t *buf, size_t len);
static void read_seed_file(yarrow_t *y, const char *path);

/* ── §5.1 Generation mechanism ─────────────────────────────────────────────── */

/*
 * Increment the 128-bit counter (big-endian, matching original counterInc()).
 * We treat counter[15] as the least significant byte.
 */
static void counter_inc(yarrow_t *y) {
    for (int i = YARROW_BLOCK_SIZE - 1; i >= 0; i--) {
        if (++y->counter[i] != 0)
            break;
    }
}

/*
 * Encrypt the current counter value into output_buf using AES-256.
 * libsodium doesn't expose raw AES-ECB, but crypto_stream_chacha20_xor
 * with a zero-message gives us a keystream block — same security model.
 *
 * We use ChaCha20 here because:
 *   a) libsodium's AES-GCM requires hardware acceleration (not always present)
 *   b) ChaCha20 is equally strong and faster in software
 *   c) The Yarrow spec says "a block cipher" — ChaCha20 in counter mode qualifies
 *
 * If you need strict AES, swap this for OpenSSL's EVP_EncryptUpdate in ECB mode.
 */
/*
 * Internal unlocked version — called only when lock is already held.
 * Generates one block of output into y->output_buf.
 */
static void generate_output_unlocked(yarrow_t *y) {
    counter_inc(y);

    uint8_t zero_block[YARROW_BLOCK_SIZE] = {0};
    crypto_stream_chacha20_xor(
        y->output_buf,
        zero_block,
        YARROW_BLOCK_SIZE,
        y->counter,
        y->key
    );

    y->output_count++;

    /* §5.1 rekey every Pg blocks — derive new key directly from output buffer
       to provide forward secrecy, without recursive calls. */
    if (y->output_count >= YARROW_Pg) {
        y->output_count = 0;
        uint8_t new_key[YARROW_KEY_SIZE] = {0};

        /* Generate two more raw blocks to form the new 32-byte key */
        for (int k = 0; k < 2; k++) {
            counter_inc(y);
            uint8_t tmp_block[YARROW_BLOCK_SIZE] = {0};
            uint8_t raw[YARROW_BLOCK_SIZE];
            crypto_stream_chacha20_xor(raw, tmp_block, YARROW_BLOCK_SIZE,
                                       y->counter, y->key);
            memcpy(new_key + k * YARROW_BLOCK_SIZE, raw, YARROW_BLOCK_SIZE);
            sodium_memzero(raw, sizeof(raw));
        }
        rekey(y, new_key);
        sodium_memzero(new_key, sizeof(new_key));
        return; /* fresh state installed; caller will regenerate output */
    }
}

static void generate_output(yarrow_t *y) {
    generate_output_unlocked(y);
}

/*
 * Rekey the generator: install new_key, reset counter by encrypting
 * the all-zero string (mirrors Java's rekey() exactly).
 */
static void rekey(yarrow_t *y, const uint8_t *new_key) {
    memcpy(y->key, new_key, YARROW_KEY_SIZE);

    /* Reset counter = Encrypt(key, 0...0) */
    uint8_t zero[YARROW_BLOCK_SIZE] = {0};
    uint8_t zero_nonce[8] = {0};
    crypto_stream_chacha20_xor(
        y->counter,
        zero,
        YARROW_BLOCK_SIZE,
        zero_nonce,
        y->key
    );

    y->fetch_cursor = YARROW_BLOCK_SIZE; /* force fresh generate on next fetch */
}

/* ── §5.2 Entropy accumulator ───────────────────────────────────────────────── */

/*
 * Third-order delta entropy estimator — direct port of Freenet's
 * estimateEntropy(). Watches how quickly values change to bound
 * the real entropy conservatively.
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

    /* Take the minimum absolute delta across all three orders */
    if (delta > delta2) delta = delta2;
    if (delta > delta3) delta = delta3;

    /* Round down 1 bit on principle; cap at 12 bits */
    delta >>= 1;
    delta &= (1 << 12) - 1;

    /* Smear MSB right to build an n-bit mask */
    delta |= delta >> 8;
    delta |= delta >> 4;
    delta |= delta >> 2;
    delta |= delta >> 1;

    /* Remove one bit → logarithm */
    delta >>= 1;

    /* Popcount (Hamming weight) */
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
    if (y->fast_select) {
        crypto_hash_sha256_update(&y->fast_pool, buf, len);
    } else {
        crypto_hash_sha256_update(&y->slow_pool, buf, len);
    }
    y->fast_select = !y->fast_select;
}

/* ── §5.3 Reseed mechanism ──────────────────────────────────────────────────── */

/*
 * Fast pool reseed: iterated hash chain of Pt=5 rounds.
 * Direct port of Freenet's fast_pool_reseed().
 */
static void fast_pool_reseed(yarrow_t *y) {
    /* Snapshot the fast pool digest without destroying state */
    crypto_hash_sha256_state pool_copy = y->fast_pool;
    uint8_t v0[YARROW_HASH_SIZE];
    crypto_hash_sha256_final(&pool_copy, v0);

    /* Re-init pool for future entropy */
    crypto_hash_sha256_init(&y->fast_pool);

    uint8_t vi[YARROW_HASH_SIZE];
    memcpy(vi, v0, YARROW_HASH_SIZE);

    /* vPt = H(H(...H(v0 || v0 || 0) || v0 || 1)...) for Pt rounds */
    for (uint8_t i = 0; i < YARROW_Pt; i++) {
        crypto_hash_sha256_state round;
        crypto_hash_sha256_init(&round);
        crypto_hash_sha256_update(&round, vi, YARROW_HASH_SIZE);
        crypto_hash_sha256_update(&round, v0, YARROW_HASH_SIZE);
        crypto_hash_sha256_update(&round, &i, 1);
        crypto_hash_sha256_final(&round, vi);
    }

    /* vi is now vPt — use it as the new key (truncate/pad to key size) */
    rekey(y, vi);

    sodium_memzero(v0, sizeof(v0));
    sodium_memzero(vi, sizeof(vi));
    y->fast_entropy = 0;
}

/*
 * Slow pool reseed: fold slow pool hash into fast pool, then fast reseed.
 * Also resets per-source contribution counters.
 */
static void slow_pool_reseed(yarrow_t *y) {
    crypto_hash_sha256_state pool_copy = y->slow_pool;
    uint8_t slow_hash[YARROW_HASH_SIZE];
    crypto_hash_sha256_final(&pool_copy, slow_hash);

    /* Re-init slow pool */
    crypto_hash_sha256_init(&y->slow_pool);

    /* Fold slow hash into fast pool */
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

    /* Init both entropy pools */
    crypto_hash_sha256_init(&y->fast_pool);
    crypto_hash_sha256_init(&y->slow_pool);

    y->fast_select  = true;
    y->fetch_cursor = YARROW_BLOCK_SIZE; /* trigger generate on first use */

    /* Seed key and counter from libsodium's secure random */
    randombytes_buf(y->key,     YARROW_KEY_SIZE);
    randombytes_buf(y->counter, YARROW_BLOCK_SIZE);

    /* Record seedfile path */
    if (seedfile) {
        strncpy(y->seedfile, seedfile, sizeof(y->seedfile) - 1);
        y->has_seedfile = true;
        read_seed_file(y, seedfile);
    }

    /* Pull in OS entropy */
    yarrow_seed_from_os(y, false);

    /* Force initial reseed so startup entropy is mixed in */
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

    /* Feed data bytes into alternating pool */
    uint8_t buf[8];
    for (int i = 0; i < 8; i++)
        buf[i] = (uint8_t)(data >> (i * 8));

    y->fast_select = !y->fast_select;
    bool went_to_fast = y->fast_select;
    consume_bytes(y, buf, 8);

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
            /* Count sources that have contributed > SLOW_THRESHOLD bits */
            int qualifying = 0;
            for (int i = 0; i < y->source_count; i++) {
                if (y->sources[i].contributed > YARROW_SLOW_THRESHOLD)
                    qualifying++;
            }
            if (qualifying >= YARROW_SLOW_K) {
                slow_pool_reseed(y);
                did_reseed = true;
            }
        }
    }

    pthread_mutex_unlock(&y->lock);

    /* Write seed file outside lock (file I/O is slow, mirrors Freenet comment) */
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
            generate_output(y);
        }
        size_t available = YARROW_BLOCK_SIZE - y->fetch_cursor;
        size_t take      = (len - written < available) ? (len - written) : available;
        memcpy(buf + written, y->output_buf + y->fetch_cursor, take);
        y->fetch_cursor += (int)take;
        written         += take;
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

    /* Rate-limit to once per hour unless forced */
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

    /* /dev/hwrng if available */
    FILE *hwrng = fopen("/dev/hwrng", "rb");
    if (hwrng) {
        if (fread(buf, 1, sizeof(buf), hwrng) == sizeof(buf))
            consume_bytes(y, buf, sizeof(buf));
        if (fread(buf, 1, sizeof(buf), hwrng) == sizeof(buf))
            consume_bytes(y, buf, sizeof(buf));
        fclose(hwrng);
    }

    /* /dev/urandom — non-blocking, always try */
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        if (fread(buf, 1, sizeof(buf), urandom) == sizeof(buf))
            consume_bytes(y, buf, sizeof(buf));
        if (fread(buf, 1, sizeof(buf), urandom) == sizeof(buf))
            consume_bytes(y, buf, sizeof(buf));
        fclose(urandom);
    }

    /* /dev/random — use O_NONBLOCK so we never hang;
       on Linux since kernel 5.6 this is equivalent to /dev/urandom anyway */
    {
        int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) consume_bytes(y, buf, (size_t)n);
            close(fd);
        }
        (void)can_block; /* parameter kept for API compatibility */
    }

    /* libsodium's own CSPRNG as a fallback/supplement */
    randombytes_buf(buf, sizeof(buf));
    consume_bytes(y, buf, sizeof(buf));

    /* Timing jitter */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    consume_bytes(y, (uint8_t *)&ts, sizeof(ts));

    sodium_memzero(buf, sizeof(buf));
}

void yarrow_destroy(yarrow_t *y) {
    pthread_mutex_lock(&y->lock);
    sodium_memzero(y->key,        sizeof(y->key));
    sodium_memzero(y->counter,    sizeof(y->counter));
    sodium_memzero(y->output_buf, sizeof(y->output_buf));
    pthread_mutex_unlock(&y->lock);
    pthread_mutex_destroy(&y->lock);
    memset(y, 0, sizeof(*y));
}
