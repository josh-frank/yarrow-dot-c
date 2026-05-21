/**
 * yarrow_test.c — test & demo for the Yarrow-256 CSPRNG
 *
 * Mirrors the test modes from the original Freenet Yarrow main():
 *   latency    — benchmark bytes/ms, uint32, uint64
 *   randomness — dump N KB of raw bytes to stdout (pipe to dieharder etc.)
 *   sample     — print sample outputs
 *   entropy    — demonstrate entropy accumulation and reseed triggering
 *
 * New mode (common_hashes.h demo):
 *   hashes     — exercise every function in common_hashes.h with visible output
 *
 * Build:
 *   gcc -O2 -o yarrow_test yarrow.c yarrow_test.c -lsodium -lpthread
 *
 * Run:
 *   ./yarrow_test             # runs all modes except randomness and hashes
 *   ./yarrow_test hashes      # common_hashes.h demo
 *   ./yarrow_test latency
 *   ./yarrow_test sample
 *   ./yarrow_test entropy
 *   ./yarrow_test randomness 1024 | dieharder -a -g 200
 */

#include "yarrow.h"
#include "common_hashes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Timing helper ──────────────────────────────────────────────────────────── */

static double ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* ── Latency benchmark ──────────────────────────────────────────────────────── */

static void bench_latency(yarrow_t *y) {
    const int ITERS  = 1000;
    const int BUF_KB = 1;
    uint8_t buf[1024 * BUF_KB];

    printf("=== Latency Benchmark ===\n");

    double t0 = ms_now();
    for (int i = 0; i < ITERS; i++)
        yarrow_next_bytes(y, buf, sizeof(buf));
    double elapsed = ms_now() - t0;
    printf("  nextBytes(%d KB): %.4f ms/KB  (%.2f MB/s)\n",
           BUF_KB, elapsed / ITERS, (ITERS * BUF_KB) / elapsed);

    t0 = ms_now();
    for (int i = 0; i < ITERS * 100; i++)
        (void)yarrow_next_uint32(y);
    elapsed = ms_now() - t0;
    printf("  nextUint32():     %.6f ms/call\n", elapsed / (ITERS * 100));

    t0 = ms_now();
    for (int i = 0; i < ITERS * 100; i++)
        (void)yarrow_next_uint64(y);
    elapsed = ms_now() - t0;
    printf("  nextUint64():     %.6f ms/call\n", elapsed / (ITERS * 100));
}

/* ── Sample output ──────────────────────────────────────────────────────────── */

static void show_samples(yarrow_t *y) {
    printf("=== Sample Output ===\n");

    printf("  nextUint32():  ");
    for (int i = 0; i < 5; i++)
        printf("%10u ", yarrow_next_uint32(y));
    printf("\n");

    printf("  nextUint64():  ");
    for (int i = 0; i < 3; i++)
        printf("%20llu ", (unsigned long long)yarrow_next_uint64(y));
    printf("\n");

    printf("  16 raw bytes:  ");
    uint8_t blob[16];
    yarrow_next_bytes(y, blob, sizeof(blob));
    for (int i = 0; i < 16; i++) printf("%02x", blob[i]);
    printf("\n");
}

/* ── Entropy demo ───────────────────────────────────────────────────────────── */

static void demo_entropy(yarrow_t *y) {
    printf("=== Entropy Accumulation Demo ===\n");

    int src_a = yarrow_register_source(y);
    int src_b = yarrow_register_source(y);
    printf("  Registered sources: %d, %d\n", src_a, src_b);

    int total_a = 0, total_b = 0;

    printf("  Feeding 200 timer ticks into source A...\n");
    for (int i = 0; i < 200; i++) {
        total_a += yarrow_accept_timer(y, src_a);
        struct timespec s = {0, 100000};
        nanosleep(&s, NULL);
    }
    printf("  Total entropy credited to A: ~%d bits\n", total_a);

    printf("  Feeding 200 timer ticks into source B...\n");
    for (int i = 0; i < 200; i++) {
        total_b += yarrow_accept_timer(y, src_b);
        struct timespec s = {0, 100000};
        nanosleep(&s, NULL);
    }
    printf("  Total entropy credited to B: ~%d bits\n", total_b);

    printf("  (Slow pool reseed triggered when %d independent sources each\n",
           YARROW_SLOW_K);
    printf("   exceed %d bits — mirrors Freenet's SLOW_K=2 logic)\n",
           YARROW_SLOW_THRESHOLD);

    printf("  Post-reseed sample: ");
    for (int i = 0; i < 4; i++)
        printf("%08x ", yarrow_next_uint32(y));
    printf("\n");
}

/* ── Raw randomness dump (pipe to dieharder or ent) ────────────────────────── */

static void dump_randomness(yarrow_t *y, int kb) {
    uint8_t buf[1024];
    for (int i = 0; i < kb; i++) {
        yarrow_next_bytes(y, buf, sizeof(buf));
        fwrite(buf, 1, sizeof(buf), stdout);
    }
}

/* ── common_hashes.h demo ───────────────────────────────────────────────────── */

static void demo_hashes(yarrow_t *y) {
    printf("=== common_hashes.h Demo ===\n\n");

    /* ── §1  Web / token ──────────────────────────────────────────────────── */
    printf("-- §1  Web / Token --\n");

    /* Hex tokens */
    char hex32[65], hex16[33];
    yarrow_random_hex(y, hex32, 32);
    yarrow_random_hex(y, hex16, 16);
    printf("  yarrow_random_hex(32):  %s\n", hex32);
    printf("  yarrow_random_hex(16):  %s\n", hex16);

    char b64_32[64]; /* ceil(32/3)*4 + 1 = 44, 64 is plenty */
    char b64_24[48]; /* ceil(24/3)*4 + 1 = 33, 48 is plenty */
    yarrow_random_base64url(y, b64_32, 32);
    yarrow_random_base64url(y, b64_24, 24);
    printf("  yarrow_random_base64url(32): %s\n", b64_32);
    printf("  yarrow_random_base64url(24): %s\n", b64_24);

    /* UUID v4 — generate three to show format consistency */
    char uuid[37];
    printf("  yarrow_random_uuid4():\n");
    for (int i = 0; i < 3; i++) {
        yarrow_random_uuid4(y, uuid);
        printf("    [%d] %s\n", i + 1, uuid);
    }

    /* Verify the version and variant nibbles */
    yarrow_random_uuid4(y, uuid);
    char version_nibble = uuid[14]; /* always '4' */
    char variant_nibble = uuid[19]; /* always '8','9','a','b' */
    printf("  UUID v4 structure check: version='%c' (want '4'), "
           "variant='%c' (want 8/9/a/b)\n",
           version_nibble, variant_nibble);

    printf("\n");

    /* ── §2  Cryptographic ────────────────────────────────────────────────── */
    printf("-- §2  Cryptographic --\n");

    /* Key material */
    uint8_t aes_key[32], hmac_key[32];
    yarrow_random_key(y, aes_key,  sizeof(aes_key));
    yarrow_random_key(y, hmac_key, sizeof(hmac_key));
    printf("  yarrow_random_key(32) [AES-256]:    ");
    for (int i = 0; i < 32; i++) printf("%02x", aes_key[i]);
    printf("\n");
    printf("  yarrow_random_key(32) [HMAC-SHA256]: ");
    for (int i = 0; i < 32; i++) printf("%02x", hmac_key[i]);
    printf("\n");

    /* Nonces */
    uint8_t nonce8[8], nonce12[12];
    yarrow_random_nonce(y, nonce8,  sizeof(nonce8));
    yarrow_random_nonce(y, nonce12, sizeof(nonce12));
    printf("  yarrow_random_nonce(8)  [ChaCha20]:  ");
    for (int i = 0; i < 8;  i++) printf("%02x", nonce8[i]);
    printf("\n");
    printf("  yarrow_random_nonce(12) [AES-GCM]:   ");
    for (int i = 0; i < 12; i++) printf("%02x", nonce12[i]);
    printf("\n");

    /* Salt */
    uint8_t salt[16];
    yarrow_random_salt(y, salt, sizeof(salt));
    printf("  yarrow_random_salt(16)  [Argon2]:    ");
    for (int i = 0; i < 16; i++) printf("%02x", salt[i]);
    printf("\n");

    /* yarrow_random_bytes_ct */
    uint8_t mask[32];
    yarrow_random_bytes_ct(y, mask, sizeof(mask));
    printf("  yarrow_random_bytes_ct(32):          ");
    for (int i = 0; i < 32; i++) printf("%02x", mask[i]);
    printf("\n");

    /* ── OTP: create, encrypt, decrypt, verify ────────────────────────────── */
    printf("\n  -- OTP --\n");

    const char *plaintext = "Attack at dawn!!";  /* exactly 16 bytes */
    size_t      msg_len   = strlen(plaintext);

    yarrow_otp_t otp = yarrow_otp_create(y, msg_len);
    if (!otp.pad) {
        fprintf(stderr, "  [ERROR] yarrow_otp_create failed\n");
    } else {
        printf("  OTP pad (%zu bytes):  ", otp.size);
        for (size_t i = 0; i < otp.size; i++) printf("%02x", otp.pad[i]);
        printf("\n");

        /* Encrypt */
        uint8_t ciphertext[msg_len];
        yarrow_otp_encrypt(&otp, (const uint8_t *)plaintext, ciphertext, 0, msg_len);
        printf("  Plaintext:           \"%s\"\n", plaintext);
        printf("  Ciphertext (hex):    ");
        for (size_t i = 0; i < msg_len; i++) printf("%02x", ciphertext[i]);
        printf("\n");

        /* Decrypt — identical call, XOR is its own inverse */
        uint8_t recovered[msg_len + 1];
        yarrow_otp_decrypt(&otp, ciphertext, recovered, 0, msg_len);
        recovered[msg_len] = '\0';
        printf("  Decrypted:           \"%s\"\n", recovered);

        int match = (memcmp(plaintext, recovered, msg_len) == 0);
        printf("  Round-trip match:    %s\n", match ? "PASS" : "FAIL");

        /* Demonstrate the range-overflow guard */
        int rc = yarrow_otp_encrypt(&otp, ciphertext, ciphertext, msg_len, 1);
        printf("  Overflow guard:      %s (got %d, want -1)\n",
               rc == -1 ? "PASS" : "FAIL", rc);

        yarrow_otp_free(&otp);
        printf("  yarrow_otp_free():   pad=%p size=%zu (zeroed+freed)\n",
               (void *)otp.pad, otp.size);
    }

    printf("\n");

    /* ── §3  Numeric / general ────────────────────────────────────────────── */
    printf("-- §3  Numeric / General --\n");

    /* yarrow_random_range: d6 rolls */
    printf("  yarrow_random_range(1, 7) — 10 d6 rolls: ");
    for (int i = 0; i < 10; i++)
        printf("%llu ", (unsigned long long)yarrow_random_range(y, 1, 7));
    printf("\n");

    /* yarrow_random_range: large range */
    printf("  yarrow_random_range(0, 1000000) — 5 values: ");
    for (int i = 0; i < 5; i++)
        printf("%llu ", (unsigned long long)yarrow_random_range(y, 0, 1000000));
    printf("\n");

    /* yarrow_random_double */
    printf("  yarrow_random_double() — 8 values in [0,1): ");
    for (int i = 0; i < 8; i++)
        printf("%.6f ", yarrow_random_double(y));
    printf("\n");

    /* yarrow_shuffle: deck of 10 cards */
    int deck[10];
    for (int i = 0; i < 10; i++) deck[i] = i + 1;
    printf("  yarrow_shuffle() on [1..10]:\n");
    printf("    before: ");
    for (int i = 0; i < 10; i++) printf("%d ", deck[i]);
    printf("\n");
    yarrow_shuffle(y, deck, 10, sizeof(int));
    printf("    after:  ");
    for (int i = 0; i < 10; i++) printf("%d ", deck[i]);
    printf("\n");

    /* Shuffle again to show it's not the same permutation */
    yarrow_shuffle(y, deck, 10, sizeof(int));
    printf("    again:  ");
    for (int i = 0; i < 10; i++) printf("%d ", deck[i]);
    printf("\n");

    printf("\n=== Done ===\n");
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    yarrow_t y;
    if (yarrow_init(&y, "prng.seed") != 0) {
        fprintf(stderr, "yarrow_init failed (sodium_init error?)\n");
        return 1;
    }

    const char *mode = (argc > 1) ? argv[1] : "all";

    if (strcmp(mode, "latency")    == 0 || strcmp(mode, "all") == 0) bench_latency(&y);
    if (strcmp(mode, "sample")     == 0 || strcmp(mode, "all") == 0) show_samples(&y);
    if (strcmp(mode, "entropy")    == 0 || strcmp(mode, "all") == 0) demo_entropy(&y);
    if (strcmp(mode, "hashes")     == 0 || strcmp(mode, "all") == 0) demo_hashes(&y);

    if (strcmp(mode, "randomness") == 0) {
        int kb = (argc > 2) ? atoi(argv[2]) : 64;
        dump_randomness(&y, kb);
    }

    yarrow_destroy(&y);
    return 0;
}
