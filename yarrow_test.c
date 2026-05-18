/**
 * yarrow_test.c — test & demo for the Yarrow-256 CSPRNG
 *
 * Mirrors the test modes from the original Freenet Yarrow main():
 *   latency   — benchmark bytes/ms, uint32, uint64
 *   randomness — dump N KB of raw bytes to stdout (pipe to dieharder etc.)
 *   sample    — print sample outputs
 *   entropy   — demonstrate entropy accumulation and reseed triggering
 */

#include "yarrow.h"
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
    const int ITERS   = 1000;
    const int BUF_KB  = 1;
    uint8_t buf[1024 * BUF_KB];

    printf("=== Latency Benchmark ===\n");

    double t0 = ms_now();
    for (int i = 0; i < ITERS; i++)
        yarrow_next_bytes(y, buf, sizeof(buf));
    double elapsed = ms_now() - t0;
    printf("  nextBytes(%d KB): %.4f ms/KB  (%.2f MB/s)\n",
           BUF_KB,
           elapsed / ITERS,
           (ITERS * BUF_KB) / elapsed);

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

    printf("  nextUint32(): ");
    for (int i = 0; i < 5; i++)
        printf("%10u ", yarrow_next_uint32(y));
    printf("\n");

    printf("  nextUint64(): ");
    for (int i = 0; i < 3; i++)
        printf("%20llu ", (unsigned long long)yarrow_next_uint64(y));
    printf("\n");

    printf("  16 random bytes: ");
    uint8_t blob[16];
    yarrow_next_bytes(y, blob, sizeof(blob));
    for (int i = 0; i < 16; i++) printf("%02x", blob[i]);
    printf("\n");
}

/* ── Entropy demo ────────────────────────────────────────────────────────────── */
static void demo_entropy(yarrow_t *y) {
    printf("=== Entropy Accumulation Demo ===\n");

    int src_a = yarrow_register_source(y);
    int src_b = yarrow_register_source(y);
    printf("  Registered sources: %d, %d\n", src_a, src_b);

    int total_a = 0, total_b = 0;
    printf("  Feeding 200 timer ticks into source A...\n");
    for (int i = 0; i < 200; i++) {
        total_a += yarrow_accept_timer(y, src_a);
        /* tiny sleep so timer values actually differ */
        struct timespec s = {0, 100000}; /* 0.1 ms */
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
    printf("  (Slow pool reseed triggered when 2 independent sources each\n");
    printf("   exceed %d bits — mirrors Freenet's SLOW_K=2 logic)\n",
           YARROW_SLOW_THRESHOLD);

    /* Show that output is still flowing fine after reseeds */
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

/* ── main ────────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    yarrow_t y;

    if (yarrow_init(&y, "prng.seed") != 0) {
        fprintf(stderr, "yarrow_init failed (sodium_init error?)\n");
        return 1;
    }

    const char *mode = (argc > 1) ? argv[1] : "all";

    if (strcmp(mode, "latency") == 0 || strcmp(mode, "all") == 0)
        bench_latency(&y);

    if (strcmp(mode, "sample") == 0 || strcmp(mode, "all") == 0)
        show_samples(&y);

    if (strcmp(mode, "entropy") == 0 || strcmp(mode, "all") == 0)
        demo_entropy(&y);

    if (strcmp(mode, "randomness") == 0) {
        int kb = (argc > 2) ? atoi(argv[2]) : 64;
        dump_randomness(&y, kb);
    }

    yarrow_destroy(&y);
    return 0;
}
