# `yarrow-dot-c`

```
gcc -O2 -o yarrow_test yarrow.c yarrow_test.c -lsodium -lpthread
./yarrow_test             # runs all modes except randomness and hashes
./yarrow_test hashes      # common_hashes.h demo
./yarrow_test latency
./yarrow_test sample
./yarrow_test entropy
./yarrow_test randomness 1024
```

The original code stored both the ChaCha20 nonce and the block position in a single 16-byte `counter[]` array and reset it inside `rekey()`. After each reseed, the counter went back to `Encrypt(key, 0...0)`, so it could revisit the same counter positions with a different key — and ChaCha20's security model requires the `(nonce, block_position)` pair to be globally unique, not just unique within one key's lifetime.

**The fix** — split them into two independent fields:

| Old | New | What it does |
|---|---|---|
| `uint8_t counter[16]` | `uint8_t nonce[8]` | Set once from `randombytes_buf` at init; **never touched again** |
| *(implicit in counter)* | `uint64_t block_counter` | Incremented before every keystream block; **never reset**, even across rekeys |
| `crypto_stream_chacha20_xor(…, counter, key)` | `crypto_stream_chacha20_xor_ic(…, nonce, block_counter, key)` | The `_ic` variant takes the initial counter as an explicit `uint64_t` argument |

**What `rekey()` now does**: it only `memcpy`s the new key and marks `fetch_cursor = YARROW_BLOCK_SIZE` (invalidates the output buffer). It no longer touches `nonce` or `block_counter`.

A few secondary changes fell out of this:
- `YARROW_BLOCK_SIZE` updated from 16 (AES block) to 64 (ChaCha20 block), since the original was accidentally using the wrong block size for ChaCha20 — it was only XOR-ing 16 bytes per call when ChaCha20 produces 64.
- The rekey key-derivation loop adjusted accordingly (takes 16 bytes from each of 2 blocks to fill 32 bytes, avoiding a full 128-byte keystream draw just for a new key).
- `yarrow_destroy()` now also zeroes `nonce` and `block_counter`.