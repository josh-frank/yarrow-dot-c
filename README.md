# `yarrow-dot-c`

```
gcc -O2 -o yarrow_test yarrow.c yarrow_test.c -lsodium -lpthread
./yarrow_test sample
./yarrow_test latency
./yarrow_test randomness 1024 | dieharder -a -g 200
```

## Bugs

- The ChaCha20 nonce reuse across rekey boundaries causes a period where some values repeat in the output stream. The fix is to use a monotonically incrementing 64-bit counter as the nonce rather than deriving it from the key — a one-line change. The Freenet original didn't have this because AES-ECB doesn't have a nonce, but it's the price of swapping in ChaCha20.