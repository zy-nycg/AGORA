/*
 * AGORA v0.2.2 — 参考实现 · C 后端 Keccak-256（GATE-10b）
 * ======================================================
 *
 * 目的：把协议唯一的哈希函数从纯 Python（约 800 µs/次）降到 C（约 1 µs/次）。
 * 规范 §2.2 要求 Keccak-256，**不是** SHA-3-256。二者仅填充字节不同：
 *
 *     Keccak-256（本协议）：域分隔字节 = 0x01
 *     SHA-3-256（NIST）    ：域分隔字节 = 0x06
 *
 * 标准测试向量（用于自检）：
 *     keccak256("")    = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
 *     keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
 *
 * **正确性纪律：** 本文件是**性能后端**，不是权威实现。权威实现是
 * `agora/crypto.py` 的纯 Python 版本。任何启用前都必须逐字节比对一致；
 * 比对不过就回退纯 Python（见 `agora/crypto_backend.py` 的 `_probe_native_keccak`）。
 *
 * 编译：`python3 tools/agora_build_native.py`（产物 native/libagora_keccak.so）
 */

#include <stddef.h>
#include <stdint.h>

/* Keccak-f[1600] 的轮常数与旋转偏移表。
 * 二者均已与 `agora/crypto.py` 的 `_rc()` / `_rho()` 逐项核对一致。 */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/* offset[x + 5y] */
static const unsigned RHO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

static inline uint64_t rotl64(uint64_t x, unsigned n) {
    /* n == 0 时左移 64 位是未定义行为，必须单独处理 */
    return n == 0 ? x : ((x << n) | (x >> (64 - n)));
}

/* Keccak-f[1600]：24 轮，每轮 θ ρ π χ ι 五步。
 *
 * π 步的索引映射为 `B[y][2x+3y] = A[x][y]`，展开成一维（下标 x + 5y）后
 * 即下方 `dst` 表 —— 该表已与 `agora/crypto.py` 的 `_KECCAK_PI_MAP`
 * 逐项核对一致。若此表写错，哈希会静默产出错误结果，因此
 * `crypto_backend` 启用前必须通过向量比对。 */
static void keccakf(uint64_t st[25]) {
    int round;
    for (round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];
        int x, y;

        for (x = 0; x < 5; x++)
            C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        for (x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                st[x + 5 * y] ^= D[x];

        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                B[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rotl64(st[x + 5 * y], RHO[x + 5 * y]);

        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                st[x + 5 * y] =
                    B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) &
                                    B[((x + 2) % 5) + 5 * y]);

        st[0] ^= RC[round];
    }
}

/*
 * Keccak-256：rate = 1088 bit = 136 字节，域分隔字节 0x01。
 *
 * 填充规则（与 `crypto.py` 的 `keccak256` 一致）：补 `0x01`、填零，
 * 末字节置最高位；当只剩 1 字节余量时二者合并为 `0x81`。
 */
void agora_keccak256(const uint8_t *in, size_t inlen, uint8_t *out) {
    const size_t rate = 136;
    uint64_t st[25];
    size_t i, off;
    int j;

    for (i = 0; i < 25; i++)
        st[i] = 0;

    /* 逐块吸收完整分组 */
    off = 0;
    while (inlen - off >= rate) {
        for (i = 0; i < rate / 8; i++) {
            uint64_t w = 0;
            for (j = 7; j >= 0; j--)
                w = (w << 8) | (uint64_t)in[off + i * 8 + (size_t)j];
            st[i] ^= w;
        }
        keccakf(st);
        off += rate;
    }

    /* 处理最后一块（含填充） */
    {
        uint8_t blk[136];
        size_t rem = inlen - off;
        for (i = 0; i < rate; i++)
            blk[i] = 0;
        for (i = 0; i < rem; i++)
            blk[i] = in[off + i];
        blk[rem] = 0x01;                       /* Keccak 域分隔（非 SHA-3 的 0x06） */
        blk[rate - 1] |= 0x80;                 /* 末字节最高位置位 */
        for (i = 0; i < rate / 8; i++) {
            uint64_t w = 0;
            for (j = 7; j >= 0; j--)
                w = (w << 8) | (uint64_t)blk[i * 8 + (size_t)j];
            st[i] ^= w;
        }
        keccakf(st);
    }

    /* 输出前 32 字节（小端） */
    for (i = 0; i < 32; i++)
        out[i] = (uint8_t)((st[i / 8] >> (8 * (i % 8))) & 0xFF);
}
