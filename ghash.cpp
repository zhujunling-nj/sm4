#include <string.h>
#include "sm4.h"

#define USE_CACHE

inline int min(int a, int b) {
    return (a <= b) ? a : b;
}

inline uint64 bytes_int64(cbytes b) {
    return (uint64)b[0] << 56 | (uint64)b[1] << 48 |
           (uint64)b[2] << 40 | (uint64)b[3] << 32 |
           (uint64)b[4] << 24 | (uint64)b[5] << 16 |
           (uint64)b[6] << 8 | (uint64)b[7];
}

inline void int64_bytes(bytes out, uint64 x) {
    out[0] = (byte)(x >> 56);
    out[1] = (byte)(x >> 48);
    out[2] = (byte)(x >> 40);
    out[3] = (byte)(x >> 32);
    out[4] = (byte)(x >> 24);
    out[5] = (byte)(x >> 16);
    out[6] = (byte)(x >> 8);
    out[7] = (byte)x;
}

inline void bytes_gf128(gf128 &out, cbytes b) {
    out.hi = bytes_int64(b);
    out.lo = bytes_int64(b + 8);
}

inline void gf128_xor(gf128 &result, const gf128 &value) {
    result.hi ^= value.hi;
    result.lo ^= value.lo;
}

#ifdef USE_CACHE
static void fm2m_mul(uint64 value_hi, uint64 value_lo,
                     uint64 times_hi, uint64 times_lo,
                     gf128 &result) {
    static const uint64 R = 0xE1LL << 56;  // f(x) = 1 + x + x^2 + x^7 + x^128
    static gf128 key, cache[64][4];

    if (key.hi != value_hi || key.lo != value_lo) {
        key.hi = value_hi;
        key.lo = value_lo;
        for (int i = 0; i < 64; i++) {
            cache[i][2].hi = value_hi;
            cache[i][2].lo = value_lo;
            bool bit_127 = value_lo & 1;
            value_lo = value_lo >> 1 | value_hi << 63;
            value_hi = value_hi >> 1 ^ (bit_127 ? R : 0);
            cache[i][1].hi = value_hi;
            cache[i][1].lo = value_lo;
            cache[i][3].hi = value_hi ^ cache[i][2].hi;
            cache[i][3].lo = value_lo ^ cache[i][2].lo;
            bit_127 = value_lo & 1;
            value_lo = value_lo >> 1 | value_hi << 63;
            value_hi = value_hi >> 1 ^ (bit_127 ? R : 0);
        }
    }

    int bits;
    uint64 result_hi = 0, result_lo = 0;
    for (int i = 0; times_hi; i++) {
        if ((bits = times_hi >> 62) != 0) {
            result_hi ^= cache[i][bits].hi;
            result_lo ^= cache[i][bits].lo;
        }
        times_hi <<= 2;
    }
    for (int i = 32; times_lo; i++) {
        if ((bits = times_lo >> 62) != 0) {
            result_hi ^= cache[i][bits].hi;
            result_lo ^= cache[i][bits].lo;
        }
        times_lo <<= 2;
    }
    result.hi = result_hi;
    result.lo = result_lo;
}

#else
static void fm2m_mul(uint64 value_hi, uint64 value_lo,
                     uint64 times_hi, uint64 times_lo,
                     gf128 &result) {
    static const uint64 R = 0xE1LL << 56;  // f(x) = 1 + x + x^2 + x^7 + x^128
    uint64 result_hi = 0, result_lo = 0;
    while (times_hi || times_lo) {
        if ((int64)times_hi < 0) {
            result_hi ^= value_hi;
            result_lo ^= value_lo;
        }
        bool bit_127 = value_lo & 1;
        value_lo = value_lo >> 1 | value_hi << 63;
        value_hi = value_hi >> 1 ^ (bit_127 ? R : 0);
        times_hi = times_hi << 1 | times_lo >> 63;
        times_lo = times_lo << 1;
    }
    result.hi = result_hi;
    result.lo = result_lo;
}
#endif

bytes ghash(bytes hash, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen) {
    byte buff[16] = {0};
    if (iv && ivlen) {
        memcpy(buff, iv, min(ivlen, 16));
    }

    gf128 hashv, temp;
    bytes_gf128(hashv, buff);
    uint64 keyint_hi = bytes_int64(key);
    uint64 keyint_lo = bytes_int64(key + 8);
    size_t len16 = srclen & (SIZE_MAX - 15);
    for (size_t pos = 0; pos < len16; pos += 16) {
        bytes_gf128(temp, src + pos);
        gf128_xor(temp, hashv);
        fm2m_mul(keyint_hi, keyint_lo, temp.hi, temp.lo, hashv);
    }

    if (len16 < srclen) {
        byte buff[16] = {0};
        memcpy(buff, src + len16, srclen - len16);
        bytes_gf128(temp, buff);
        gf128_xor(temp, hashv);
        fm2m_mul(keyint_hi, keyint_lo, temp.hi, temp.lo, hashv);
    }

    int64_bytes(hash, hashv.hi);
    int64_bytes(hash + 8, hashv.lo);
    return hash;
}
