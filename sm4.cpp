#include <string.h>
#include "sm4.h"

// Default IV
static const byte IV0[16] = {0};

// Expanded SM4 box table
static const byte BOXES_TABLE[] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6,
    0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76,
    0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,
    0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
    0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3,
    0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73,
    0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb,
    0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e,
    0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21,
    0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf,
    0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce,
    0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34,
    0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29,
    0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c,
    0x5b, 0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
    0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1,
    0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12,
    0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96,
    0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee,
    0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// System parameter
static const uint32 FK[] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

// Fixed parameter
static const uint32 CK[] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85,
    0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11,
    0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d,
    0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5,
    0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279
};

inline int min(int a, int b) {
    return (a <= b) ? a : b;
}

inline uint32 rotl(uint32 x, int n) {
    return x << n | x >> (32 - n);
}

inline uint32 byte_int32(cbytes b) {
    return b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3];
}

inline void int32_bytes(bytes out, uint32 x) {
    out[0] = (byte)(x >> 24);
    out[1] = (byte)(x >> 16);
    out[2] = (byte)(x >> 8);
    out[3] = (byte)x;
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

inline void xor128(word *out, const word *src1, const word *src2) {
    out[0] = src1[0] ^ src2[0];
    out[1] = src1[1] ^ src2[1];
#if WORD_SIZE == 4
    out[2] = src1[2] ^ src2[2];
    out[3] = src1[3] ^ src2[3];
#endif
}

inline void bitxor(bytes out, cbytes src1, cbytes src2, int len) {
    int i, len4 = len & 12;
    for (i = 0; i < len4; i += 4) {
        *(uint32 *)(out + i) = *(uint32 *)(src1 + i) ^ *(uint32 *)(src2 + i);
    }
    for (; i < len; i++) {
        out[i] = src1[i] ^ src2[i];
    }
}

inline uint32 sm4_t(uint32 a) {
    uint32 b = BOXES_TABLE[a >> 24] << 24 | BOXES_TABLE[a >> 16 & 255] << 16 |
               BOXES_TABLE[a >> 8 & 255] << 8 | BOXES_TABLE[a & 255];
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
}

inline uint32 sm4_t1(uint32 a) {
    uint32 b = BOXES_TABLE[a >> 24] << 24 | BOXES_TABLE[a >> 16 & 255] << 16 |
               BOXES_TABLE[a >> 8 & 255] << 8 | BOXES_TABLE[a & 255];
    return b ^ rotl(b, 13) ^ rotl(b, 23);
}

inline uint32 sm4_f(uint32 x0, uint32 x1, uint32 x2, uint32 x3, uint32 rk) {
    return x0 ^ sm4_t(x1 ^ x2 ^ x3 ^ rk);
}

static void pkcs7(bytes dst, cbytes src, int srclen) {
    int padlen = 16 - srclen;
    memcpy(dst, src, srclen);
    memset(dst + srclen, padlen, padlen);
}

static ssize_t unpkcs7(cbytes buf, size_t len) {
    int pad = buf[len - 1];
    if (pad > 16 || (size_t)pad > len) {
        return -1;
    }
    for (int i = 2; i <= pad; i++) {
        if (buf[len - i] != pad)
            return -1;
    }
    return len - pad;
}

static void encrypt(bytes out, const uint32 *ekey, cbytes src) {
    uint32 ulbuf0 = byte_int32(src);
    uint32 ulbuf1 = byte_int32(src + 4);
    uint32 ulbuf2 = byte_int32(src + 8);
    uint32 ulbuf3 = byte_int32(src + 12);
    uint32 ulbuf4 = sm4_f(ulbuf0, ulbuf1, ulbuf2, ulbuf3, ekey[0]);
    ulbuf0 = sm4_f(ulbuf1, ulbuf2, ulbuf3, ulbuf4, ekey[1]);
    for (int i = 2; i < 32; i += 5) {
        ulbuf1 = sm4_f(ulbuf2, ulbuf3, ulbuf4, ulbuf0, ekey[i]);
        ulbuf2 = sm4_f(ulbuf3, ulbuf4, ulbuf0, ulbuf1, ekey[i + 1]);
        ulbuf3 = sm4_f(ulbuf4, ulbuf0, ulbuf1, ulbuf2, ekey[i + 2]);
        ulbuf4 = sm4_f(ulbuf0, ulbuf1, ulbuf2, ulbuf3, ekey[i + 3]);
        ulbuf0 = sm4_f(ulbuf1, ulbuf2, ulbuf3, ulbuf4, ekey[i + 4]);
    }
    int32_bytes(out, ulbuf0);
    int32_bytes(out + 4, ulbuf4);
    int32_bytes(out + 8, ulbuf3);
    int32_bytes(out + 12, ulbuf2);
}

static void key_reverse(uint32 *dkey, const uint32 *ekey) {
    for (int i = 0; i < 32; i += 4) {
        dkey[i] = ekey[31 - i];
        dkey[i + 1] = ekey[30 - i];
        dkey[i + 2] = ekey[29 - i];
        dkey[i + 3] = ekey[28 - i];
    }
}

static void key_extend(uint32 *ekey, cbytes key) {
    uint32 tk0 = byte_int32(key) ^ FK[0];
    uint32 tk1 = byte_int32(key + 4) ^ FK[1];
    uint32 tk2 = byte_int32(key + 8) ^ FK[2];
    uint32 tk3 = byte_int32(key + 12) ^ FK[3];
    ekey[0] = tk0 ^ sm4_t1(tk1 ^ tk2 ^ tk3 ^ CK[0]);
    ekey[1] = tk1 ^ sm4_t1(tk2 ^ tk3 ^ ekey[0] ^ CK[1]);
    ekey[2] = tk2 ^ sm4_t1(tk3 ^ ekey[0] ^ ekey[1] ^ CK[2]);
    ekey[3] = tk3 ^ sm4_t1(ekey[0] ^ ekey[1] ^ ekey[2] ^ CK[3]);
    for (int i = 4; i < 32; i++) {
        ekey[i] = ekey[i - 4] ^ sm4_t1(ekey[i - 3] ^ ekey[i - 2] ^ ekey[i - 1] ^ CK[i]);
    }
}

ssize_t encrypt_ecb(bytes out, cbytes key, cbytes src, size_t srclen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    size_t len16 = srclen & (SIZE_MAX - 15);
    for (size_t i = 0; i < len16; i += 16) {
        encrypt(out + i, ekey, src + i);
    }
    byte buff[16];
    pkcs7(buff, src + len16, (int)(srclen - len16));
    encrypt(out + len16, ekey, buff);
    return len16 + 16;
}

ssize_t decrypt_ecb(bytes out, cbytes key, cbytes src, size_t srclen) {
    uint32 ekey[32], dkey[32];
    key_extend(ekey, key);
    key_reverse(dkey, ekey);
    for (size_t i = 0; i < srclen; i += 16) {
        encrypt(out + i, dkey, src + i);
    }
    return unpkcs7(out, srclen);
}

ssize_t encrypt_cbc(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv) {
    uint32 ekey[32];
    key_extend(ekey, key);
    if (iv == NULL) {
        iv = IV0;
    }
    byte buff[16], temp[16];
    size_t len16 = srclen & (SIZE_MAX - 15);
    for (size_t i = 0; i < len16; i += 16) {
        xor128((word *)temp, (word *)(src + i), (word *)iv);
        encrypt(out + i, ekey, temp);
        iv = out + i;
    }
    pkcs7(buff, src + len16, (int)(srclen - len16));
    xor128((word *)temp, (word *)buff, (word *)iv);
    encrypt(out + len16, ekey, temp);
    return len16 + 16;
}

ssize_t decrypt_cbc(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv) {
    uint32 ekey[32], dkey[32];
    key_extend(ekey, key);
    key_reverse(dkey, ekey);
    if (iv == NULL) {
        iv = IV0;
    }
    for (size_t i = 0; i < srclen; i += 16) {
        encrypt(out + i, dkey, src + i);
        xor128((word *)(out + i), (word *)(out + i), (word *)iv);
        iv = src + i;
    }
    return unpkcs7(out, srclen);
}

static void ctr_counter_incr(bytes counter, int csize = 16) {
    int end = 15 - csize;
    for (int i = 15; i > end; i--) {
        counter[i]++;
        if (counter[i])
            break;
    }
}

static size_t encrypt_ctr_gtr(bytes out, const uint32 *ekey, cbytes src, size_t srclen, bytes ctr, int csize) {
    byte enctr[16];
    size_t len16 = srclen & (SIZE_MAX - 15);
    for (size_t i = 0; i < len16; i += 16) {
        encrypt(enctr, ekey, ctr);
        xor128((word *)(out + i), (word *)(src + i), (word *)enctr);
        ctr_counter_incr(ctr, csize);
    }
    if (len16 < srclen) {
        encrypt(enctr, ekey, ctr);
        bitxor(out + len16, src + len16, enctr, (int)(srclen - len16));
    }
    return srclen;
}

ssize_t encrypt_ctr(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    byte ctr[16] = {0};
    if (iv && ivlen) {
        memcpy(ctr, iv, min(ivlen, 16));
    }
    return encrypt_ctr_gtr(out, ekey, src, srclen, ctr, 16);
}

static void set_icb_hashkey(bytes icb, bytes hashkey,
                            const uint32 *ekey, cbytes iv, int ivlen) {
    encrypt(hashkey, ekey, hashkey);
    if (ivlen == 12) {
        memcpy(icb, iv, ivlen);
        icb[15] = 1;
        return;
    }
    byte buff[16] = {0};
    int64_bytes(buff + 8, (uint64)ivlen << 3);
    ghash(icb, hashkey, iv, ivlen);
    ghash(icb, hashkey, buff, 16, icb, 16);
}

ssize_t encrypt_gcm(bytes out, bytes tag, cbytes key, cbytes src, size_t srclen,
                    cbytes iv, int ivlen, cbytes aad, size_t aadlen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    byte hashkey[16] = {0};
    byte ctr[16], icb[16] = {0};
    set_icb_hashkey(icb, hashkey, ekey, iv, ivlen);
    memcpy(ctr, icb, 16);
    ctr_counter_incr(ctr, 4);
    encrypt_ctr_gtr(out, ekey, src, srclen, ctr, 4);
    //calculate the auth tag
    byte buff[16];
    int64_bytes(buff, (uint64)aadlen << 3);
    int64_bytes(buff + 8, (uint64)srclen << 3);
    ghash(tag, hashkey, aad, aadlen);
    ghash(tag, hashkey, out, srclen, tag, 16);
    ghash(tag, hashkey, buff, 16, tag, 16);
    encrypt_ctr_gtr(tag, ekey, tag, 16, icb, 0);
    return srclen;
}

ssize_t decrypt_gcm(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen,
                    cbytes aad, size_t aadlen, cbytes tag, int taglen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    byte hashkey[16] = {0};
    byte icb[16] = {0};
    set_icb_hashkey(icb, hashkey, ekey, iv, ivlen);
    //calculate the auth tag
    byte buff[16], tag1[16];
    int64_bytes(buff, (uint64)aadlen << 3);
    int64_bytes(buff + 8, (uint64)srclen << 3);
    ghash(tag1, hashkey, aad, aadlen);
    ghash(tag1, hashkey, src, srclen, tag1, 16);
    ghash(tag1, hashkey, buff, 16, tag1, 16);
    encrypt_ctr_gtr(tag1, ekey, tag1, 16, icb, 0);
    if (memcmp(tag, tag1, taglen)) {
        return -1;
    }
    ctr_counter_incr(icb, 4);
    encrypt_ctr_gtr(out, ekey, src, srclen, icb, 4);
    return srclen;
}

static void cbc_mac(bytes tag, uint32 ekey[], cbytes src, size_t srclen,
                    cbytes iv, int ivlen, cbytes aad, size_t aadlen, int taglen) {
    // https://www.rfc-editor.org/rfc/rfc3610 2.2
    size_t fllen = 15 - ivlen;      // length of data length in flags
    int ftlen = (taglen - 2) >> 1;  // tag length in flags (first byte of block 0)
    byte blk[16];
    blk[0] = (byte)(((aadlen > 0) << 6) | (ftlen << 3) | (fllen - 1));
    int64_bytes(blk + 8, srclen);
    memcpy(blk + 1, iv, ivlen);
    encrypt(tag, ekey, blk);

    if (aadlen) {
        int lenlen;
        if (aadlen < 65280) {  // 2^16 - 2^8
            blk[0] = (byte)(aadlen >> 16);
            blk[1] = (byte)aadlen;
            lenlen = 2;
        } else if (aadlen < 4294967296LL) {  // 2^32
            blk[0] = 0xFF, blk[1] = 0xFE;
            int32_bytes(blk + 2, (uint32)aadlen);
            lenlen = 6;
        } else {  // 2^32 to 2^64
            blk[0] = blk[1] = 0xFF;
            int64_bytes(blk + 2, aadlen);
            lenlen = 10;
        }
        memcpy(blk + lenlen, aad, 16 - lenlen);
        xor128((word *)tag, (word *)tag, (word *)blk);
        encrypt(tag, ekey, tag);
        size_t len16 = aadlen - ((aadlen + lenlen) & 15);
        for (size_t i = 16 - lenlen; i < len16; i += 16) {
            xor128((word *)tag, (word *)tag, (word *)(aad + i));
            encrypt(tag, ekey, tag);
        }
        if (len16 < aadlen) {
            memset(blk, 0, 16);
            memcpy(blk, aad + len16, aadlen - len16);
            xor128((word *)tag, (word *)tag, (word *)blk);
            encrypt(tag, ekey, tag);
        }
    }

    if (srclen) {
        size_t len16 = srclen & (SIZE_MAX - 15);
        for (size_t i = 0; i < len16; i += 16) {
            xor128((word *)tag, (word *)tag, (word *)(src + i));
            encrypt(tag, ekey, tag);
        }
        if (len16 < srclen) {
            memset(blk, 0, 16);
            memcpy(blk, src + len16, srclen - len16);
            xor128((word *)tag, (word *)tag, (word *)blk);
            encrypt(tag, ekey, tag);
        }
    }
}

ssize_t encrypt_ccm(bytes out, bytes tag, cbytes key, cbytes src, size_t srclen,
                    cbytes iv, int ivlen, cbytes aad, size_t aadlen, int taglen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    cbc_mac(tag, ekey, src, srclen, iv, ivlen, aad, aadlen, taglen);
    byte enicb[16], icb[16] = {0};
    int llen = 15 - ivlen;
    icb[0] = llen - 1;
    memcpy(icb + 1, iv, ivlen);
    encrypt(enicb, ekey, icb);
    xor128((word *)tag, (word *)tag, (word *)enicb);
    ctr_counter_incr(icb, llen);
    encrypt_ctr_gtr(out, ekey, src, srclen, icb, llen);
    return srclen;
}

ssize_t decrypt_ccm(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen,
                    cbytes aad, size_t aadlen, cbytes tag, int taglen) {
    uint32 ekey[32];
    key_extend(ekey, key);
    byte tag1[16], enicb[16], icb[16] = {0};
    int llen = 15 - ivlen;
    icb[0] = llen - 1;
    memcpy(icb + 1, iv, ivlen);
    encrypt(enicb, ekey, icb);
    ctr_counter_incr(icb, llen);
    encrypt_ctr_gtr(out, ekey, src, srclen, icb, llen);
    cbc_mac(tag1, ekey, out, srclen, iv, ivlen, aad, aadlen, taglen);
    xor128((word *)tag1, (word *)tag1, (word *)enicb);
    return memcmp(tag, tag1, taglen) ? -1 : srclen;
}
