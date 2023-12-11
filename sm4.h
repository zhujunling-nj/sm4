#ifndef __SM4_H__
#define __SM4_H__
#include <stdint.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef _MSC_VER
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t int64;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef unsigned char byte;
typedef const byte *cbytes;
typedef byte *bytes;

typedef struct {
    uint64 hi;
    uint64 lo;
} gf128;

#ifdef _WIN64
#define WORD_SIZE 8
typedef uint64_t word;
#elif __SIZEOF_POINTER__ == 8
#define WORD_SIZE 8
typedef uint64_t word;
#else
#define WORD_SIZE 4
typedef uint32_t word;
#endif

ssize_t encrypt_ecb(bytes out, cbytes key, cbytes src, size_t srclen);
ssize_t decrypt_ecb(bytes out, cbytes key, cbytes src, size_t srclen);

ssize_t encrypt_cbc(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv);
ssize_t decrypt_cbc(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv);

ssize_t encrypt_ctr(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen);

ssize_t encrypt_gcm(bytes out, bytes tag, cbytes key, cbytes src, size_t srclen,
                    cbytes iv, int ivlen, cbytes aad, size_t aadlen);
ssize_t decrypt_gcm(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen,
                    cbytes aad, size_t aadlen, cbytes tag, int taglen);

ssize_t encrypt_ccm(bytes out, bytes tag, cbytes key, cbytes src, size_t srclen,
                    cbytes iv, int ivlen, cbytes aad, size_t aadlen, int taglen);
ssize_t decrypt_ccm(bytes out, cbytes key, cbytes src, size_t srclen, cbytes iv, int ivlen,
                    cbytes aad, size_t aadlen, cbytes tag, int taglen);

bytes ghash(bytes hash, cbytes key, cbytes src, size_t srclen, cbytes iv = NULL, int ivlen = 0);

#ifdef __cplusplus
}
#endif
#endif
