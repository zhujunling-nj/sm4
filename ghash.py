#-*-coding:utf8;-*-
''' GF(2^128)上的Hash函数 '''

class GF2m128:
    ''' 有限域GF(2^128)上的数学运算 '''
    __slots__ = []
    R = 0xE1 << 120  # f(x) = 1 + x + x^2 + x^7 + x^128
    CACHE_SIZE = 64
    CACHE = {}

    @classmethod
    def mul(cls, aaa, bbb):
        ''' GF(2^128)上的乘法运算 '''
        result = aaa
        bits = f'{bbb:0128b}'.rstrip('0')
        for k in bits[-2::-1]:
            result = result >> 1 ^ cls.R if result & 1 else result >> 1
            if k == '1':
                result ^= aaa
        return result

    @classmethod
    def fmul(cls, aaa, bbb):
        ''' GF(2^128)上的乘法运算, 使用缓存加速 '''
        if aaa not in cls.CACHE:
            cls.CACHE[aaa] = cls.create_cache(aaa)
            if len(cls.CACHE) > cls.CACHE_SIZE:
                del cls.CACHE[next(iter(cls.CACHE))]
        cache = cls.CACHE[aaa]
        result = 0
        for i in range(16):
            result ^= cache[i][bbb & 0xFF]
            bbb >>= 8
        return result

    @classmethod
    def create_cache(cls, key):
        ''' 生成缓存: 16*256 '''
        cache = []
        for i in range(16):
            cache2 = []
            for _ in range(8):
                cache2.append(key)
                key = key >> 1 ^ cls.R if key & 1 else key >> 1
            cache.append([])
            for j in range(256):
                result = 0
                for k in range(8):
                    if j & 0x80:
                        result ^= cache2[k]
                    if not (j := j << 1):
                        break
                cache[i].append(result)
        return cache[::-1]


class GHash:
    ''' GF(2^128)上的Hash函数 '''
    __slots__ = []
    USE_CACHE = 0

    @staticmethod
    def ghash_imp(keyint, data, hashv=0):
        ''' GHASH Implement '''
        gf_mul = GF2m128.fmul if GHash.USE_CACHE else GF2m128.mul
        datalen = len(data)
        len16 = datalen - (datalen & 15)
        for pos in range(0, len16, 16):
            hashv ^= bytes2int(data[pos:pos+16])
            hashv = gf_mul(keyint, hashv)
        if len16 < datalen:
            data = data[len16:].ljust(16, b'\0')
            hashv ^= bytes2int(data)
            hashv = gf_mul(keyint, hashv)
        return hashv

    @staticmethod
    def ghash(key, data, iv0=bytes(16)):
        ''' GHASH Function '''
        keyint = bytes2int(key)
        hashv = bytes2int(iv0.ljust(16, b'\0'))
        hashv = GHash.ghash_imp(keyint, data, hashv)
        return int2bytes(hashv, 16)


def int2bytes(value, length):
    ''' Convert Integer to Bytes '''
    return value.to_bytes(length, 'big')

def bytes2int(bytestr):
    ''' Convert Bytes to Integer '''
    return int.from_bytes(bytestr, 'big')
