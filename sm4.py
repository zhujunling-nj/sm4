''' SM4 encrypt and decrypt '''
from struct import pack, unpack, unpack_from
try:
    from _sm4 import (
        encrypt_ecb, decrypt_ecb, encrypt_cbc, decrypt_cbc, encrypt_ctr,
        encrypt_gcm, decrypt_gcm, encrypt_ccm, decrypt_ccm
    )
    _SM4 = True
except ImportError:
    _SM4 = None

try:
    from ghash import GHash
except ImportError:
    GHash = None


# Expanded SM4 box table
_BOXES_TABLE = \
    b'\xd6\x90\xe9\xfe\xcc\xe1\x3d\xb7\x16\xb6\x14\xc2\x28\xfb\x2c\x05' \
    b'\x2b\x67\x9a\x76\x2a\xbe\x04\xc3\xaa\x44\x13\x26\x49\x86\x06\x99' \
    b'\x9c\x42\x50\xf4\x91\xef\x98\x7a\x33\x54\x0b\x43\xed\xcf\xac\x62' \
    b'\xe4\xb3\x1c\xa9\xc9\x08\xe8\x95\x80\xdf\x94\xfa\x75\x8f\x3f\xa6' \
    b'\x47\x07\xa7\xfc\xf3\x73\x17\xba\x83\x59\x3c\x19\xe6\x85\x4f\xa8' \
    b'\x68\x6b\x81\xb2\x71\x64\xda\x8b\xf8\xeb\x0f\x4b\x70\x56\x9d\x35' \
    b'\x1e\x24\x0e\x5e\x63\x58\xd1\xa2\x25\x22\x7c\x3b\x01\x21\x78\x87' \
    b'\xd4\x00\x46\x57\x9f\xd3\x27\x52\x4c\x36\x02\xe7\xa0\xc4\xc8\x9e' \
    b'\xea\xbf\x8a\xd2\x40\xc7\x38\xb5\xa3\xf7\xf2\xce\xf9\x61\x15\xa1' \
    b'\xe0\xae\x5d\xa4\x9b\x34\x1a\x55\xad\x93\x32\x30\xf5\x8c\xb1\xe3' \
    b'\x1d\xf6\xe2\x2e\x82\x66\xca\x60\xc0\x29\x23\xab\x0d\x53\x4e\x6f' \
    b'\xd5\xdb\x37\x45\xde\xfd\x8e\x2f\x03\xff\x6a\x72\x6d\x6c\x5b\x51' \
    b'\x8d\x1b\xaf\x92\xbb\xdd\xbc\x7f\x11\xd9\x5c\x41\x1f\x10\x5a\xd8' \
    b'\x0a\xc1\x31\x88\xa5\xcd\x7b\xbd\x2d\x74\xd0\x12\xb8\xe5\xb4\xb0' \
    b'\x89\x69\x97\x4a\x0c\x96\x77\x7e\x65\xb9\xf1\x09\xc5\x6e\xc6\x84' \
    b'\x18\xf0\x7d\xec\x3a\xdc\x4d\x20\x79\xee\x5f\x3e\xd7\xcb\x39\x48' \

# System parameter
_FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

# Fixed parameter
_CK = (
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85,
    0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11,
    0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d,
    0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5,
    0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279
)


class SM4Error(Exception):
    ''' SM4 error '''
    __slots__ = ['msg']

    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return self.msg


class SM4:
    ''' SM4 encrypt and decrypt '''
    __slots__ = ['key']
    FAST = _SM4 is not None

    def __init__(self, key):
        if len(key) != 16:
            raise SM4Error('The key must have length of 16 bytes.')
        self.key = key

    def encrypt_ecb(self, data):
        ''' SM4-ECB block encryption '''
        if self.FAST:
            return encrypt_ecb(self.key, data)

        output = bytearray()
        datalen = len(data)
        len16 = datalen - (datalen & 15)
        enc_key = SM4._key_extend(self.key)
        for pos in range(0, len16, 16):
            output.extend(SM4._encrypt(enc_key, data, pos))

        data = SM4.pkcs7(data[len16:])
        output.extend(SM4._encrypt(enc_key, data))
        return output

    def decrypt_ecb(self, data):
        ''' SM4-ECB block decryption '''
        if self.FAST:
            return decrypt_ecb(self.key, data)

        output = bytearray()
        dec_key = SM4._key_extend(self.key, False)
        for pos in range(0, len(data), 16):
            output.extend(SM4._encrypt(dec_key, data, pos))
        return SM4.unpkcs7(output)

    def encrypt_cbc(self, data, iv0=bytes(16)):
        ''' SM4-CBC block encryption '''
        if self.FAST:
            return encrypt_cbc(self.key, data, iv0)

        output = bytearray()
        datalen = len(data)
        len16 = datalen - (datalen & 15)
        enc_key = SM4._key_extend(self.key)
        for pos in range(0, len16, 16):
            iv0 = SM4._encrypt(enc_key, xor128(iv0, data, 0, pos))
            output.extend(iv0)

        data = SM4.pkcs7(data[len16:])
        iv0 = SM4._encrypt(enc_key, xor128(iv0, data))
        output.extend(iv0)
        return output

    def decrypt_cbc(self, data, iv0=bytes(16)):
        ''' SM4-CBC block decryption '''
        if self.FAST:
            return decrypt_cbc(self.key, data, iv0)

        output = bytearray()
        dec_key = SM4._key_extend(self.key, False)
        for pos in range(0, len(data), 16):
            temp = SM4._encrypt(dec_key, data, pos)
            output.extend(iv0[i] ^ temp[i] for i in range(16))
            iv0 = data[pos:pos+16]
        return SM4.unpkcs7(output)

    def encrypt_ctr(self, data, iv0=bytes(16)):
        ''' SM4-CTR encryption and decryption '''
        if self.FAST:
            return encrypt_ctr(self.key, data, iv0)

        ctr = pack('16s', iv0)
        output = bytearray()
        datalen = len(data)
        len16 = datalen - (datalen & 15)
        enc_key = SM4._key_extend(self.key)
        for pos in range(0, len16, 16):
            enctr = SM4._encrypt(enc_key, ctr)
            output.extend(xor128(enctr, data, 0, pos))
            ctr = SM4._ctr_counter_incr(ctr)
        if len16 < datalen:
            enctr = SM4._encrypt(enc_key, ctr)
            output.extend(bitxor(enctr, data[len16:]))
        return output

    def encrypt_gcm(self, data, iv0, aad, tlen=16):
        ''' SM4-GCM encryption '''
        if not 12 <= tlen <= 16:
            raise SM4Error('The tlen must be between 12 and 16.')
        if self.FAST:
            return encrypt_gcm(self.key, data, iv0, aad, tlen)
        if GHash is None:
            raise SM4Error('GHash Not Implemented.')

        enc_key = SM4._key_extend(self.key)
        hashkey = SM4._encrypt(enc_key, bytes(16))
        keyint = bytes2int(hashkey)
        if len(iv0) == 12:
            icb = iv0 + b'\0\0\0\1'
        else:
            hashv = GHash.ghash_imp(keyint, iv0, 0)
            hashv = GHash.ghash_imp(keyint, pack('>QQ', 0, len(iv0)<<3), hashv)
            icb = int2bytes(hashv, 16)

        data = SM4._gctr(enc_key, data, SM4._ctr_counter_incr(icb, 4))
        lenf = pack('>QQ', len(aad)<<3, len(data)<<3)
        hashv = GHash.ghash_imp(keyint, aad, 0)
        hashv = GHash.ghash_imp(keyint, data, hashv)
        hashv = GHash.ghash_imp(keyint, lenf, hashv)
        block = int2bytes(hashv, 16)
        enicb = SM4._encrypt(enc_key, icb)
        tag = xor128(enicb, block)
        return data, tag[:tlen]

    def decrypt_gcm(self, data, iv0, aad, tag):
        ''' SM4-GCM decryption '''
        if not 12 <= len(tag) <= 16:
            raise SM4Error('The tag must have length from 12 to 16 bytes.')
        if self.FAST:
            return decrypt_gcm(self.key, data, iv0, aad, tag)
        if GHash is None:
            raise SM4Error('GHash Not Implemented.')

        enc_key = SM4._key_extend(self.key)
        hashkey = SM4._encrypt(enc_key, bytes(16))
        keyint = bytes2int(hashkey)
        if len(iv0) == 12:
            icb = iv0 + b'\0\0\0\1'
        else:
            hashv = GHash.ghash_imp(keyint, iv0, 0)
            hashv = GHash.ghash_imp(keyint, pack('>QQ', 0, len(iv0)<<3), hashv)
            icb = int2bytes(hashv, 16)

        lenf = pack('>QQ', len(aad)<<3, len(data)<<3)
        hashv = GHash.ghash_imp(keyint, aad, 0)
        hashv = GHash.ghash_imp(keyint, data, hashv)
        hashv = GHash.ghash_imp(keyint, lenf, hashv)
        block = int2bytes(hashv, 16)
        enicb = SM4._encrypt(enc_key, icb)
        tag1 = xor128(enicb, block)
        if tag1[:len(tag)] != tag:
            raise SM4Error('Tag mismatching.')
        return SM4._gctr(enc_key, data, SM4._ctr_counter_incr(icb, 4))

    def encrypt_ccm(self, data, iv0, aad, tlen=16):
        ''' SM4-CCM encryption '''
        if not 4 <= tlen <= 16 or tlen & 1:
            raise SM4Error('The tlen must be an even number between 4 and 16.')
        if not 7 <= len(iv0) <= 13:
            raise SM4Error('The iv0 must have length from 7 to 13 bytes.')
        if self.FAST:
            return encrypt_ccm(self.key, data, iv0, aad, tlen)

        llen = 15 - len(iv0)
        icb = pack('B15s', llen-1, iv0)
        enc_key = SM4._key_extend(self.key)
        enicb = SM4._encrypt(enc_key, icb)
        tag = SM4._gen_cbc_mac(enc_key, data, iv0, aad, tlen)
        data = SM4._gctr(enc_key, data, SM4._ctr_counter_incr(icb, llen))
        tag = xor128(tag, enicb)
        return data, tag[:tlen]

    def decrypt_ccm(self, data, iv0, aad, tag):
        ''' SM4-CCM decryption '''
        tlen = len(tag)
        if not 4 <= tlen <= 16 or tlen & 1:
            raise SM4Error('The tag must have an even number of bytes between 4 and 16.')
        if not 7 <= len(iv0) <= 13:
            raise SM4Error('The iv0 must have length from 7 to 13 bytes.')
        if self.FAST:
            return decrypt_ccm(self.key, data, iv0, aad, tag)

        llen = 15 - len(iv0)
        icb = pack('B15s', llen-1, iv0)
        enc_key = SM4._key_extend(self.key)
        enicb = SM4._encrypt(enc_key, icb)
        data = SM4._gctr(enc_key, data, SM4._ctr_counter_incr(icb, llen))
        tag1 = SM4._gen_cbc_mac(enc_key, data, iv0, aad, tlen)
        tag1 = xor128(tag1, enicb)
        if tag1[:len(tag)] != tag:
            raise SM4Error('Tag mismatching.')
        return data

    @staticmethod
    def _gen_cbc_mac(enc_key, data, iv0, aad, tlen):
        ''' https://www.rfc-editor.org/rfc/rfc3610 2.2 '''
        fllen = 15 - len(iv0)  # length of data length in flags
        datalen = len(data)
        if datalen >= 1 << fllen*8:
            raise SM4Error('The data or iv0 is too long.')

        aadlen = len(aad)        # aad length
        ftlen = (tlen - 2) >> 1  # tag length in flags (first byte of block 0)
        blk = pack('B', (bool(aadlen) << 6) | (ftlen << 3) | (fllen-1))
        blk += iv0 + int2bytes(datalen, fllen)
        tag = SM4._encrypt(enc_key, blk)

        if aadlen:
            if aadlen < 65280:  # 2^16 - 2^8
                allen = pack('>H', aadlen)           # encoded aad length
            elif aadlen < 4294967296:  # 2^32
                allen = pack('>HI', 0xFFFE, aadlen)  # encoded aad length
            else:   # 2^32 to 2^64
                allen = pack('>HQ', 0xFFFF, aadlen)  # encoded aad length
            blk = allen + aad[:16-len(allen)]        # block 1 with aad
            tag = SM4._encrypt(enc_key, xor128(tag, blk))
            len16 = aadlen - ((aadlen+len(allen)) & 15)
            for pos in range(16-len(allen), len16, 16):
                tag = SM4._encrypt(enc_key, xor128(tag, aad, 0, pos))
            if len16 < aadlen:
                tag = SM4._encrypt(enc_key, xor128(tag, aad[len16:].ljust(16, b'\0')))

        if datalen > 0:
            len16 = datalen - (datalen & 15)
            for pos in range(0, len16, 16):
                tag = SM4._encrypt(enc_key, xor128(tag, data, 0, pos))
            if len16 < datalen:
                tag = SM4._encrypt(enc_key, xor128(tag, data[len16:].ljust(16, b'\0')))

        return tag[:tlen]

    @staticmethod
    def pkcs7(data):
        ''' PKCS7 padding '''
        padlen = 16 - (len(data) & 15)
        return data.ljust(16, pack('B', padlen))

    @staticmethod
    def unpkcs7(data):
        ''' PKCS7 unpadding '''
        padlen = data[-1]
        if padlen > 16 or padlen > len(data):
            raise SM4Error('Decrypt error: Invalid pad bytes.')
        padbytes = pack('B', padlen) * padlen
        if data[-padlen:] != padbytes:
            raise SM4Error('Decrypt error: Invalid pad bytes.')
        return data[:-padlen]

    @staticmethod
    def _t(a_32):
        ''' 合成置换: 由非线性变换τ和线性变换L复合而成 '''
        # 非线性变换τ: bi = SBox(ai)
        b_32 = _BOXES_TABLE[a_32 >> 24] << 24 | _BOXES_TABLE[a_32 >> 16 & 255] << 16 | \
               _BOXES_TABLE[a_32 >> 8 & 255] << 8 | _BOXES_TABLE[a_32 & 255]
        # 线性变换L: L(b) = b⊕(b<<<2)⊕(b<<<10)⊕(b<<<18)⊕(b<<<24)
        return b_32 ^ rotl(b_32, 2) ^ rotl(b_32, 10) ^ rotl(b_32, 18) ^ rotl(b_32, 24)

    @staticmethod
    def _t1(a_32):
        ''' 合成置换T', 用于密钥扩展 '''
        # 非线性变换τ: bi = SBox(ai)
        b_32 = _BOXES_TABLE[a_32 >> 24] << 24 | _BOXES_TABLE[a_32 >> 16 & 255] << 16 | \
               _BOXES_TABLE[a_32 >> 8 & 255] << 8 | _BOXES_TABLE[a_32 & 255]
        # 线性变换L': L'(b) = b⊕(b<<<13)⊕(b<<<23)
        return b_32 ^ rotl(b_32, 13) ^ rotl(b_32, 23)

    @staticmethod
    def _ctr_counter_incr(counter, csize=16):
        if not isinstance(counter, bytearray):
            counter = bytearray(counter)
        for i in range(15, 15 - csize, -1):
            counter[i] = (counter[i] + 1) & 255
            if counter[i]:
                break
        return counter

    @staticmethod
    def _gctr(enc_key, data, gtr):
        output = bytearray()
        datalen = len(data)
        len16 = datalen - (datalen & 15)
        for pos in range(0, len16, 16):
            engtr = SM4._encrypt(enc_key, gtr)
            output.extend(xor128(engtr, data, 0, pos))
            gtr = SM4._ctr_counter_incr(gtr, 4)
        if len16 < datalen:
            engtr = SM4._encrypt(enc_key, gtr)
            output.extend(bitxor(engtr, data[len16:]))
        return output

    @staticmethod
    def _key_extend(key, encrypt=True):
        ''' SM4 key extend '''
        m_k = list(unpack('>4I', key))
        m_k[0] ^= _FK[0]
        m_k[1] ^= _FK[1]
        m_k[2] ^= _FK[2]
        m_k[3] ^= _FK[3]
        t_k = [m_k[0] ^ SM4._t1(m_k[1] ^ m_k[2] ^ m_k[3] ^ _CK[0])]
        t_k.append(m_k[1] ^ SM4._t1(m_k[2] ^ m_k[3] ^ t_k[0] ^ _CK[1]))
        t_k.append(m_k[2] ^ SM4._t1(m_k[3] ^ t_k[0] ^ t_k[1] ^ _CK[2]))
        t_k.append(m_k[3] ^ SM4._t1(t_k[0] ^ t_k[1] ^ t_k[2] ^ _CK[3]))
        t_k.extend(
            t_k[i-4] ^ SM4._t1(t_k[i-3] ^ t_k[i-2] ^ t_k[i-1] ^ _CK[i]) for i in range(4, 32)
        )
        return t_k if encrypt else t_k[::-1]

    @staticmethod
    def _encrypt(skey, data, offset=0):
        ''' encrypt/decrypt one group '''
        ulbuf = list(unpack_from('>4I', data, offset))
        for i in range(32):
            # 轮函数: F(x0,x1,x2,x3,rk) = x0⊕T(x1⊕x2⊕x3⊕rk)
            ulbuf.append(ulbuf[i] ^ SM4._t(ulbuf[i+1] ^ ulbuf[i+2] ^ ulbuf[i+3] ^ skey[i]))
        return pack('>4I', ulbuf[35], ulbuf[34], ulbuf[33], ulbuf[32])


def rotl(value, cnt):
    ''' 32bits left shift '''
    return value << cnt & 0xFFFFFFFF | value >> (32 - cnt)

def bitxor(data1, data2):
    ''' Xor Byte to Byte '''
    return bytes(a ^ b for a, b in zip(data1, data2))

def xor128(data1, data2, offset1=0, offset2=0):
    ''' 128 bits xor '''
    idata1 = unpack_from('QQ', data1, offset1)
    idata2 = unpack_from('QQ', data2, offset2)
    return pack('QQ', idata1[0] ^ idata2[0], idata1[1] ^ idata2[1])

def int2bytes(value, length):
    ''' Convert Integer to Bytes '''
    return value.to_bytes(length, 'big')

def bytes2int(bytestr):
    ''' Convert Bytes to Integer '''
    return int.from_bytes(bytestr, 'big')
