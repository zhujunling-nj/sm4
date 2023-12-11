# SM4

国家商用密码算法SM4，采用纯Python（不依赖其它第三方模块）与C扩展实现（纯Python也可以执行，但通过C扩展可以提升性能）。

## 主要功能

* SM4加密与解密。
* 支持 ECB、CBC、GTR、GCM、CCM分组模式。

## 安装方法
1. 执行 pip3 wheel . 构建版本包；
2. 执行 pip install sm4-x.x.x-cpxxx-cpxxx-xxx.whl 安装

## 使用样例
```
from os import urandom
from sm4 import SM4

key = urandom(16)
iv1 = urandom(16)
iv2 = urandom(12)
aad = urandom(32)

sm4 = SM4(key)
data = 'SM4加解密测试'.encode()

# ECB 模式
ciphertext = sm4.encrypt_ecb(data)
print('ECB CipherText:', ciphertext.hex())
print('PlainText:', sm4.decrypt_ecb(ciphertext).decode())
print()

# CBC 模式
ciphertext = sm4.encrypt_cbc(data, iv1)
print('CBC CipherText:', ciphertext.hex())
print('PlainText:', sm4.decrypt_cbc(ciphertext, iv1).decode())
print()

# CTR 模式
ciphertext = sm4.encrypt_ctr(data, iv2)
print('CTR CipherText:', ciphertext.hex())
# CTR 模式没有解密函数, 对密文再次加密就是解密
print('PlainText:', sm4.encrypt_ctr(ciphertext, iv2).decode())
print()

# GCM 模式
ciphertext, tag = sm4.encrypt_gcm(data, iv2, aad)
print('GCM CipherText:', ciphertext.hex())
print('GCM Tag:', tag.hex())
print('PlainText:', sm4.decrypt_gcm(ciphertext, iv2, aad, tag).decode())
print()

# CCM 模式
ciphertext, tag = sm4.encrypt_ccm(data, iv2, aad)
print('CCM CipherText:', ciphertext.hex())
print('CCM Tag:', tag.hex())
print('PlainText:', sm4.decrypt_ccm(ciphertext, iv2, aad, tag).decode())

```