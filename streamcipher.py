#!/usr/bin/env python
#-*- coding: UTF-8 -*-

# Copyright (c) 2014 v3aqb
# License: GPLv2+

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class StreamCipher(object):
    def __init__(self, method, key, iv, mode):
        self.method = method
        self.key = key
        self.iv = iv
        self.iv_len = len(iv)
        self.cipher = self.get_cipher().encryptor() if mode else self.get_cipher().decryptor()
        self.update = self.cipher.update

    def get_cipher(self):
        if self.method.startswith('aes'):
            return Cipher(algorithms.AES(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('bf'):
            return Cipher(algorithms.Blowfish(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('camellia'):
            return Cipher(algorithms.Camellia(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('cast5'):
            return Cipher(algorithms.CAST5(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('seed'):
            return Cipher(algorithms.SEED(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('idea'):
            return Cipher(algorithms.IDEA(self.key), modes.CFB(self.iv), default_backend())
        if self.method.startswith('rc4'):
            return Cipher(algorithms.ARC4(self.key), None, default_backend())
        raise ValueError('crypto method %s not supported!' % self.method)


def main():
    key = b"_M\xcc;Z\xa7e\xd6\x1d\x83'\xde\xb8\x82\xcf\x99+\x95\x99\n\x91Q7J\xbd\x8f\xf8\xc5\xa7\xa0\xfe\x08"
    iv = b'\xb7\xb47,\xdf\xbc\xb3\xd1j&1\xb5\x9bP\x9e\x94'
    method = 'aes_256_cfb'
    cipher = StreamCipher(method, key, iv, 1)
    decipher = StreamCipher(method, key, iv, 0)
    a = cipher.update(b'a long test string')
    b = cipher.update(b'a long test string')
    c = decipher.update(a)
    d = decipher.update(b)
    print(b == b'\xc9\xc1h\xe4u\x9b\xa7\x94\x0c\xa6 \xbf\xc7au\xb10\x8a')
    print(repr(a))
    print(repr(b))
    print(repr(c))
    print(repr(d))
    print('encrypt and decrypt 2MB data')
    s = os.urandom(1000)
    import time
    t = time.time()
    for _ in range(1049):
        a = cipher.update(s)
        b = cipher.update(s)
        c = decipher.update(a)
        d = decipher.update(b)
    print('StreamCipher %ss' % (time.time() - t))
    import M2Crypto.EVP
    cipher = M2Crypto.EVP.Cipher(method, key, iv, 1)
    decipher = M2Crypto.EVP.Cipher(method, key, iv, 0)
    t = time.time()
    for _ in range(1049):
        a = cipher.update(s)
        b = cipher.update(s)
        c = decipher.update(a)
        d = decipher.update(b)
    print('M2Crypto %ss' % (time.time() - t))

if __name__ == "__main__":
    main()
