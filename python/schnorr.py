#!/usr/bin/env python

import random

from elgamal import ElGamal
from Crypto.Util.number import bytes_to_long, GCD, inverse, long_to_bytes

from utils import string_to_long

def verdict_1024():
    p = string_to_long("fd8a16fc2afdaeb2ea62b66b355f73e6c2fc4349bf4551793"
        "36ca1b45f75d68da0101cba63c22efd5f72e5c81dc30cf709da"
        "aef2323e950160926e11ef8cbf40a26496668749218b5620276"
        "697c2d1536b31042ad846e1e5758d79b3e4e0b5bc4c5d3a4e95"
        "da4502e9058ea3beade156d8234e35d5164783c57e6135139db"
        "097")
    g = 2
    q = (p - 1) // 2
    r = 2
    return SchnorrGroup(p, g, q, r)

def diffiehellman_1024():
    g = string_to_long("A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F"
        "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213"
        "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1"
        "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A"
        "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24"
        "855E6EEB 22B3B2E5")
    p = string_to_long("B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6"
        "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0"
        "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70"
        "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0"
        "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708"
        "DF1FB2BC 2E4A4371")
    q = string_to_long("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353")
    r = 2
    return SchnorrGroup(p, g, q, r)

class SchnorrGroup(ElGamal):
    def __init__(self, p, g, q, r):
        self.p = p
        self.q = q
        self.g = g
        self.r = r

    def generator(self):
        return self.g

    def order(self):
        return self.q

    def zero(self):
        return 0

    def identity(self):
        return 1

    def is_element(self, a):
        return pow(a, self.q, self.p) == 1

    def is_generator(self, a):
        return self.is_element(a) and \
                (pow(a, self.r, self.p) == 1)

    def random_secret(self):
        return random.randrange(1 << (self.q.bit_length() - 1), self.q - 1)

    def random_element(self):
        return self.multiply(self.generator(), self.random_secret())

    def add(self, a, b):
        return (a * b) % self.p

    def multiply(self, a, b):
        return pow(a, b, self.p)

    def inverse(self, a):
        return inverse(a, self.p)

    def bytes(self, a):
        return long_to_bytes(a)

    def element(self, a):
        return bytes_to_long(a)

    def encode(self, data):
        if isinstance(data, int):
            data = long_to_bytes(data)
        tmp_data = bytearray(b'\xff' + data + b'0\xff')
        
        pad = 0
        while pad < 256:
            element = bytes_to_long(tmp_data)
            if self.is_element(element):
                break
            pad += 1
            tmp_data[-2] = pad

        assert pad != 256

        return element

    def decode(self, a):
        data = long_to_bytes(a)
        assert data[0] == 0xff and data[-1] == 0xff
        return data[1:-2]

    def sign(self, secret, data):
        p1 = self.p - 1
        while True:
            k = random.randrange(1 << (p1.bit_length() - 1), p1)
            if GCD(k, p1) == 1:
                break
        r = self.multiply(self.generator(), k)
        k_inv = inverse(k, p1)
        s = ((self._hash(data, p1) - secret * r) * k_inv) % p1
        return (r, s)

    def verify(self, element, data, sign):
        if sign[0] < 1 or sign[0] > self.p - 1:
            return False
        if sign[1] < 1 or sign[1] > self.p - 1:
            return False
        v1 = self.add(self.multiply(element, sign[0]),
                self.multiply(sign[0], sign[1]))
        v2 = self.multiply(self.generator(), self._hash(data, self.p - 1))
        return v1 == v2

def main():
    group = verdict_1024()
    from elgamal import PrivateKey, PublicKey
    x0 = PrivateKey(group)
    y0 = x0.public_key()
    x1 = PrivateKey(group)
    y1 = x1.public_key()

    assert x0.exchange(y1) == y1.exchange(x0)

    data = b"hello"
    encrypted = y0.encrypt(data)
    assert x0.decrypt(encrypted) == data

    assert y0.verify(data, x0.sign(data))

if __name__ == "__main__":
    main()
