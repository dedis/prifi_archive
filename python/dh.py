#!/usr/bin/env python

import binascii
import random

from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

def _s2l(s):
    s = bytes("".join(s.split()), "UTF-8")
    s = binascii.a2b_hex(s)
    return bytes_to_long(s)

g = _s2l("A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F"
    "D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213"
    "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1"
    "909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A"
    "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24"
    "855E6EEB 22B3B2E5")
p = _s2l("B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6"
    "9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0"
    "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70"
    "98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0"
    "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708"
    "DF1FB2BC 2E4A4371")
q = _s2l("F518AA87 81A8DF27 8ABA4E7D 64B7CB9D 49462353")

class PublicKey:
    def __init__(self, y, g = g, p = p, q = q):
        self.g = g
        self.p = p
        self.q = q
        self.y = y
        self.dsa = self._gen_dsa()

    def _gen_dsa(self):
        return DSA.construct((self.y, self.g, self.p, self.q))

    def exchange(self, priv):
        return pow(self.y, priv.x, self.p)

    def verify(self, msg, sig):
        h = SHA256.new()
        h.update(msg)
        msg = h.digest()
        return self.dsa.verify(msg, sig)

    def has_private(self):
        return False

class PrivateKey(PublicKey):
    def __init__(self, g = g, p = p, q = q, x = None):
        self.x = x
        if x == None:
            self.x = random.randrange(1 << (q.bit_length() - 1), q - 1)

        y = pow(g, self.x, p)
        PublicKey.__init__(self, y, g, p, q)
        self.pubkey = PublicKey(self.y, g, p, q)

    def _gen_dsa(self):
        return DSA.construct((self.y, self.g, self.p, self.q, self.x))

    def sign(self, msg):
        h = SHA256.new()
        h.update(msg)
        msg = h.digest()
        k = random.randrange(1 << (self.q.bit_length() - 1), self.q - 1)
        return self.dsa.sign(msg, k)

    def exchange(self, pub):
        return pow(pub.y, self.x, self.p)

    def has_private(self):
        return True

def main():
    dh0 = PrivateKey()
    pdh0 = dh0.pubkey
    dh1 = PrivateKey()
    pdh1 = dh1.pubkey

    assert dh0.exchange(pdh1) == dh1.exchange(pdh0)
    data = long_to_bytes(dh1.y)
    assert pdh0.verify(data, dh0.sign(data))

if __name__ == "__main__":
    main()
