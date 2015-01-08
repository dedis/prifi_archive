#!/usr/bin/env python

from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, GCD

class ElGamal:
    def _hash(self, data, bits):
        limit = bits // 8 + 0 if bits % 8 == 0 else 1
        h = SHA256.new()
        h.update(data)
        return bytes_to_long(h.digest()[0:limit])

    def encrypt(self, element, data):
        y = self.random_secret()
        c1 = self.multiply(self.generator(), y)
        s = self.multiply(element, y)
        de = self.encode(data)
        c2 = self.add(de, s)
        return (c1, c2)

    def decrypt(self, secret, encrypted):
        c1, c2 = encrypted
        s = self.multiply(c1, secret)
        de = self.add(c2, self.inverse(s))
        return self.decode(de)

class PublicKey:
    def __init__(self, group, element):
        self.group = group
        self.element = element

    def exchange(self, private):
        return self.group.multiply(self.element, private.secret)

    def verify(self, data, sign):
        return self.group.verify(self.element, data, sign)

    def encrypt(self, data):
        return self.group.encrypt(self.element, data)

class PrivateKey(PublicKey):
    def __init__(self, group, secret = None):
        if secret == None:
            secret = group.random_secret()
        element = group.multiply(group.generator(), secret)
        PublicKey.__init__(self, group, element)
        self.secret = secret

    def exchange(self, public):
        return self.group.multiply(public.element, self.secret)

    def sign(self, data):
        return self.group.sign(self.secret, data)

    def decrypt(self, encrypted):
        return self.group.decrypt(self.secret, encrypted)

    def public_key(self):
        return PublicKey(self.group, self.element)
