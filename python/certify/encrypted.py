#!/usr/bin/env python
import random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

import verdict

class EncryptedAccumulator:
    def __init__(self, group):
        self.group = group

    def before(self, ciphertexts):
        nciphertexts = [ciphertext[0] for ciphertext in ciphertexts]
        for sdx in range(len(nciphertexts)):
            shared = self.group.identity()
            for idx in range(len(ciphertexts)):
                if idx == sdx:
                    continue
                shared = self.group.add(shared, ciphertexts[idx][1][0])
            seed = self.group.decode(self.group.add(shared, ciphertexts[sdx][1][1]))
            aes = AES.new(seed, AES.MODE_CTR, counter = Counter.new(128))
            for ndx in range(len(nciphertexts[sdx])):
                for cdx in range(len(nciphertexts[sdx][ndx])):
                    nciphertexts[sdx][ndx][cdx] = aes.decrypt(nciphertexts[sdx][ndx][cdx])

        return nciphertexts

    def after(self, cleartexts):
        return cleartexts

class EncryptedCertifier:
    def __init__(self, verifier):
        self.verifier = verifier
        h = SHA256.new()
        self.hdata = bytes_to_long(h.digest())

    def certify(self, ciphertexts):
        generator = pow(self.verifier.group.g, self.hdata % self.verifier.group.q, self.verifier.group.p)
        other = self.verifier.generate_ciphertext(generator)
        seed = random.getrandbits(128)
        own = self.verifier.generate_ciphertext(generator, seed)

        aes = AES.new(long_to_bytes(seed), AES.MODE_CTR, counter = Counter.new(128))
        for ndx in range(len(ciphertexts)):
            for cdx in range(len(ciphertexts[ndx])):
                ciphertexts[ndx][cdx] = aes.encrypt(ciphertexts[ndx][cdx])
        return (ciphertexts, (other, own))

    def verify(self, cleartexts):
        return cleartexts
