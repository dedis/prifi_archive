#!/usr/bin/env python
import random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

import verdict

class EncryptedBase:
    def __init__(self):
        h = SHA256.new()
        self.counter = 0
        self.cleartext_to_generator([[]])

    def cleartext_to_generator(self, cleartext):
        h = SHA256.new()

        h.update(long_to_bytes(self.counter))
        for layer1 in cleartext:
            for layer2 in layer1:
                h.update(layer2)

        self.hdata = bytes_to_long(h.digest())
        self.counter += 1

class EncryptedAccumulator(EncryptedBase):
    def __init__(self, verifier):
        EncryptedBase.__init__(self)
        self.verifier = verifier

    def before(self, ciphertexts):
        generator = self.verifier.group.multiply( \
                self.verifier.group.generator(), \
                self.hdata % self.verifier.group.order())

        base = self.verifier.generate_ciphertext(generator)

        nciphertexts = [ciphertext[0] for ciphertext in ciphertexts]
        for sdx in range(len(nciphertexts)):
            shared = base
            for idx in range(len(ciphertexts)):
                if idx == sdx:
                    continue
                shared = self.verifier.group.add(shared, ciphertexts[idx][1][0])
            pseed = self.verifier.group.add(shared, ciphertexts[sdx][1][1])
            seed = self.verifier.group.decode(pseed)
            aes = AES.new(seed, AES.MODE_CTR, counter = Counter.new(128))
            for ndx in nciphertexts[sdx].keys():
                for cdx in range(len(nciphertexts[sdx][ndx])):
                    nciphertexts[sdx][ndx][cdx] = aes.decrypt(nciphertexts[sdx][ndx][cdx])

        return nciphertexts

    def after(self, cleartexts):
        self.cleartext_to_generator(cleartexts)
        return cleartexts

class EncryptedCertifier(EncryptedBase):
    def __init__(self, verifier):
        EncryptedBase.__init__(self)
        self.verifier = verifier
        self.seed_min = 2**121
        self.seed_max = 2**128

    def certify(self, ciphertexts):
        generator = self.verifier.group.multiply( \
                self.verifier.group.generator(), \
                self.hdata % self.verifier.group.order())
                
        other = self.verifier.generate_ciphertext(generator)
        seed = random.randrange(self.seed_min, self.seed_max)
        own = self.verifier.generate_ciphertext(generator, seed)

        aes = AES.new(long_to_bytes(seed), AES.MODE_CTR, counter = Counter.new(128))
        for ndx in ciphertexts.keys():
            for cdx in range(len(ciphertexts[ndx])):
                ciphertexts[ndx][cdx] = aes.encrypt(ciphertexts[ndx][cdx])
        return (ciphertexts, (other, own))

    def verify(self, cleartexts):
        self.cleartext_to_generator(cleartexts)
        return cleartexts
