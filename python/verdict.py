#!/usr/bin/env python

import binascii
import random

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from elgamal import PublicKey, PrivateKey
import schnorr

class Verdict:
    def __init__(self, key, public_keys):
        self.group = key.group
        self.key = key.secret
        self.public_keys = [key.element for key in public_keys]

        self.shared_secret = 0
        self.index = -1
        for idx in range(len(self.public_keys)):
            ks = self.public_keys[idx]
            if self.index == -1 and ks == key.element:
                self.index = idx
                continue
            multi = 1 if self.index == -1 else -1
            add = -1 if self.index == -1 else 0
            self.shared_secret = (self.shared_secret + (pow(ks, self.key, self.group.p) * multi) % self.group.p + add) % self.group.q
        assert self.index != -1
        self.secret_commit = pow(self.group.g, self.shared_secret, self.group.p)

    def key_count(self):
        return len(self.public_keys)

    def set_commitments(self, commitments):
        self.commitments = commitments
        assert len(self.commitments) == len(self.public_keys)

    def challenge(self, generator, ciphertext, index):
        return self._challenge(generator, ciphertext, index)

    def owner_challenge(self, generator, ciphertext):
        return self._challenge(generator, ciphertext, self.index)

    def generate_ciphertext(self, generator, data = None):
        if data == None:
            data = 1
        else:
            data = self.group.encode(data)
        return self.group.add(data, self.group.multiply(self.group.generator(), self.shared_secret))

    def _challenge(self, generator, ciphertext, index):
        assert False

    def verify(self, generator, ciphertext, proof, data_index, user_index):
        assert False

def main():
    count = 10
    group = schnorr.verdict_1024()
    slot_index = random.randrange(0, count)
    keys = []
    pkeys = []
    for idx in range(count):
        k = PrivateKey(group)
        keys.append(k)
        pkeys.append(k.public_key())

    verdicts = []
    commitments = []
    for idx in range(count):
        verdicts.append(Verdict(keys[idx], pkeys))
        commitments.append(verdicts[-1].secret_commit)

    for verdict in verdicts:
        verdict.set_commitments(commitments)

    msg = bytes("hello world", "UTF-8")
    h = SHA256.new()
    h.update(msg)
    generator = pow(group.g, bytes_to_long(h.digest()), group.p)

    ciphertexts = []
    proofs = []

    for idx in range(count):
        if idx == slot_index:
            ciphertexts.append(verdicts[idx].generate_ciphertext(generator, msg))
#            proofs.append(verdicts[idx].owner_challenge(generator, ciphertexts[-1]))
        else:
            ciphertexts.append(verdicts[idx].generate_ciphertext(generator))
#            proofs.append(verdicts[idx].challenge(generator, ciphertexts[-1], slot_index))

#    for idx in range(count):
#        assert verdicts[0].verify(generator, ciphertexts[idx], proofs[idx], slot_index, idx) == True
    cleartext = 1
    for ciphertext in ciphertexts:
        cleartext = (cleartext * ciphertext) % group.p
    print(group.decode(cleartext))

if __name__ == "__main__":
    main()
