#!/usr/bin/env python

import binascii
import random

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from dh import PrivateKey, PublicKey

def _s2l(s):
    s = bytes("".join(s.split()), "UTF-8")
    s = binascii.a2b_hex(s)
    return bytes_to_long(s)

p = _s2l("fd8a16fc2afdaeb2ea62b66b355f73e6c2fc4349bf4551793"
    "36ca1b45f75d68da0101cba63c22efd5f72e5c81dc30cf709da"
    "aef2323e950160926e11ef8cbf40a26496668749218b5620276"
    "697c2d1536b31042ad846e1e5758d79b3e4e0b5bc4c5d3a4e95"
    "da4502e9058ea3beade156d8234e35d5164783c57e6135139db"
    "097")

g = _s2l("02")

q = (p - 1) // 2

def rand_in_q():
    return random.randrange(1 << (q.bit_length() - 1), q - 1)

def gen_key():
    return rand_in_q()

class Verdict:
    def __init__(self, key, public_keys):
        self.key = key
        self.public_keys = public_keys
        self.shared_secret = 1
        self.index = -1
        for idx in range(len(self.public_keys)):
            ks = self.public_keys[idx].y
            self.shared_secret = (self.shared_secret * ks) % p
            if ks == self.key.y:
                self.index = idx
        assert self.index != -1
        self.shared_secret = pow(self.shared_secret, self.key.x, p)
        self.secret_commit = pow(g, self.shared_secret, p)

    def set_commitments(self, commitments):
        self.commitments = commitments
        assert len(self.commitments) == len(self.public_keys)

    def challenge(self, generator, ciphertext, index):
        return self._challenge(generator, ciphertext, index)

    def owner_challenge(self, generator, ciphertext):
        return self._challenge(generator, ciphertext, self.index)

    def generate_ciphertext(self, generator, data = 1):
        return data * pow(generator, self.shared_secret, p)

    def _challenge(self, generator, ciphertext, index):
        data_key = self.public_keys[index].y

        v1 = rand_in_q()
        v2 = rand_in_q()
        w = rand_in_q()
        commitment = self.secret_commit

        if self.index == index:
            t1 = (pow(commitment, w, p) * pow(g, v1, p)) % p
            t2 = (pow(ciphertext, w, p) * pow(generator, v1, p)) % p
            t3 = pow(data_key, -w % q, p)
        else:
            t1 = pow(g, v1, p)
            t2 = pow(generator, v1, p)
            t3 = (pow(data_key, w, p) * pow(g, v2, p)) % p

        h = SHA256.new()
        h.update(long_to_bytes(g))
        h.update(long_to_bytes(generator))
        h.update(long_to_bytes(g))
        h.update(long_to_bytes(self.secret_commit))
        h.update(long_to_bytes(ciphertext))
        h.update(long_to_bytes(data_key))
        h.update(long_to_bytes(t1))
        h.update(long_to_bytes(t2))
        h.update(long_to_bytes(t3))
        d = bytes_to_long(h.digest())

        c1 = (d - w) % q
        c2 = w
        if self.index == index:
            r1 = -(self.key.x * d) % q
        else:
            r1 = (v1 - c1 * self.shared_secret) % q
        r2 = v2

        if self.index == index:
            return (c2, c1, v1, r1)
        return (c1, c2, r1, r2)

    def verify(self, generator, ciphertext, proof, data_index, user_index):
        c1, c2, r1, r2 = proof
        commitment = self.commitments[user_index]
        data_key = self.public_keys[data_index].y

        t1 = (pow(commitment, c1, p) * pow(g, r1, p)) % p
        t2 = (pow(ciphertext, c1, p) * pow(generator, r1, p)) % p
        t3 = (pow(data_key, c2, p) * pow(g, r2, p)) % p

        h = SHA256.new()
        h.update(long_to_bytes(g))
        h.update(long_to_bytes(generator))
        h.update(long_to_bytes(g))
        h.update(long_to_bytes(commitment))
        h.update(long_to_bytes(ciphertext))
        h.update(long_to_bytes(data_key))
        h.update(long_to_bytes(t1))
        h.update(long_to_bytes(t2))
        h.update(long_to_bytes(t3))
        return (c1 + c2) % q == bytes_to_long(h.digest())

def main():
    count = 10
    slot_index = random.randrange(0, count)
    keys = []
    pkeys = []
    for idx in range(count):
        k = PrivateKey(g, p, q)
        keys.append(k)
        pkeys.append(k.pubkey)

    verdicts = []
    commitments = []
    for idx in range(count):
        verdicts.append(Verdict(keys[idx], pkeys))
        commitments.append(verdicts[-1].secret_commit)

    for verdict in verdicts:
        verdict.set_commitments(commitments)

    msg = bytes("hello world", "UTF-8")
    msgi = bytes_to_long(msg)
    h = SHA256.new()
    h.update(msg)
    generator = pow(g, bytes_to_long(h.digest()), p)

    ciphertexts = []
    proofs = []

    for idx in range(count):
        if idx == slot_index:
            ciphertexts.append(verdicts[slot_index].generate_ciphertext(generator, msgi))
            proofs.append(verdicts[slot_index].owner_challenge(generator, ciphertexts[-1]))
        else:
            ciphertexts.append(verdicts[idx].generate_ciphertext(generator))
            proofs.append(verdicts[idx].challenge(generator, ciphertexts[-1], slot_index))

    for idx in range(count):
        assert verdicts[0].verify(generator, ciphertexts[idx], proofs[idx], slot_index, idx) == True

if __name__ == "__main__":
    main()
