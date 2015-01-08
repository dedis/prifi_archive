#!/usr/bin/env python

import random
import unittest

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

import schnorr
from elgamal import PublicKey, PrivateKey

class BaseVerdict:
    def __init__(self, client_keys, trustee_keys):
        self.group = trustee_keys[0].group
        self.client_keys = client_keys
        self.trustee_keys = trustee_keys

    def generate_ciphertext(self, generator, data = None):
        encrypted = self.group.multiply(generator, self._shared_secret)
        if data != None:
            data = self.group.encode(data)
            encrypted = self.group.add(data, encrypted)
        return encrypted

    def set_commitments(self, client_commitments, trustee_commitments):
        assert len(client_commitments) == len(self.client_keys)
        assert len(trustee_commitments) == len(self.trustee_keys)
        self.ccommit = client_commitments
        self.tcommit = trustee_commitments

    def commitment(self):
        return self.secret_commit

class TrusteeVerdict(BaseVerdict):
    def __init__(self, ss_or_key, client_keys, trustee_keys, ss = False):
        BaseVerdict.__init__(self, client_keys, trustee_keys)

        if ss:
            self._shared_secret = ss_or_key
        else:
            self._shared_secret = self.group.zero()
            for idx in range(len(client_keys)):
                self._shared_secret = (self._shared_secret - ss_or_key.exchange(client_keys[idx])) % self.group.q
        self.secret_commit = self.group.multiply(self.group.generator(), self._shared_secret)

    def shared_secret(self):
        return self._shared_secret


class ClientVerdict(BaseVerdict):
    def __init__(self, key, client_keys, trustee_keys):
        BaseVerdict.__init__(self, client_keys, trustee_keys)

        self._shared_secret = self.group.zero()
        index = -1
        for idx in range(len(trustee_keys)):
            ks = trustee_keys[idx]
            if index == -1 and ks == key.element:
                index = idx
                continue
            self._shared_secret = (self._shared_secret + key.exchange(trustee_keys[idx])) % self.group.q
        self.secret_commit = self.group.multiply(self.group.generator(), self._shared_secret)

class Test(unittest.TestCase):
    def test_basic(self):
        group = schnorr.verdict_1024()
        self.basic(group)

    def gen_keys(self, group, count):
        keys = []
        pkeys = []

        for idx in range(count):
            k = PrivateKey(group)
            keys.append(k)
            pkeys.append(k.public_key())

        return (keys, pkeys)

    def setup(self, group, clients, trustees):
        ckeys, cpkeys = self.gen_keys(group, clients)
        tkeys, tpkeys = self.gen_keys(group, trustees)

        cverdicts = []
        ccommitments = []

        for idx in range(clients):
            cverdicts.append(ClientVerdict(ckeys[idx], cpkeys, tpkeys))
            ccommitments.append(cverdicts[-1].commitment())

        tverdicts = []
        tcommitments = []

        for idx in range(trustees):
            tverdicts.append(TrusteeVerdict(tkeys[idx], cpkeys, tpkeys))
            tcommitments.append(tverdicts[-1].commitment())

        for verdict in cverdicts:
            verdict.set_commitments(ccommitments, tcommitments)

        for verdict in tverdicts:
            verdict.set_commitments(ccommitments, tcommitments)

        return (cverdicts, tverdicts)

    def basic(self, group):
        trustees = 3
        clients = 10
        owner_idx = random.randrange(0, clients)

        cverdicts, tverdicts = self.setup(group, clients, trustees)

        msg = bytes("hello world", "UTF-8")
        h = SHA256.new()
        h.update(msg)
        generator = pow(group.g, bytes_to_long(h.digest()), group.p)

        cciphertexts = []
        cproofs = []

        for idx in range(clients):
            if idx == owner_idx:
                cciphertexts.append(cverdicts[idx].generate_ciphertext(generator, msg))
            else:
                cciphertexts.append(cverdicts[idx].generate_ciphertext(generator))

        tciphertexts = []
        for idx in range(trustees):
            tciphertexts.append(tverdicts[idx].generate_ciphertext(generator))

        cleartext = group.identity()
        for ciphertext in tciphertexts:
            cleartext = group.add(cleartext, ciphertext)

        for ciphertext in cciphertexts:
            cleartext = group.add(cleartext, ciphertext)

        self.assertEqual(msg, group.decode(cleartext))

if __name__ == "__main__":
    unittest.main()
