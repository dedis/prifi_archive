#!/usr/bin/env python

import random
import unittest

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

import schnorr
from elgamal import PublicKey, PrivateKey

class VerdictBase:
    def __init__(self, anon_key, client_keys, trustee_keys):
        self.group = trustee_keys[0].group
        self.anon_key = anon_key
        self.client_keys = client_keys
        self.trustee_keys = trustee_keys

    def generate_ciphertext(self, generator, data = None):
        encrypted = self.group.multiply(generator, self.shared_secret)
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

class OwnerVerdict(VerdictBase):
    def __init__(self, anon_key, key, client_keys, trustee_keys):
        VerdictBase.__init__(self, anon_key, client_keys, trustee_keys)

        self.shared_secret = self.group.zero()
        for idx in range(len(trustee_keys)):
            self.shared_secret = (self.shared_secret + \
                    key.exchange(trustee_keys[idx]) + \
                    anon_key.exchange(trustee_keys[idx]) \
                    ) % self.group.q


        self.secret_commit = self.group.multiply(self.group.generator(), \
                self.shared_secret)

class ClientVerdict(VerdictBase):
    def __init__(self, anon_key, key, client_keys, trustee_keys):
        VerdictBase.__init__(self, anon_key, client_keys, trustee_keys)

        self.shared_secret = self.group.zero()
        for idx in range(len(trustee_keys)):
            self.shared_secret = (self.shared_secret + \
                    key.exchange(trustee_keys[idx])) % self.group.q


        self.secret_commit = self.group.multiply(self.group.generator(), \
                self.shared_secret)

class TrusteeVerdict(VerdictBase):
    def __init__(self, anon_key, key, client_keys, trustee_keys):
        VerdictBase.__init__(self, anon_key, client_keys, trustee_keys)

        self.shared_secret = self.group.zero()
        for idx in range(len(client_keys)):
            self.shared_secret = (self.shared_secret - \
                    key.exchange(client_keys[idx])) % self.group.q

        self.shared_secret = (self.shared_secret - \
                key.exchange(anon_key)) % self.group.q

        self.secret_commit = self.group.multiply(self.group.generator(), \
                self.shared_secret)

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

    def setup(self, group, clients, trustees, owner_idx):
        ckeys, cpkeys = self.gen_keys(group, clients)
        tkeys, tpkeys = self.gen_keys(group, trustees)
        akey = PrivateKey(group)
        apkey = akey.public_key()

        cverdicts = []
        ccommitments = []

        for idx in range(clients):
            if idx == owner_idx:
                cverdicts.append(OwnerVerdict(akey, ckeys[idx], cpkeys, tpkeys))
            else:
                cverdicts.append(ClientVerdict(apkey, ckeys[idx], cpkeys, tpkeys))
            ccommitments.append(cverdicts[-1].commitment())

        tverdicts = []
        tcommitments = []

        for idx in range(trustees):
            tverdicts.append(TrusteeVerdict(apkey, tkeys[idx], cpkeys, tpkeys))
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

        cverdicts, tverdicts = self.setup(group, clients, trustees, owner_idx)

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
