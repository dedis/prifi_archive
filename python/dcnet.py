#!/usr/bin/env python

import random
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

import verdict

from cells.null import NullDecoder, NullEncoder
from certify.encrypted_exchange import EncryptedAccumulator, EncryptedCertifier
from certify.null import NullAccumulator, NullCertifier
from certify.signature import SignatureAccumulator, SignatureCertifier

from elgamal import PublicKey, PrivateKey
import schnorr

global_group = schnorr.verdict_1024()

cell_length = 256
empty_cell = bytes(0 for x in range(cell_length))

class XorNet:
    def __init__(self, secrets):
        self.secrets = secrets
        streams = []
        for secret in secrets:
            h = SHA256.new()
            h.update(secret)
            seed = h.digest()[:16]
            aes = AES.new(seed, AES.MODE_CTR, counter = Counter.new(128))
            streams.append(aes)
        self.streams = streams

    def produce_ciphertext(self):
        ciphertext = bytes(0 for x in range(cell_length))
        for stream in self.streams:
            ciphertext = stream.encrypt(ciphertext)
        return ciphertext

class Trustee:
    def __init__(self, key, client_keys):
        self.key = key
        self.client_keys = client_keys
        self.interval = -1

        self.secrets = []
        for key in self.client_keys:
            self.secrets.append(long_to_bytes(self.key.exchange(key)))

        self.nym_keys = []
        self.trap_keys = []

    def add_nyms(self, nym_keys):
        self.nym_keys.extend(nym_keys)

    def sync(self, client_set):
        self.interval += 1
        trap_key = PrivateKey(global_group)
        self.trap_keys.append(trap_key)
        self.xornet = XorNet(self.secrets)

    def produce_ciphertext(self):
        return self.xornet.produce_ciphertext()

    def produce_ciphertext(self, nyms):
        cells_for_nyms = []
        for ndx in nyms:
            cells_for_nyms.append(self.xornet.produce_ciphertext(ndx))
        return cells_for_nyms

class Relay:
    def __init__(self, trustees, accumulator, decoder):
        self.nyms = 0
        self.trustees = trustees
        self.interval = -1
        self.accumulator = accumulator
        self.decoder = decoder

    def add_nyms(self, nym_count):
        self.nyms += nym_count

    def sync(self, client_set):
        self.interval += 1

    def decode_start(self):
        self.xorbuf = 0

    def decode_client(self, cell):
        self.xorbuf ^= bytes_to_long(cell)

    def decode_trustee(self, cell):
        self.decode_client(cell)

    def decode_cell(self):
        return long_to_bytes(self.xorbuf, cell_length)

class Client:
    def __init__(self, key, trustee_keys, certifier, encoder):
        self.key = key
        self.trustee_keys = trustee_keys
        self.secrets = []
        for key in self.trustee_keys:
            self.secrets.append(long_to_bytes(self.key.exchange(key)))

        self.pub_nym_keys = []
        self.certifier = certifier
        self.encoder = encoder

    def sync(self, client_set, trap_keys):
        self.xornet = XorNet(self.secrets)

    def add_own_nym(self, nym_key):
        pass

    def add_nyms(self, nym_keys):
        self.pub_nym_keys.extend(nym_keys)

    def produce_ciphertexts(self):
        return self.xornet.produce_ciphertext()

def gen_keys(count):
    dhkeys = []
    pkeys = []

    for idx in range(count):
        dh = PrivateKey(global_group)
        dhkeys.append(dh)
        pkeys.append(dh.public_key())

    return dhkeys, pkeys

def main():
    t0 = time.time()

    trustee_count = 3
    client_count = 10

    trustee_dhkeys, trustee_keys = gen_keys(trustee_count)
    client_dhkeys, client_keys = gen_keys(client_count)
    nym_dhkeys, nym_keys = gen_keys(client_count)

    trustees = []
    for idx in range(trustee_count):
        trustee = Trustee(trustee_dhkeys[idx], client_keys)
        trustee.add_nyms(nym_keys)
        trustees.append(trustee)

    clients = []
    for idx in range(client_count):
        certifier = NullCertifier()
        certifier = SignatureCertifier(client_dhkeys[idx], client_keys)
        certifier = EncryptedCertifier(verdict.ClientVerdict(client_dhkeys[idx], client_keys, trustee_keys))
        client = Client(client_dhkeys[idx], trustee_keys, certifier, NullEncoder())
        client.add_own_nym(nym_dhkeys[idx])
        client.add_nyms(nym_keys)
        clients.append(client)

    accumulator = NullAccumulator()
    accumulator = SignatureAccumulator()

    ss = 0
    for tdh in trustee_dhkeys:
        v = verdict.TrusteeVerdict(tdh, client_keys, trustee_keys)
        ss = (ss + v.shared_secret()) % tdh.group.order()

    accumulator = EncryptedAccumulator(verdict.TrusteeVerdict(ss, client_keys, trustee_keys, True))
    relay = Relay(trustee_count, accumulator, NullDecoder())
    relay.add_nyms(client_count)
    relay.sync(None)

    trap_keys = []
    for trustee in trustees:
        trustee.sync(None)
        trap_keys.append(trustee.trap_keys[-1].public_key())

    for client in clients:
        client.sync(None, trap_keys)

    cleartexts = []
    for i in range(len(clients)):
        relay.decode_start()
        for idx in range(len(trustees)):
            trustee = trustees[idx]
            ciphertext = trustee.produce_ciphertext()
            relay.decode_trustee(ciphertext)

        for client in clients:
            ciphertext = client.produce_ciphertexts()
            relay.decode_client(ciphertext)

        cleartexts.append(relay.decode_cell())
    print(cleartexts)

    print(time.time() - t0)
    for client in clients:
        client.process_cleartext(cleartext)
    t0 = time.time()

    cleartexts = []
    for i in range(len(clients)):
        relay.decode_start()
        for idx in range(len(trustees)):
            trustee = trustees[idx]
            ciphertext = trustee.produce_ciphertext()
            relay.decode_trustee(ciphertext)

        for i, client in enumerate(clients):
            ciphertext = client.produce_ciphertexts()
            cleartext = long_to_bytes(0)
            if i == 0:
                cleartext = bytes("Hello", "UTF-8")
            ciphertext = long_to_bytes(
                    bytes_to_long(ciphertext) ^ bytes_to_long(cleartext))
            relay.decode_client(ciphertext)
        cleartexts.append(relay.decode_cell())
    print(cleartexts)

    print(time.time() - t0)

if __name__ == "__main__":
    main()
