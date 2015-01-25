#!/usr/bin/env python

import queue
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
    def __init__(self, secrets, interval):
        self.secrets = secrets
        self.interval = interval
        streams = []
        for secret in secrets:
            h = SHA256.new()
            h.update(secret)
            h.update(long_to_bytes(self.interval))
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

    def sync(self, client_set, trap_key):
        self.interval += 1
        self.trap_keys.append(trap_key)
        self.xornet = XorNet(self.secrets, self.interval)

    def produce_ciphertext(self, nym_index):
        return self.xornet.produce_ciphertext()

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

        self.own_nym_keys = []
        self.own_nyms = {}
        self.interval = -1
        self.pub_nym_keys = []
        self.nyms_in_processing = []
        self.certifier = certifier
        self.encoder = encoder

    def set_message_queue(self, messages):
        self.message_queue = messages

    def sync(self, client_set, trap_keys):
        self.interval += 1
        self.xornet = XorNet(self.secrets, self.interval)

    def add_own_nym(self, nym_key):
        self.nyms_in_processing.append(nym_key)

    def add_nyms(self, nym_keys):
        offset = len(self.pub_nym_keys)
        self.pub_nym_keys.extend(nym_keys)
        for nidx in range(len(self.nyms_in_processing)):
            nym = self.nyms_in_processing[nidx]
            # If trying to add a nym_key owned by this client, remove it from
            # nyms_in_processing and update own_nym_keys and own_nyms with it.
            for idx in range(offset, len(self.pub_nym_keys)):
                if nym.public_key().element != self.pub_nym_keys[idx].element:
                    continue
                self.own_nym_keys.append((nym, idx))
                self.own_nyms[idx] = nym
                self.nyms_in_processing.remove(nym)

    def produce_ciphertexts(self, nym_index):
        ciphertext = self.xornet.produce_ciphertext()
        cleartext = bytearray(cell_length)
        if nym_index in self.own_nyms:
            try:
                cleartext = self.message_queue.get_nowait()
            except:  # XXX make generic to queues
                pass
        # XXX pull XOR out into util
        ciphertext = long_to_bytes(
                bytes_to_long(ciphertext) ^ bytes_to_long(cleartext),
                blocksize=cell_length)
        return ciphertext

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
    trap_dhkeys, trap_keys = gen_keys(trustee_count)

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
        client.set_message_queue(queue.Queue())
        clients.append(client)

    accumulator = NullAccumulator()
    accumulator = SignatureAccumulator()
    accumulator = EncryptedAccumulator(global_group)
    relay = Relay(trustee_count, accumulator, NullDecoder())
    relay.add_nyms(client_count)
    relay.sync(None)

    for i, trustee in enumerate(trustees):
        trustee.sync(None, trap_dhkeys[i])

    for client in clients:
        client.sync(None, trap_keys)

    cleartexts = []
    for i in range(len(clients)):
        relay.decode_start()
        for idx in range(len(trustees)):
            trustee = trustees[idx]
            ciphertext = trustee.produce_ciphertext(i)
            relay.decode_trustee(ciphertext)

        for client in clients:
            ciphertext = client.produce_ciphertexts(i)
            relay.decode_client(ciphertext)

        cleartexts.append(relay.decode_cell().decode("utf-8"))
    print(cleartexts)

    print(time.time() - t0)
    t0 = time.time()

    for client in clients:
        message = bytes("Hello", "utf-8")
        message += bytes(cell_length - len(message))
        client.message_queue.put(message)

    cleartexts = []
    for i in range(len(clients)):
        relay.decode_start()
        for idx in range(len(trustees)):
            trustee = trustees[idx]
            ciphertext = trustee.produce_ciphertext(i)
            relay.decode_trustee(ciphertext)

        for client in clients:
            ciphertext = client.produce_ciphertexts(i)
            relay.decode_client(ciphertext)

        cleartexts.append(relay.decode_cell())
    print(cleartexts)

    print(time.time() - t0)

if __name__ == "__main__":
    main()
