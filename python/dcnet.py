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

cell_length = 24
empty_cell = bytes(0 for x in range(cell_length))

class XorNet:
    def __init__(self, secrets, interval):
        self.secrets = secrets
        self.interval = interval
        self.cell_count = {}

    def produce_ciphertext(self, nym_idx):
        if nym_idx not in self.cell_count:
            self.cell_count[nym_idx] = 0

        ciphertext = bytes(0 for x in range(cell_length))
        for secret in self.secrets:
            h = SHA256.new()
            h.update(secret)
            h.update(long_to_bytes(self.interval))
            h.update(long_to_bytes(self.cell_count[nym_idx]))
            h.update(long_to_bytes(nym_idx))

            seed = h.digest()[:16]
            aes = AES.new(seed, AES.MODE_CTR, counter = Counter.new(128))
            ciphertext = aes.encrypt(ciphertext)
        self.cell_count[nym_idx] += 1
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
        self.xornet = XorNet(self.secrets, self.interval)

    def produce_interval_ciphertext(self, cell_count=1):
        cells_for_nyms = []
        for ndx in range(len(self.nym_keys)):
            ciphertext = []
            for idx in range(cell_count):
                ciphertext.append(self.xornet.produce_ciphertext(ndx))
            cells_for_nyms.append(ciphertext)
        return cells_for_nyms

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
        self.cells_for_nyms = [[] for x in range(self.trustees)]
        self.current_cell = [0 for x in range(self.nyms)]

    def store_trustee_ciphertext(self, trustee_idx, cells_for_nyms):
        assert len(self.cells_for_nyms[trustee_idx]) == 0
        self.cells_for_nyms[trustee_idx] = cells_for_nyms

    def process_ciphertext(self, ciphertexts):
        ciphertexts = self.accumulator.before(ciphertexts)

        cleartext = []
        for nym_texts in ciphertexts[0]:
            cleartext.append([0 for x in range(len(nym_texts))])

        # Merging client ciphertexts
        for cldx in range(len(ciphertexts)):
            client_texts = ciphertexts[cldx]
            for nymdx in range(len(client_texts)):
                nym_texts = client_texts[nymdx]
                for celldx in range(len(nym_texts)):
                    cell = nym_texts[celldx]
                    cleartext[nymdx][celldx] ^= bytes_to_long(cell)

        # Merging trustee ciphertexts
        for nymdx in range(len(cleartext)):
            nym_texts = cleartext[nymdx]
            offset = self.current_cell[nymdx]
            cells = len(nym_texts)
            for celldx in range(cells):
                for tidx in range(self.trustees):
                    cell = self.cells_for_nyms[tidx][nymdx][offset + celldx]
                    cleartext[nymdx][celldx] ^= bytes_to_long(cell)
                cell = long_to_bytes(cleartext[nymdx][celldx])
                cell = self.decoder.decode(cell)
                cleartext[nymdx][celldx] = cell
            self.current_cell[nymdx] += cells

        return self.accumulator.after(cleartext)

class Client:
    def __init__(self, key, trustee_keys, certifier, encoder):
        self.key = key
        self.trustee_keys = trustee_keys
        self.secrets = []
        for key in self.trustee_keys:
            self.secrets.append(long_to_bytes(self.key.exchange(key)))

        self.own_nym_keys = []
        self.own_nyms = {}
        self.pub_nym_keys = []
        self.nyms_in_processing = []

        self.interval = -1
        self.data_queue = {}

        self.certifier = certifier
        self.encoder = encoder

    def sync(self, client_set, trap_keys):
        self.interval += 1
        self.xornet = XorNet(self.secrets, self.interval)

        self.trap_seeds = []
        for nym_key, idx in self.own_nym_keys:
            h = SHA256.new()
            for trap_key in trap_keys:
                h.update(long_to_bytes(trap_key.exchange(nym_key)))
            self.trap_seeds.append(h.digest())

    def add_own_nym(self, nym_key):
        self.nyms_in_processing.append(nym_key)

    def add_nyms(self, nym_keys):
        offset = len(self.pub_nym_keys)
        self.pub_nym_keys.extend(nym_keys)

        for nidx in range(len(self.nyms_in_processing)):
            nym = self.nyms_in_processing[nidx]
            for idx in range(offset, len(self.pub_nym_keys)):
                if nym.pubkey.y != self.pub_nym_keys[idx].y:
                    continue
                self.own_nym_keys.append((nym, idx))
                self.own_nyms[idx] = nym
                self.nyms_in_processing.remove(nym)

    def send(self, nym_idx, data):
        assert self.encoder.encoded_size(len(data)) <= cell_length
        if nym_idx not in self.data_queue:
            self.data_queue[nym_idx] = []
        self.data_queue[nym_idx].append(data)

    def produce_ciphertexts(self):
        cells_for_nyms = []
        count = 1
        for nym_idx in range(len(self.pub_nym_keys)):
            cells = []
            for idx in range(count):
                ciphertext = self.xornet.produce_ciphertext((nym_idx))
                cleartext = long_to_bytes(0)
                if nym_idx in self.data_queue:
                    cleartext = self.data_queue[nym_idx][0]
                    if len(self.data_queue[nym_idx]) == 1:
                        del self.data_queue[nym_idx]
                    else:
                        self.data_queue[nym_idx] = self.data_queue[nym_idx][1:]
                cleartext = self.encoder.encode(cleartext)
                ciphertext = long_to_bytes(
                        bytes_to_long(ciphertext) ^ bytes_to_long(cleartext))
                cells.append(ciphertext)
            cells_for_nyms.append(cells)
        return self.certifier.certify(cells_for_nyms)

    def process_cleartext(self, cleartext):
        return self.certifier.verify(cleartext)

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

    for idx in range(len(trustees)):
        trustee = trustees[idx]
        ciphertext = trustee.produce_interval_ciphertext()
        relay.store_trustee_ciphertext(idx, ciphertext)

    client_ciphertexts = []
    for client in clients:
        client_ciphertexts.append(client.produce_ciphertexts())
    cleartext = relay.process_ciphertext(client_ciphertexts)
    print(cleartext)

    print(time.time() - t0)
    for client in clients:
        client.process_cleartext(cleartext)
    t0 = time.time()

    client_ciphertexts = []
    for client in clients:
        client.send(client.own_nym_keys[0][1], bytes("Hello", "UTF-8"))
        client_ciphertexts.append(client.produce_ciphertexts())
    cleartext = relay.process_ciphertext(client_ciphertexts)
    print(cleartext)

    print(time.time() - t0)
    for client in clients:
        client.process_cleartext(cleartext)
    t0 = time.time()

    client_ciphertexts = []
    for client in clients:
        client_ciphertexts.append(client.produce_ciphertexts())
    cleartext = relay.process_ciphertext(client_ciphertexts)
    print(cleartext)

    print(time.time() - t0)
    for client in clients:
        client.process_cleartext(cleartext)
    t0 = time.time()

if __name__ == "__main__":
    main()
