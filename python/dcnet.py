#!/usr/bin/env python

import queue
import random
import time
from copy import deepcopy
import unittest
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

import verdict

from cells.null import NullDecoder, NullEncoder, NullChecker
from certify.encrypted_exchange import EncryptedAccumulator, EncryptedCertifier
from certify.null import NullAccumulator, NullCertifier
from certify.signature import SignatureAccumulator, SignatureCertifier

from elgamal import PublicKey, PrivateKey
import schnorr

global_group = schnorr.verdict_1024()

cell_length = 256
empty_cell = bytes(0 for x in range(cell_length))

class XorNet:
    """ Class for handling the xor net layer.

    Attributes:
      secrets (object list): The shared secrets to use to encrypt ciphertext
      interval (int): The number of the current interval
        (to uniquify the AES keys)
      cell_count (int -> int dictionary): Maps nym indices to the number of
        cells of that index that have been encrypted so far (used as another
        uniquifier)
    """
    def __init__(self, secrets, interval):
        self.secrets = secrets
        self.interval = interval
        self.cell_count = {}

    def produce_ciphertext(self, nym_idx):
        if nym_idx not in self.cell_count:
            self.cell_count[nym_idx] = 0

        # We're not transmitting data, so start with null ciphertext
        ciphertext = bytes(0 for x in range(cell_length))
        for secret in self.secrets:
            # Per secret, AES-encrypt the ciphertext with a hash of the secret
            # plus interval/cell/slot information.
            h = SHA256.new()
            h.update(secret)
            h.update(long_to_bytes(self.interval))
            seed = h.digest()[:16]
            aes = AES.new(seed, AES.MODE_CTR, counter = Counter.new(128))
            ciphertext = aes.encrypt(ciphertext)
        # At this point, ciphertext has been encrypted with something resulting
        # from each shared secret
        self.cell_count[nym_idx] += 1
        return ciphertext

class Trustee:
    def __init__(self, key, client_keys, checker):
        """
        Usage: Create a Trustee, call add_nyms on all client nyms, then call
        sync.  After this, call produce_interval_ciphertext as needed.

        Attributes:
          key (PrivateKey): This trustee's long-term private key
          client_keys (PublicKey list): List of long-term public keys of
            clients
          interval (int): The index of the current interval
          secrets (byte list list): List of long-term shared secrets between
            this trustee and each client
          nym_keys (PublicKey list): List of long-term public keys of each slot
            owner pseudonym
          trap_keys (PrivateKey list): The nth element is the trustee's trap
            private key for the nth interval.
          xornet (XorNet): Local copy of the XorNet for generating ciphertext
        """
        self.key = key
        self.client_keys = client_keys
        self.interval = -1

        # Generate a shared secret with each client. These are session-long.
        self.secrets = []
        for key in self.client_keys:
            self.secrets.append(long_to_bytes(self.key.exchange(key)))

        self.nym_keys = []
        self.trap_keys = []
        self.checker = checker
        self.all_trap_secrets = []

    def add_nyms(self, nym_keys):
        """ Called when the client set changes to add new nym_keys to this
        trustee's nym_keys set.
        """
        self.nym_keys.extend(nym_keys)
        self.all_trap_secrets.extend([[] for _ in nym_keys])

    def sync(self, client_set):
        """ Called at the beginning of an interval to generate new trap keys
        for secret sharing, and to update xornet with the new interval.
        """
        self.interval += 1
        trap_key = PrivateKey(global_group)
        self.trap_secrets = [trap_key.exchange(k) for k in self.nym_keys]
        self.trap_keys.append(trap_key)
        self.xornet = XorNet(self.secrets, self.interval)
        self.all_trap_secrets = [[] for _ in self.nym_keys]

    def produce_interval_ciphertext(self):
        """ Generate cells_count cells' worth of ciphertext for each nym in
        self.nym_keys. Returns as a list of lists of ciphertext cells
        """
        cell_count = 100
        cells_for_nyms = []
        for ndx in range(len(self.nym_keys)):
            ciphertext = []
            nym_noise_gen = self.checker([self.trap_secrets[ndx]])
            noise = nym_noise_gen.trap_noise(cell_count)
            for idx in range(cell_count):
                cell = bytes_to_long(self.xornet.produce_ciphertext(ndx))
                cell ^= bytes_to_long(noise[idx])
                ciphertext.append(long_to_bytes(cell))
            cells_for_nyms.append(ciphertext)
        return cells_for_nyms

    def publish_trap_secrets(self):
        return self.trap_secrets

    def store_trap_secrets(self, trap_secrets):
        for i in range(len(trap_secrets)):
            this_trap_list = self.all_trap_secrets[i]
            for secret in trap_secrets[i]:
                if secret not in this_trap_list:
                    self.all_trap_secrets[i].append(secret)

    def check_interval_traps(self, cleartexts):
        """ Determine whether any trap bits have been flipped, where ciphertexts
        is a list of cells
        """
        nym_trap_checkers = []
        for nym_secrets in self.all_trap_secrets:
            nym_trap_checkers.append(self.checker(nym_secrets))
        for cleartext in cleartexts:
            for nymdx in range(len(cleartext)):
                for cell in cleartext[nymdx]:
                    if not nym_trap_checkers[nymdx].check(long_to_bytes(cell)):
                        print("A trap bit was flipped!")
                        # TODO: Call something if this happens
                        return False
        return True

class Relay:
    """ DC-nets layer Relay.

    Usage: initialize, add_nyms on the number of nyms across all clients, sync,
    then store_trustee_ciphertext untill there is enough to call
    process_ciphertext. Repeat for each round.

    Attributes:
      nyms (int): Number of nyms in the current interval
      trustees (int): The number of trustees this relay is communicating with
      interval (int): Index of the current interval
      accumulator: Accumulator object from certify
      decoder (any Decoder class from cells): The decoder to use for reversing
        the trap encoding
      cells_for_nyms (list list): Indexed by trustee index; stores a list of
        of cells for each nym within each trustee entry
      current_cell (int list): The nth element is the index of the next cell of
        nym n to process
    """
    def __init__(self, trustees, accumulator, decoder):
        self.nyms = 0
        self.trustees = trustees
        self.interval = -1
        self.accumulator = accumulator
        self.decoder = decoder()

    def add_nyms(self, nym_count):
        self.nyms += nym_count

    def sync(self, client_set):
        self.interval += 1
        self.cells_for_nyms = [[] for x in range(self.trustees)]
        self.current_cell = [0 for x in range(self.nyms)]

    def store_trustee_ciphertext(self, trustee_idx, cells_for_nyms):
        """ cells_for_nyms is a list of cells for each pseudonym. This stores
        that list under trustee_idx within self.cells_for_nyms.
        """
        assert len(self.cells_for_nyms[trustee_idx]) == 0
        self.cells_for_nyms[trustee_idx] = cells_for_nyms

    def process_ciphertext(self, ciphertexts):
        """ returns the original messages encoded in ciphertexts. NOTE: This
        assumes enough trustee ciphertext has already been accumulated and
        does not block!

        input:
        ciphertexts is a list of lists, where there is one element per slot,
        and each slot contains a list of the form [client_texts, Client DH
        signature], where each element of client_texts is a list of nym_texts,
        where each nym_text is a list of the cells contained in the slot owned
        by a single pseudonym.

        output:
        Returns a list with one element per pseudonym, where eacn element is
        a list of decoded cells.
        """
        ciphertexts = self.accumulator.before(ciphertexts)

        # cleartext is a list with one element per pseudonym, where each element
        # contains the cleartext of that pseudonym's output. So cleartext is
        # actual-client-agnostic.
        cleartext = []
        for nym_texts in ciphertexts[0]:
            cleartext.append([0 for x in range(len(nym_texts))])

        # Merging client ciphertexts
        for cldx in range(len(ciphertexts)):
            # For each client...
            client_texts = ciphertexts[cldx]
            for nymdx in range(len(client_texts)):
                # For each nym slot of this client's ciphertext...
                nym_texts = client_texts[nymdx]
                for celldx in range(len(nym_texts)):
                    # For each cell in this nym's slot...
                    cell = nym_texts[celldx]
                    # xor this client's verison of this cell with the cell so far
                    cleartext[nymdx][celldx] ^= bytes_to_long(cell)

        # Merging trustee ciphertexts
        for nymdx in range(len(cleartext)):
            nym_texts = cleartext[nymdx]
            offset = self.current_cell[nymdx]
            cells = len(nym_texts)
            for celldx in range(cells):
                # For each cell:
                # 1. xor the stored trustee cell with the client cell...
                for tidx in range(self.trustees):
                    cell = self.cells_for_nyms[tidx][nymdx][offset + celldx]
                    cleartext[nymdx][celldx] ^= bytes_to_long(cell)

        return cleartext

    def trap_decode_cleartext(self, cleartext):
        for nymdx in range(len(cleartext)):
            nym_texts = cleartext[nymdx]
            cells = len(nym_texts)
            for celldx in range(cells):
                # 2. cell decode the xornet-decrypted cell...
                cell = long_to_bytes(cleartext[nymdx][celldx])
                cell = self.decoder.decode(cell)
                # 3. update cleartext to store the original message for later
                #    transmission to clients
                cleartext[nymdx][celldx] = cell
            self.current_cell[nymdx] += cells

        return self.accumulator.after(cleartext)

class Client:
    """ DC-nets layer Client. A Client can own multiple pseudonyms (nyms), each
    of which has its own slot. Each slot is comprised of cells.

    Usage: After creating a Client, call add_own_nym on one or more private
    keys, then call add_nyms on all public keys (including this client's). Then,
    call sync with trap keys produced by each trustee. After this, call send an
    arbitrary number of times to send data.

    Attributes:
      key (PrivateKey): This client's long-term private key
      trustee_keys (PublicKey list): List of long-term public keys of trustees
      secrets (byte list list): List of long-term shared secrets between this
        client and each trustee
      trap_seeds (byte list): One per nym. Each seed is a hash of all trap keys
        passed to sync.
      own_nym_keys ((PrivateKey, int) list): List of (private key, nym index)
        tuples for each pseudonym owned by this client
      own_nyms (int -> PrivateKey): map of nym indices to nym PrivateKeys owned
        by this client
      pub_nym_keys (PublicKey list): List of (anybody's) public pseudonym keys
      nyms_in_processing (PrivateKey list): list for temporarily storing nyms
        for which we have the private key but have not yet added the public key
      interval (int): The index of the current interval
      data_queue (int -> byte list): map of nym indices to list of data to be
        transmitted with that pseudonym
      certifier: Certifier object from certify
      encoder (Encoder object from cells): Object for trap encoding data
      xornet (XorNet): Local copy of the XorNet for generating ciphertext
    """
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
        self.new_encoder = encoder

    def set_message_queue(self, messages):
        self.message_queue = messages

    def sync(self, client_set, trap_keys):
        """ Called at the beginning of each interval to update all secrets

        inputs:
          client_set: TODO:?
          trap_keys (PublicKey list): Public trap key per trustee
        """
        self.interval += 1
        self.xornet = XorNet(self.secrets, self.interval)

        self.trap_seeds = {}
        for nym_key, idx in self.own_nym_keys:
            self.trap_seeds[nym_key] = []
            for trap_key in trap_keys:
                self.trap_seeds[nym_key] \
                    .append(trap_key.exchange(nym_key))
            self.encoder = self.new_encoder(self.trap_seeds[nym_key])

    def add_own_nym(self, nym_key):
        """ Add nym_key (PrivateKey) to nyms_in_processing. Once its PublicKey
        gets added via add_nyms, it will be moved to own_nyms.
        """
        self.nyms_in_processing.append(nym_key)

    def add_nyms(self, nym_keys):
        """ Add nym_keys (PublicKey list) to pub_nym_keys. If the corresponding
        private key is in processing, add that to own_nyms and own_nym_keys.
        """
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

    def send(self, nym_idx, data):
        """ Add data (byte list) to the queue of data to send with nym_idx.
        Precondition: data must be small enough to fit in a cell.
        """
        assert self.encoder.encoded_size(len(data)) <= cell_length
        if nym_idx not in self.data_queue:
            self.data_queue[nym_idx] = []
        self.data_queue[nym_idx].append(data)

    def produce_ciphertexts(self):
        """ Produce ciphertext for all (everybody's) nyms, optionally encoding
        data into the slots owned by this Client's nyms. Returns the output of
        a call to certify (ciphertexts, (other, own))
        """
        cells_for_nyms = []
        count = 1
        for nym_idx in range(len(self.pub_nym_keys)):
            cells = []
            for idx in range(count):
                ciphertext = self.xornet.produce_ciphertext((nym_idx))
                cleartext = long_to_bytes(0)
                # For each nym, if it has data to send, encode it and xor it
                # into the ciphertext
                if nym_idx in self.data_queue:
                    cleartext = self.encoder.encode(self.data_queue[nym_idx][0])
                    if len(self.data_queue[nym_idx]) == 1:
                        del self.data_queue[nym_idx]
                    else:
                        self.data_queue[nym_idx] = self.data_queue[nym_idx][1:]
                elif nym_idx in self.own_nyms:
                    cleartext = self.encoder.encode(cleartext)
                ciphertext = long_to_bytes(
                        bytes_to_long(ciphertext) ^ bytes_to_long(cleartext))
                cells.append(ciphertext)
            cells_for_nyms.append(cells)
        return self.certifier.certify(cells_for_nyms)

    def process_cleartext(self, cleartext):
        return self.certifier.verify(cleartext)


class Test(unittest.TestCase):
    def setUp(self):
        self.trustee_count = 3
        self.client_count = 10

        self.trustee_dhkeys, self.trustee_keys = self.gen_keys(self.trustee_count)
        self.client_dhkeys, self.client_keys = self.gen_keys(self.client_count)
        self.nym_dhkeys, self.nym_keys = self.gen_keys(self.client_count)

        self.trustees = self.spawn_trustees()
        self.clients = self.spawn_clients()
        self.relay = self.spawn_relay()

        self.start_interval()

    def test_send(self):
        for idx in range(len(self.trustees)):
            trustee = self.trustees[idx]
            ciphertext = trustee.produce_interval_ciphertext()
            self.relay.store_trustee_ciphertext(idx, ciphertext)

        self.to_chk = []
        self.send(self.clients, self.trustees, self.relay, self.to_chk)
        self.send(self.clients, self.trustees, self.relay, self.to_chk,
                  bytes("Hello", "UTF-8"))
        self.send(self.clients, self.trustees, self.relay, self.to_chk)

    def test_check(self):
        self.test_send()
        t0 = time.time()
        trap_secrets = [trustee.publish_trap_secrets() for trustee in self.trustees]
        composite_secrets = [[trap_secrets[i][j] \
                              for i in range(self.trustee_count)] \
                                for j in range(len(trap_secrets[0]))]
        for i in range(self.trustee_count):
            self.trustees[i].store_trap_secrets(composite_secrets)
            self.assertTrue(self.trustees[i].check_interval_traps(self.to_chk),
                            msg="Trustee {0} rejected ciphertext {1}"
                            .format(i, self.to_chk))
        print(time.time() - t0)

    def gen_keys(self, count):
        dhkeys = []
        pkeys = []

        for idx in range(count):
            dh = PrivateKey(global_group)
            dhkeys.append(dh)
            pkeys.append(dh.public_key())

        return dhkeys, pkeys

    def spawn_trustees(self):
        trustees = []
        for idx in range(self.trustee_count):
            trustee = Trustee(self.trustee_dhkeys[idx], self.client_keys,
                              self.checker)
            trustee.add_nyms(self.nym_keys)
            trustees.append(trustee)
        return trustees

    def spawn_clients(self):
        clients = []
        for idx in range(self.client_count):
            certifier = NullCertifier()
            certifier = SignatureCertifier(self.client_dhkeys[idx],
                                           self.client_keys)
            client_verdict = verdict.ClientVerdict(self.client_dhkeys[idx],
                                                   self.client_keys,
                                                   self.trustee_keys)
            certifier = EncryptedCertifier(client_verdict)
            client = Client(self.client_dhkeys[idx], self.trustee_keys,
                            certifier, self.encoder)
            client.add_own_nym(self.nym_dhkeys[idx])
            client.add_nyms(self.nym_keys)
            clients.append(client)
        return clients

    def spawn_relay(self):
        accumulator = NullAccumulator()
        accumulator = SignatureAccumulator()

        ss = 0
        for tdh in self.trustee_dhkeys:
            v = verdict.TrusteeVerdict(tdh, self.client_keys, self.trustee_keys)
            ss = (ss + v.shared_secret()) % tdh.group.order()

        trustee_verdict = verdict.TrusteeVerdict(ss, self.client_keys,
                                                 self.trustee_keys, True)
        accumulator = EncryptedAccumulator(trustee_verdict)
        relay = Relay(self.trustee_count, accumulator, self.decoder)
        relay.add_nyms(self.client_count)
        return relay

    def start_interval(self):
        self.relay.sync(None)
        trap_keys = []
        for trustee in self.trustees:
            trustee.sync(None)
            trap_keys.append(trustee.trap_keys[-1].public_key())
        for client in self.clients:
            client.sync(None, trap_keys)

    def send(self, clients, trustees, relay, to_check, m=None):
        t0 = time.time()
        client_ciphertexts = []
        for client in clients:
            if m != None:
                client.send(client.own_nym_keys[0][1], m)
            client_ciphertexts.append(client.produce_ciphertexts())
        next_to_check = relay.process_ciphertext(client_ciphertexts)
        to_check.append(deepcopy(next_to_check))
        cleartext = relay.trap_decode_cleartext(next_to_check)

        if m == None:
            m = long_to_bytes(0)
        for i in range(len(cleartext)):
            self.assertEqual(cleartext[i][0], m,
                             msg="Slot {0} got {1}; expected{2}"
                             .format(i, cleartext[i][0], m))
        print(time.time() - t0)
        for client in clients:
            client.process_cleartext(cleartext)

if __name__ == "__main__":
    unittest.main()
