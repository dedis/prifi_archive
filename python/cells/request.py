#!/usr/bin/env python
from Crypto.Hash import SHA256
import random
import math
from bitstring import Bits, BitArray
from Crypto.Util.number import long_to_bytes, bytes_to_long
import unittest
import cells.request_tuning as opt

clients = 20
trap_flip_risk = 0.1
hash_collision_risk = 1

def request_cell_length():
    _, b = opt.findb(clients, trap_flip_risk, hash_collision_risk)
    return b

def set_trap_flip_risk(tfr):
    global trap_flip_risk
    trap_flip_risk = tfr

class RequestBase():
    def __init__(self, clients, trap_flip_risk,
                 hash_collision_risk=0.01,
                 cell_bit_length=None,
                 bits_per_nym=None):
        if cell_bit_length == None:
            r, b = opt.findb(clients, trap_flip_risk, hash_collision_risk)
            assert(not math.isnan(b)), "No results for n {0} h {1} p {2}"\
                .format(clients, hash_collision_risk, trap_flip_risk)
            self.request_bits, self.cell_bit_length = r, b
        else:
            self.request_bits = bits_per_nym
            self.cell_bit_length = cell_bit_length

    def cell_from_seeds(self, seeds):
        """ Generates a request cell for the client with the provided seeds """
        h = SHA256.new()
        for seed in seeds:
            h.update(long_to_bytes(seed))
        random.seed(h.digest())
        cell = [False] * self.cell_bit_length
        flip = random.sample(range(0, self.cell_bit_length), self.request_bits)
        self.rstate = random.getstate()
        for bit in flip:
            cell[bit] = True
        return Bits(cell)

class RequestChecker(RequestBase):
    def __init__(self, seedlist, cell_bit_length=None, bits_per_nym=None):
        """ seeds is a list of lists of trap secrets, such that seeds[nid][tid]
        is the shared secret between nym nid and trustee tid
        Attributes
          full (Bits): the or of all client cells
          trapmask (Bits): negation of full (0 where any client's code is 1)
          bloom (dict: Bits -> int list): Maps encoded cells to a list of the
            indices of the nyms whose request code is that code
        """
        super().__init__(clients, trap_flip_risk, hash_collision_risk,
                         cell_bit_length, bits_per_nym)
        self.bloom = {}
        self.full = Bits(uint=0, length=self.cell_bit_length)
        for i in range(len(seedlist)):
            key = self.cell_from_seeds(seedlist[i])
            if not key in self.bloom.keys():
                self.bloom[key] = [i]
            else:
                self.bloom[key].append(i)
            self.full |= key
        self.trapmask = ~self.full
        self.trapcount = sum((~self.full >> i) & Bits(uint=1,
                                                      length=self.cell_bit_length) \
                             for i in range(self.cell_bit_length))

    def trap_noise(self, count):
        return NotImplemented

    def check(self, cell):
        """ Verify that the cell's trap bits have not been flipped """
        cellbits = Bits(uint=bytes_to_long(cell), length=len(self.trapmask))
        if cellbits & self.trapmask != Bits(len(self.trapmask)):
            print("Bad trap bit in request cell: Got\n {0}, full was\n {1}, bloom: {2}"
                  .format((cellbits & self.trapmask).bin,
                          self.full.bin, self.bloom))
            return False
        return True

class RequestEncoder(RequestBase):
    def __init__(self, seeds=None):
        super().__init__(clients, trap_flip_risk, hash_collision_risk)
        self.cell = self.cell_from_seeds(seeds)

    def encode(self, cell=None):
        """ Encodes a request for a cell into the shared request cell.
            If cell is specified, probabilistically return a subset of the 1
            bits in self.cell that are 0 in cell.
            """
        if cell == None or bytes_to_long(cell) == 0:
            return self.cell.tobytes()
        else:
            bcell = Bits(uint=bytes_to_long(cell), length=len(self.cell))
            missing = BitArray((bcell & self.cell) ^ self.cell)
            random.setstate(self.rstate)
            for idx in range(len(missing)):
                if missing[idx]:
                    missing[idx] = random.choice([True, False])
            self.rstate = random.getstate()
            return missing.tobytes()

    def decoded_size(self, size):
        return NotImplemented

    def encoded_size(self, size):
        return -(-self.cell_bit_length // 8)

class RequestDecoder(RequestChecker):
    def decode(self, cell):
        """ Takes a request cell containing one or more requests for slots and
        grants all of them """
        nyms = []
        bcell = Bits(uint=bytes_to_long(cell), length=self.cell_bit_length)
        for key in self.bloom.keys():
            if bcell & key == key:
                nyms.extend(self.bloom[key])
        return nyms

class Test(unittest.TestCase):
    def setUp(self):
        self.e = RequestEncoder([1, 2, 3])
        self.c = RequestChecker([[1, 2, 3]])
        self.d = RequestDecoder([[1, 2, 3]])
        random.seed()

    def test_cells_from_seeds(self):
        self.assertEqual(self.e.cell_from_seeds([1, 2, 3]),
                         self.e.cell_from_seeds([1, 2, 3]))

    def test_encode(self):
        ecell = self.e.encode()
        self.assertEqual(self.c.full, Bits(ecell))

    def test_decode(self):
        ecell = self.e.encode()
        self.assertEqual(self.d.decode(ecell), [0])

    def test_check(self):
        ecell = self.e.encode()
        self.assertTrue(self.c.check(ecell))

    def test_flter_bloom(self):
        """ Tests that the result of multiple insertions of encoded()'s is a
        superset of the encoded cells, for multiple random sets """
        nymseeds = {}
        for i in range(30):
            nymseeds[i] = []
            for _ in range(30):
                nymseeds[i].append(random.randint(0, 9))
        d = RequestDecoder(nymseeds)
        encs = [RequestEncoder(nymseeds[i]) for i in nymseeds]
        random.seed()
        for _ in range(30):
            samplesize = random.randint(1, len(nymseeds))
            nyms = sorted(random.sample(range(len(nymseeds)), samplesize))
            these_encs = [encs[i] for i in nyms]
            cell = Bits(uint=0, length=d.cell_bit_length)
            for enc in these_encs:
                cell |= Bits(enc.encode())
            self.assertEqual(d.full | cell, d.full)
            self.assertTrue(d.check(cell.tobytes()))
            print("DONE CHECKING NOW DECODING")
            decoded = sorted(d.decode(cell.tobytes()))
            print("DONE CHECKING NOW VERIFYING")
            for elt in nyms:
                self.assertTrue(elt in decoded,
                                msg="elt: {0} nyms: {1} decoded: {2}\n"
                                .format(elt, nyms, decoded) + \
                                "encs: {0}\n cell: {1}"
                                .format([i.encode() for i in encs], cell))
if __name__ == '__main__':
    unittest.main()
