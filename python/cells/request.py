#!/usr/bin/env python
from Crypto.Hash import SHA256
import random
from bitstring import Bits, BitArray
from Crypto.Util.number import long_to_bytes, bytes_to_long
import unittest
import cells.request_tuning as opt

clients = 10
trap_flip_risk = .1
hash_collision_risk = 0.01

def request_cell_length():
    r, b = opt.findb(clients, trap_flip_risk, hash_collision_risk)
    print("Request cell length: {0}. Bits per client: {1}".format(b, r))
    return b

class RequestBase():
    def __init__(self, clients, trap_flip_risk,
                 hash_collision_risk=0.01,
                 cell_bit_length=None,
                 bits_per_nym=None):
        if cell_bit_length == None:
            self.request_bits, self.cell_bit_length = opt.findb(clients,
                                                            trap_flip_risk,
                                                            hash_collision_risk)
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
          bloom (dict: Bits -> int): Maps encoded cells to the index of the
            nym whose request it is
        """
        super().__init__(clients, trap_flip_risk, hash_collision_risk,
                         cell_bit_length, bits_per_nym)
        self.bloom = {}
        self.full = Bits(uint=0, length=self.cell_bit_length)
        for i in range(len(seedlist)):
            key = self.cell_from_seeds(seedlist[i])
            if key in self.bloom.keys():
                print("RequestChecker: Warning: Hash collision detected")
            self.bloom[key] = i
            self.full |= key
        # long to bytes apparently can't handle negatives, so use bits intsead
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
            print("Bad trap bit in request cell: Got\n {0}, full was\n {1}"
                  .format(cellbits & self.trapmask,
                          bin(self.full)))
            return False
        return True

class RequestEncoder(RequestBase):
    def __init__(self, seeds=None):
        super().__init__(clients, trap_flip_risk, hash_collision_risk)
        self.cell = self.cell_from_seeds(seeds)

    def encode(self, cell=None):
        """ Encodes a request for a cell into the shared request cell.
            The argument is ignored.
            """
        return self.cell.tobytes()

    def decoded_size(self, size):
        return NotImplemented

    def encoded_size(self, size):
        return -(-self.cell_bit_length // 8)

class RequestDecoder(RequestChecker):
    def decode(self, cell):
        """ Takes a request cell containing one or more requests for slots and
        grants all of them """
        nyms = []
        bcell = Bits(cell)
        for key in self.bloom.keys():
            print("Cell: {0}\n key: {1}\n and: {2} = key? {3} thus: {4}"
                  .format(bcell.bin, key.bin,
                          (bcell & key).bin,
                          bcell & key == key, self.bloom[key]))
            if bcell & key == key:
                nyms.append(self.bloom[key])
                print("Appended {0}. now nyms is {1}"
                      .format(self.bloom[key], nyms))
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
                                msg="nyms: {0} decoded: {1}\n"
                                .format(nyms, decoded) + \
                                "encs: {0}\n cell: {1}"
                                .format([i.encode() for i in encs], cell))
if __name__ == '__main__':
    unittest.main()
