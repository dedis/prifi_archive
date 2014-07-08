#!/usr/bin/env python
from Crypto.Hash import SHA256
import random
from bitstring import Bits, BitArray
from Crypto.Util.number import long_to_bytes
import unittest

cell_bit_length = 8
request_bits = 2

def cell_from_seeds(seeds):
    """ Generates a request cell for the client with the provided seeds """
    h = SHA256.new()
    for seed in seeds:
        h.update(long_to_bytes(seed))
    random.seed(h.digest())
    cell = [False] * cell_bit_length
    for _ in range(request_bits):
        cell[random.randint(1, cell_bit_length) - 1] = True
    return Bits(cell)

class RequestChecker:
    def __init__(self, seedlist):
        """ seeds is a list of lists of trap secrets, such that seeds[nid][tid]
        is the shared secret between nym nid and trustee tid
        Attributes
          full (Bits): the or of all client cells
          trapmask (Bits): negation of full (0 where any client's code is 1)
          bloom (dict: Bits -> int): Maps encoded cells to the index of the
            nym whose request it is
        """
        self.bloom = {}
        self.full = Bits(cell_bit_length)
        for i in range(len(seedlist)):
            key = cell_from_seeds(seedlist[i])
            self.bloom[key] = i
            self.full |= key
        self.trapmask = ~self.full

    def trap_noise(self, count):
        return NotImplemented

    def check(self, cell):
        """ Verify that the cell's trap bits have not been flipped """
        if cell & self.trapmask != Bits(cell_bit_length):
            print("Bad trap bit in request cell: Got {0}, mask was {1}"
                  .format(cell & self.trapmask, self.trapmask))
            return False
        return True

class RequestEncoder:
    def __init__(self, seeds=None):
        self.cell = cell_from_seeds(seeds)

    def encode(self, cell=None):
        """ Encodes a request for a cell into the shared request cell.
            The argument is ignored.
            """
        return self.cell

    def decoded_size(self, size):
        return NotImplemented

    def encoded_size(self, size):
        return -(-cell_bit_length // 8)

class RequestDecoder(RequestChecker):
    def decode(self, cell):
        """ Takes a request cell containing one or more requests for slots and
        grants all of them """
        nyms = []
        for key in self.bloom.keys():
            if cell & key == key:
                nyms.append(self.bloom[key])
        return nyms

class Test(unittest.TestCase):
    def setUp(self):
        self.e = RequestEncoder([1, 2, 3])
        self.c = RequestChecker([[1, 2, 3]])
        self.d = RequestDecoder([[1, 2, 3]])

    def test_cells_from_seeds(self):
        self.assertEqual(cell_from_seeds([1, 2, 3]), cell_from_seeds([1, 2, 3]))

    def test_encode(self):
        ecell = self.e.encode()
        self.assertEqual(self.c.full, ecell)
    
    def test_decode(self):
        ecell = self.e.encode()
        self.assertEqual(self.d.decode(ecell), [0])

    def test_check(self):
        ecell = self.e.encode()
        self.assertTrue(self.c.check(ecell))
    
    def test_bloom(self):
        """ Tests that the result of multiple insertions of encoded()'s is a
        superset of the encoded cells, for multiple random sets """
        nymseeds = {}
        encs = []
        for i in range(10):
            nymseeds[i] = []
            for _ in range(10):
                nymseeds[i].append(random.randint(0, 9))
            encs.append(RequestEncoder(nymseeds[i]))
        for trial in range(30):
            samplesize = random.randint(1, len(nymseeds))
            nyms = sorted(random.sample(range(len(nymseeds)), samplesize))
            these_encs = [encs[i] for i in nyms]
            cell = Bits(cell_bit_length)
            for enc in these_encs:
                cell |= enc.encode()
            d = RequestDecoder(nymseeds)
            self.assertEqual(d.full | cell, d.full)
            self.assertTrue(d.check(cell))
            decoded = d.decode(cell)
            for elt in nyms:
                self.assertTrue(elt in decoded)

if __name__ == '__main__':
    unittest.main()
