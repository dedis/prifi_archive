#!/usr/bin/env python
from Crypto.Hash import SHA256
import random
from bitstring import Bits
from Crypto.Util.number import long_to_bytes, bytes_to_long
import unittest
import math
import functools

clients = 10
trap_flip_risk = .1
hash_collision_risk = 0.01

def request_cell_length():
    opt = Optimizer(clients, trap_flip_risk)
    r, b = opt.findb(clients, trap_flip_risk, hash_collision_risk)
    print("Request cell length: {0}. Bits per client: {1}".format(b, r))
    return b

class RequestBase():
    def __init__(self, clients, trap_flip_risk, hash_collision_risk=0.01):
        opt = Optimizer(clients, trap_flip_risk)
        self.request_bits, self.cell_bit_length = opt.findb(clients,
                                                            trap_flip_risk,
                                                            hash_collision_risk)

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
        return bytes_to_long(Bits(cell).tobytes())

class RequestChecker(RequestBase):
    def __init__(self, seedlist):
        """ seeds is a list of lists of trap secrets, such that seeds[nid][tid]
        is the shared secret between nym nid and trustee tid
        Attributes
          full (Bits): the or of all client cells
          trapmask (Bits): negation of full (0 where any client's code is 1)
          bloom (dict: Bits -> int): Maps encoded cells to the index of the
            nym whose request it is
        """
        super().__init__(clients, trap_flip_risk, hash_collision_risk)
        self.bloom = {}
        self.full = 0
        for i in range(len(seedlist)):
            key = self.cell_from_seeds(seedlist[i])
            print("Adding key {0} for val {1} to bloom".format(bin(key), i))
            if key in self.bloom.keys():
                print("Ouch, a hash collision!")
            self.bloom[key] = i
            self.full |= key
        print("Full: {0}".format(bin(self.full)))
        # long to bytes apparently can't handle negatives, so use bits intsead
        self.trapmask = ~Bits(uint=self.full, length=self.cell_bit_length)
        self.trapcount = sum((~self.full >> i) & 0x1 \
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
        return long_to_bytes(self.cell)

    def decoded_size(self, size):
        return NotImplemented

    def encoded_size(self, size):
        return -(-self.cell_bit_length // 8)

class RequestDecoder(RequestChecker):
    def decode(self, cell):
        """ Takes a request cell containing one or more requests for slots and
        grants all of them """
        nyms = []
        lcell = bytes_to_long(cell)
        for key in self.bloom.keys():
            print("Cell: {0}\n key: {1}\n and: {2} = key? {3} thus: {4}"
                  .format(bin(lcell), bin(key), bin(lcell & key), lcell & key == key, self.bloom[key]))
            if lcell & key == key:
                nyms.append(self.bloom[key])
                print("Appended {0}. now nyms is {1}"
                      .format(self.bloom[key], nyms))
        return nyms

class Optimizer:
    """ Class for efficiently computing optimal (or at least good) parameters
    for request encoders """
    def __init__(self, n, p):
        """ p is the desired probability that any single bit will be a trap bit.
        n is the number of clients. """
        # pn has no special properties, it just makes the algebra cleaner
        self.pn = (p * (n + 1) / n) ** (1 / (n + 1))
        # the max number of request bits per client - this is the highest
        # factorial we will need to compute
        rmax = math.ceil(15 * n - 15 * n * self.pn - 1)
        # dynamic programming table for factorials
        self.factable = [1] * rmax
        for i in range(1, rmax):
            self.factable[i] = self.factable[i - 1] * i

    def dpf(self, n):
        """ (D)ynamic (P)rogramming (F)actorial:
        Try to retrieve n! from the pre-computed factorial table """
        if n >= len(self.factable):
            print("Didn't compute n fact: {0}".format(n))
            raise(Exception)  # the table should always be big enough,
                            # so this is an error.
            return math.factorial(n)
        return self.factable[n]

    def pno(self, n, r, b):
        """ (P)robability that there are (no) hash collisions.
        n is the number of pseudonyms
        r is the number of bits each pseudonym sets to 1 in their encoded
          request cell
        b is the number of bits in the request cell
        """
        assert(b >= r)
        ncr = self.nCr(b, r)
        if ncr < n:
            # there are fewer than n unique combinations of r bits from b, so
            # there is a 100% chance of hash collisions.
            return 0
        return self.nPr(ncr, n) / ncr ** n

    @functools.lru_cache()
    def nCr(self, n, r):
        """ From an (n) element set, the number of unordered (C)ombinations of
        (r) elements that can be chosen from it """
        rf = self.dpf(r)
        part = self.partFact(n - r, n)
        return part // rf

    def nPr(self, n, r):
        """ From an (n) element set, the number of (P)ermutations of (r)
        elements that can be drawn from it. """
        return self.partFact(n - r, n)

    @functools.lru_cache()
    def partFact(self, l, h):
        """ The product of all integers in the interval (l, h], h > l.

        Textbook nCr and nPr use factorials to approximate multiplying all
        consecutive integers between two integers much higher than 1. partFact
        computes this directly instead of computing both factorials.
        """
        if l >= h:
            return 1
        else:
            return h * self.partFact(l, h - 1)

    def findb(self, n, p, hp):
        """ Experimentally determine the smallest number of bits required to
        have a probability of hash collisions (two pseudonyms with the same
        encoded cell contents) below hp.
        inputs:
          n: the number of pseudonyms
          p: the desired probability that an arbitrary bit is a trap bit
          hp: the desired maximum probability that multiple pseudonyms hash to
            the same cell encoding
        outputs:
          r: the number of bits each encoder should set to 1 in their encoded
            request cell
          b: the size in bits of the request cell
        """
        self.pn = (p * (n + 1) / n) ** (1 / (n + 1))
        for b in range(math.ceil(n / 8) * 8, math.ceil(n / 8) * 8 * 15, 8):
            r = math.ceil(b - b * self.pn - 1)
            h = self.pno(n, r, b)
            if h > 1 - hp:
                return r, b

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
        self.assertEqual(self.c.full, bytes_to_long(ecell))
    
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
            cell = 0
            for enc in these_encs:
                cell |= bytes_to_long(enc.encode())
            self.assertEqual(d.full | cell, d.full)
            self.assertTrue(d.check(long_to_bytes(cell)))
            print("DONE CHECKING NOW DECODING")
            decoded = sorted(d.decode(long_to_bytes(cell)))
            print("DONE CHECKING NOW VERIFYING")
            for elt in nyms:
                self.assertTrue(elt in decoded,
                                msg="nyms: {0} decoded: {1}\n"
                                .format(nyms, decoded) + \
                                "encs: {0}\n cell: {1}"
                                .format([i.encode() for i in encs], cell))

if __name__ == '__main__':
    unittest.main()
