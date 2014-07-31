import functools
import math

""" Module for efficiently computing optimal (or at least good) parameters
for request encoders """

# This is used to precompute factorials - the actual number of clients is passed in.
max_clients = 200
# the max number of request bits per client - this is the highest
# factorial we will need to compute
rmax = 8 * max_clients
# dynamic programming table for factorials
factable = [1] * rmax
for i in range(1, rmax):
    factable[i] = factable[i - 1] * i

@functools.lru_cache()
def findb(n, p, hp):
    """ Experimentally determine the smallest number of bits required to
    have a probability of hash collisions (two pseudonyms with the same
    encoded cell contents) below hp. Returns 0,0 if not possible.
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
    br = math.log(p) / n
#     for b in range(8, math.ceil(n / 8) * 8 * 15, 8):
    for b in range(8, math.ceil(n / 8) * 8 + 1, 8):
        r = math.ceil(br / math.log((b-1) / b))
        h = __pno(n, r, b)
        if h > 1 - hp:
            return r, b
    return float('nan'), float('nan')
## Low level helper functions

def __dpf(n):
    """ (D)ynamic (P)rogramming (F)actorial:
    Try to retrieve n! from the pre-computed factorial table """
    if n >= len(factable):
        print("Didn't compute n fact: {0}".format(n))
        raise(Exception)  # the table should always be big enough,
                        # so this is an error.
        return math.factorial(n)
    return factable[n]

def __pno(n, r, b):
    """ (P)robability that there are (no) hash collisions.
    n is the number of pseudonyms
    r is the number of bits each pseudonym sets to 1 in their encoded
      request cell
    b is the number of bits in the request cell
    """
    assert(b >= r)
    ncr = __nCr(b, r)
    if ncr < n:
        # there are fewer than n unique combinations of r bits from b, so
        # there is a 100% chance of hash collisions.
        return 0
    return __nPr(ncr, n) / ncr ** n

@functools.lru_cache()
def __nCr(n, r):
    """ From an (n) element set, the number of unordered (C)ombinations of
    (r) elements that can be chosen from it """
    small = min(r, n - r)
    smallf = __dpf(small)
    if n >= len(factable):
        part = __partFact(n - small, n)
    else:
        part = __dpf(n) // __dpf(n - small)
    return part // smallf

def __nPr(n, r):
    """ From an (n) element set, the number of (P)ermutations of (r)
    elements that can be drawn from it. """
    return __partFact(n - r, n)

@functools.lru_cache()
def __partFact(l, h):
    """ The product of all integers in the interval (l, h], h > l.

    Textbook nCr and nPr use factorials to approximate multiplying all
    consecutive integers between two integers much higher than 1. partFact
    computes this directly instead of computing both factorials.
    """
    if l >= h:
        return 1
    else:
        return h * __partFact(l, h - 1)

if __name__ == '__main__':
    print(findb(10,.5,.5))