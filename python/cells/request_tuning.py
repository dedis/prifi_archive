import functools
import math
import numpy
import matplotlib
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import random
import request

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
    for b in range(math.ceil(n / 8) * 8, math.ceil(n / 8) * 8 * 15, 8):
        r = math.ceil(br / math.log((b-1) / b))
        h = __pno(n, r, b)
        if h > 1 - hp:
            r = r
            b = b
            return r, b
    return 0,0

def tradeoff_axes(X, Y, n, steps=20):
    """ Generate the arguments to plot_surface for tests of various p and hp
    values and n clients.
    inputs:
      X, Y are the results of numpy.meshgrid
      Steps is the number of points between 0 and 1 to
        test.

    """
    zs = numpy.array([[0] * (steps - 1)] * (steps - 1))
    for x in range(len(X)):
        for y in range(len(Y[0])):
            hp = X[x][y]
            p = Y[x][y]
            _, b = findb(n, p, hp)
            zs[x][y] = b
    return zs

## Graphing
def expected_trap_bits(n, bit_length, request_bits):
    return bit_length * ((bit_length - 1) / bit_length) ** (request_bits * n)

def graph_trap_bits(request_bits=3, trials=5):
    xs = [] # Bit length
    ys = [] # Client number
    zs = [] # Experimental numbers of trap bits
    ezs = [] # Percentage error
    mzs = [] # Number of bits difference from expected
    for clients in range(20, 200, 10):
        for cell_bit_length in range(-(-clients // 8) * 8, 8 * clients,
                8 * -(-clients // 8)):
            expected = expected_trap_bits(clients, cell_bit_length, request_bits)
            for _ in range(trials):
                random.seed()
                seedlist = [random.sample(range(1, 100), 10) for _ in range(clients)]
                c = request.RequestChecker(seedlist, cell_bit_length, request_bits)
                xs.append(cell_bit_length)
                ys.append(clients)
                zs.append(c.trapcount)
                mzs.append(zs[-1] - expected)
                if c.trapcount > 0:
                    ezs.append((c.trapcount - expected) / c.trapcount)
                else:
                    ezs.append(0)
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    # Set up the predicted wireframe
    Xs = numpy.arange(1, 1200, 40)
    Ys = numpy.arange(1, 200, 20)
    Xs, Ys = numpy.meshgrid(Xs, Ys)
    tzs = Xs * ((Xs - 1) / Xs) ** (Ys * request_bits)
    # Plot the predicted wireframe
    ax.plot_wireframe(Xs, Ys, tzs)
    # Plot the experimental results
    ax.scatter(xs, ys, zs)
    # Uncomment to plot error margins instead
    # ax.scatter(xs, ys, ezs)
    plt.title("Number of Trap Bits, r = 3")
    plt.xlabel("Request Cell Bit Length")
    plt.ylabel("Number of Clients")
    print("Stdev: {0} Mean error: {1} Median error: {2}".format(numpy.std(mzs), numpy.mean(ezs), numpy.median(ezs)))
    plt.show()

def graph_tradeoffs():
    fig = plt.figure()
    ax = fig.gca(projection='3d')
    r = lambda: random.randint(0,255)
    steps = 10
    xs = [x * 1/steps for x in range(1, steps)]
    ys = [y * 1/steps for y in range(1, steps)]
    X, Y = numpy.meshgrid(xs, ys)
    proxies = []
    labels = []
    for n in range(10, 100, 10):
        # Assign each n a random color
        clr = '#%02X%02X%02X' % (r(),r(),r())
        nzs = tradeoff_axes(X, Y, n, 10)
        ax.plot_surface(X, Y, nzs, color=clr, alpha=0.5, rstride=1, cstride=1)
        proxies.append(matplotlib.lines.Line2D([0], [0], c=clr))
        labels.append("{0} clients".format(n))
    # Makes the legend match what the layers of the graph look like
    ax.legend(reversed(proxies), reversed(labels))
    plt.legend()
    plt.title("Number of bits required to achieve security properties")
    plt.xlabel("Probability of any hash collisions")
    plt.ylabel("Proportion of bits that are traps")
    plt.show()

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
    graph_tradeoffs()
    graph_trap_bits()

