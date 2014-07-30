import numpy
import random
import matplotlib
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import cells.request_tuning as opt
from cells.request import RequestChecker

def tradeoff_axes(n, steps=20):
    """ Generate the arguments to plot_surface for tests of various p and hp
    values and n clients.
    inputs:
      X, Y are the results of numpy.meshgrid
      Steps is the number of points between 0 and 1 to
        test.

    """
    xs = [x * 1/steps for x in range(1, steps + 1)]
    ys = [y * 1 / steps for y in range(1, steps + 1)]
    X, Y = numpy.meshgrid(xs, ys)
    zs = numpy.array([[float('nan')] * steps] * steps)
    for x in range(len(X)):
        for y in range(len(Y[0])):
            hp = X[x][y]
            p = Y[x][y]
            _, b = opt.findb(n, p, hp)
            zs[x][y] = b
    return X, Y, zs

def tradeoff_scatter(n, steps=20):
    xs = []
    ys = []
    zs = []
    for x in range(1, steps + 1):
        hp = x * 1/steps
        for y in range(1, steps + 1):
            p = y * 0.4 / steps
            _, b = opt.findb(n, p, hp)
            if b != float('nan'):
                xs.append(hp)
                ys.append(p)
                zs.append(b)
    return xs, ys, zs

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
                c = RequestChecker(seedlist, cell_bit_length, request_bits)
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
    r = lambda n: random.random() * 2.5 * n
    steps = 10
    proxies = []
    labels = []
    for n in range(10, 100, 10):
        # Assign each n a random color
        clr = '#%02X%02X%02X' % (r(n), r(n), r(n))
        xs, ys, nzs = tradeoff_axes(n, steps)
        ax.plot_surface(xs, ys, nzs, color=clr, alpha=0.8, rstride=1, cstride=1, linewidth=0.1)
#         xs, ys, zs = tradeoff_scatter(n, steps)
#         ax.scatter(xs, ys, zs, c=clr)
        proxies.append(matplotlib.lines.Line2D([0], [0], c=clr))
        labels.append("{0} clients".format(n))
    # Makes the legend match what the layers of the graph look like
    ax.legend(reversed(proxies), reversed(labels))
    plt.legend()
    plt.title("Number of bits required to achieve security properties")
    plt.xlabel("Probability of any hash collisions")
    plt.ylabel("Proportion of bits that are traps")
    plt.show()

if __name__ == '__main__':
    graph_tradeoffs()
