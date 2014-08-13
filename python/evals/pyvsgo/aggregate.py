import statistics
import sys

datamap = {}
for line in sys.stdin:
    x, y = line.split()
    x, y = int(x), float(y)
    try:
        datamap[x].append(y)
    except:
        datamap[x] = [y]
for x, y in sorted(datamap.items()):
    y = sorted(y)[2:-2]     # remove outliers
    print(x, statistics.mean(y), statistics.stdev(y))
