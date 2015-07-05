#!/usr/local/bin/python
import argparse
import redis
import time
import sys

parser = argparse.ArgumentParser(description='Local version of emulab-sync')
parser.add_argument("-i", "--init", help="initialize sync", type=int)
parser.add_argument("-n", "--name", help="sync name")
args = parser.parse_args()

r = redis.StrictRedis(host='localhost', port=6379, db=0)

def waitForZero(name):
    sys.stdout.flush()
    while True:
        if r.get(name) == '0':
            return
        time.sleep(0.2)

if args.init is None:
    sys.stdout.flush()
    r.decr(args.name)
    waitForZero(args.name)
else:
    sys.stdout.flush()
    r.incrby(args.name, args.init)
    waitForZero(args.name)
