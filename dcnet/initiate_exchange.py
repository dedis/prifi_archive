import argparse
import requests

def main():
    p = argparse.ArgumentParser(description="Start up a number of clients on localhost")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=4, dest="n_clients")
    opts = p.parse_args()

    for i in range(opts.n_clients):
        r = requests.post("http://localhost:{}/start".format(i + 12345))
    print("Initiated exchange on {} clients".format(opts.n_clients))

if __name__ == "__main__":
    main()
