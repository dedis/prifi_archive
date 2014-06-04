import argparse
import json
import os
import random
import shutil

from dcnet import G, P, Q

def random_dh_key():
    # The secret should be the same bit length as P.
    return random.randrange(1 << (P.bit_length() - 1), P - 1)

def main():
    p = argparse.ArgumentParser(description="Generate DC-net keys")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=8, dest="n_clients")
    p.add_argument("output_dir")
    opts = p.parse_args()
    print("Generating keys for {} clients.".format(opts.n_clients))

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    priv_keys = [random_dh_key() for i in range(opts.n_clients)]
    pub_keys = [pow(G, key, P) for key in priv_keys]

    with open(os.path.join(opts.output_dir, "client.json"), "w", encoding="utf-8") as fp:
        json.dump({"public_keys": pub_keys}, fp)
    for i, priv_key in enumerate(priv_keys):
        with open(os.path.join(opts.output_dir, "client-{}.json".format(i)), "w", encoding="utf-8") as fp:
            json.dump({"n": i, "private_key": priv_key}, fp)

if __name__ == "__main__":
    main()
