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
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="n_clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="n_trustees")
    p.add_argument("output_dir")
    opts = p.parse_args()
    print("Generating keys for {} clients and {} trustees.".format(opts.n_clients, opts.n_trustees))

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    client_priv_keys = [random_dh_key() for i in range(opts.n_clients)]
    client_pub_keys = [pow(G, key, P) for key in client_priv_keys]

    trustee_priv_keys = [random_dh_key() for i in range(opts.n_trustees)]
    trustee_pub_keys = [pow(G, key, P) for key in trustee_priv_keys]

    session = {
        "client_public_keys" : client_pub_keys,
        "trustee_public_keys" : trustee_pub_keys,
    }

    with open(os.path.join(opts.output_dir, "session.json"), "w", encoding="utf-8") as fp:
        json.dump(session, fp)
    for i, priv_key in enumerate(client_priv_keys):
        with open(os.path.join(opts.output_dir, "client-{}.json".format(i)), "w", encoding="utf-8") as fp:
            json.dump({"n": i, "private_key": priv_key}, fp)
    for i, priv_key in enumerate(trustee_priv_keys):
        with open(os.path.join(opts.output_dir, "trustee-{}.json".format(i)), "w", encoding="utf-8") as fp:
            json.dump({"n": i, "private_key": priv_key}, fp)

if __name__ == "__main__":
    main()
