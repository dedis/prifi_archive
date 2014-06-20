import argparse
import json
import os
import random
import shutil

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from dcnet import G, P, Q

def random_dh_key():
    # The secret should be the same bit length as P.
    return random.randrange(1 << (P.bit_length() - 1), P - 1)

def main():
    p = argparse.ArgumentParser(description="Generate system configuration")
    p.add_argument("-r", "--relays", type=int, metavar="N", default=1, dest="n_relays")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="n_clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="n_trustees")
    p.add_argument("output_dir")
    opts = p.parse_args()
    print("Generating system config for {} relays, {} clients, and {} trustees.".format(opts.n_relays,
            opts.n_clients, opts.n_trustees))

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    # generate long-lived key pairs and ids
    n = opts.n_relays + opts.n_clients + opts.n_trustees
    priv_keys = [random_dh_key() for i in range(n)]
    pub_keys = [pow(G, key, P) for key in priv_keys]
    ids = [SHA256.new(long_to_bytes(p)).hexdigest() for p in pub_keys]
    ips = ["localhost:{}".format(12345 + i) for i in range(n)]

    entities = [
        {
            "id" : ids[i],
            "key" : pub_keys[i],
            "ip" : ips[i],
        }
        for i in range(n)
    ]

    # XXX group_id generated how?
    group_id = 1
    system = {
        "version" : 1,
        "group-id" : group_id,
        "relays" : entities[:opts.n_relays],
        "clients" : entities[opts.n_relays : opts.n_relays + opts.n_clients],
        "servers" : entities[opts.n_relays + opts.n_clients:],
    }

    with open(os.path.join(opts.output_dir, "system.json"), "w", encoding="utf-8") as fp:
        json.dump(system, fp)

    # give each entity it's own private data
    for iden, key in zip(ids, priv_keys):
        with open(os.path.join(opts.output_dir, "{}.json".format(iden)), "w", encoding="utf-8") as fp:
            json.dump({"id": iden, "private_key": key}, fp)

if __name__ == "__main__":
    main()
