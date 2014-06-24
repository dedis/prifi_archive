import argparse
import json
import os
import random
import shutil

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from dh import PublicKey, PrivateKey

def main():
    p = argparse.ArgumentParser(description="Generate system configuration")
    p.add_argument("-r", "--relays", type=int, metavar="N", default=1, dest="n_relays")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="n_clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="n_trustees")
    p.add_argument("output_dir")
    opts = p.parse_args()

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    n = opts.n_relays + opts.n_clients + opts.n_trustees

    # generate long-lived key pairs and ids
    priv_keys = [PrivateKey() for i in range(n)]
    pub_keys = [key.pubkey for key in priv_keys]
    ids = [SHA256.new(long_to_bytes(key.y)).hexdigest() for key in pub_keys]

    # configure local topology for testing
    ips = ["localhost:{}".format(12345 + i) for i in range(n)]

    entities = [
        {
            "id" : ids[i],
            "key" : pub_keys[i].y,
            "ip" : ips[i],
        }
        for i in range(n)
    ]

    # XXX group_id generated how? hash of config?
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
            json.dump({"id": iden, "private_key": key.x}, fp)

    print("Generated system config for {} relays, {} clients, and {} trustees.".format(opts.n_relays,
            opts.n_clients, opts.n_trustees))

if __name__ == "__main__":
    main()
