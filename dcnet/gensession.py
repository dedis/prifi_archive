import argparse
import json
import os
import random
import shutil

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from dcnet import G, P, Q
from gensystem import random_dh_key

def main():
    p = argparse.ArgumentParser(description="Generate session config from system config")
    p.add_argument("output_dir")
    opts = p.parse_args()
    print("Generating session config from {}".format(os.path.join(opts.output_dir, "system.json")))

    # load in the system config
    with open(os.path.join(opts.output_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        relays = data["relays"]
        clients = data["clients"]
        servers = data["servers"]

    n_relays = len(relays)
    n_clients = len(clients)
    n_servers = len(servers)
    ids = [entity["id"] for entity in relays + clients + servers]

    # generate session key pairs
    n = n_relays + n_clients + n_servers
    priv_keys = [random_dh_key() for i in range(n)]
    pub_keys = [pow(G, key, P) for key in priv_keys]

    entities = [
        {
            "id" : ids[i],
            "dhkey" : pub_keys[i],
        }
        for i in range(n)
    ]
    relays = entities[:n_relays]
    clients = entities[n_relays : n_relays + n_clients]
    servers = entities[n_relays + n_clients:]

    # XXX session_id generated how?
    # XXX trustee signatures
    group_id = data["group-id"]
    session_id = 1
    session = {
        "group-id" : group_id,
        "session-id" : session_id,
        "relays" : relays,
        "clients" : clients,
        "servers" : servers,
    }

    with open(os.path.join(opts.output_dir, "session.json"), "w", encoding="utf-8") as fp:
        json.dump(session, fp)

    # give each entity it's own private session data
    for iden, key in zip(ids, priv_keys):
        with open(os.path.join(opts.output_dir, "{}-{}.json".format(iden, session_id)), "w", encoding="utf-8") as fp:
            json.dump({"id": iden, "private_key": key}, fp)

if __name__ == "__main__":
    main()
