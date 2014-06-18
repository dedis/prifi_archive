import argparse
import json
import os
import random

import dcnet

def main():
    p = argparse.ArgumentParser(description="Local, insecure DC-net test")
    p.add_argument("data_dir")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="n_clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="n_trustees")
    opts = p.parse_args()

    # start multiple clients in the same process
    clients = []
    n_clients = opts.n_clients
    for i in range(n_clients):
        with open(os.path.join(opts.data_dir, "client-{}.json".format(i)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            client_id = data["n"]
            private_key = data["private_key"]
            clients.append(dcnet.Client(client_id, private_key))

    # same with trustees
    trustees = []
    n_trustees = opts.n_trustees
    for i in range(n_trustees):
        with open(os.path.join(opts.data_dir, "trustee-{}.json".format(i)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            trustee_id = data["n"]
            private_key = data["private_key"]
            trustees.append(dcnet.Trustee(trustee_id, private_key))

    # give everyone the public session data
    with open(os.path.join(opts.data_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_public_keys = data["trustee_public_keys"][:n_trustees]
        for client in clients:
            client.compute_secrets(trustee_public_keys)
        client_public_keys = data["client_public_keys"][:n_clients]
        for trustee in trustees:
            trustee.compute_secrets(client_public_keys)

    # start a single relay
    relay = dcnet.Relay()
    relay.decode_start()

    # run for one cell (first client gets ownership)
    messages = ["This is client-0's message.".encode("utf-8")]
    messages += [None] * (n_clients - 1)
    for i, client in enumerate(clients):
        cell = client.encode(len(messages[0]), messages[i])
        relay.decode_client(i, cell)
    for i, trustee in enumerate(trustees):
        cell = trustee.encode(len(messages[0]))
        relay.decode_trustee(i, cell)

    # make sure the message survives
    print(relay.decode_final().decode("utf-8"))

if __name__ == "__main__":
    main()
