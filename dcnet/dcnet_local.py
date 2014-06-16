import argparse
import json
import os
import random

import dcnet

def main():
    p = argparse.ArgumentParser(description="Local, insecure DC-net test")
    p.add_argument("data_dir")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=8, dest="n_clients")
    opts = p.parse_args()

    # start multiple clients in the same process
    clients = list()
    for i in range(opts.n_clients):
        with open(os.path.join(opts.data_dir, "client-{}.json".format(i)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            client_id = data["n"]
            private_key = data["private_key"]
            clients.append(dcnet.Client(client_id, private_key))
    with open(os.path.join(opts.data_dir, "client.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        public_keys = data["public_keys"][:opts.n_clients]
        for client in clients:
            client.compute_secrets(public_keys)

    # run for one exchange (each client gets one slot)
    for i, client in enumerate(clients):
        message = "This is client-{}'s message.".format(i)
        transmission = client.prepare_exchange(0, message)
        for j, receiver in enumerate(clients):
            messages = receiver.handle_exchange(0, i, transmission)
            if messages is not None:
                for k, message in enumerate(messages):
                    print("{}: {}".format(j, message))

if __name__ == "__main__":
    main()
