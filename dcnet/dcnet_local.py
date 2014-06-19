import argparse
import json
import os
import random

import dcnet

def main():
    p = argparse.ArgumentParser(description="Local, insecure DC-net test")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # load the public session data
    with open(os.path.join(opts.config_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        session_id = data["session-id"]
        relay_ids = [r["id"] for r in data["relays"]]
        client_ids, client_keys = zip(*[(c["id"], c["dhkey"]) for c in data["clients"]])
        trustee_ids, trustee_keys = zip(*[(s["id"], s["dhkey"]) for s in data["servers"]])

    # start a single relay for now
    relay = dcnet.Relay()
    relay.decode_start()

    # start multiple clients in the same process
    clients = []
    for iden in client_ids:
        with open(os.path.join(opts.config_dir, "{}-{}.json".format(iden, session_id)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            private_key = data["private_key"]
            clients.append(dcnet.Client(iden, private_key))

    # same with servers
    trustees = []
    for iden in trustee_ids:
        with open(os.path.join(opts.config_dir, "{}-{}.json".format(iden, session_id)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            private_key = data["private_key"]
            trustees.append(dcnet.Trustee(iden, private_key))

    # share public keys
    for client in clients:
        client.compute_secrets(trustee_keys)
    for trustee in trustees:
        trustee.compute_secrets(client_keys)

    # load the post-shuffle slots
    with open(os.path.join(opts.config_dir, "shuffle.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        slots = data["slots"]

    # run for one slot
    messages = ["This is client-{}'s message.".format(i) for i in range(len(clients))]
    for i, client in enumerate(clients):
        if client_keys[i] == slots[0]:
            cell = client.encode(len(messages[0]), messages[i].encode("utf-8"))
        else:
            cell = client.encode(len(messages[0]), None)
        relay.decode_client(None, cell)
    for i, trustee in enumerate(trustees):
        cell = trustee.encode(len(messages[0]))
        relay.decode_trustee(None, cell)

    # make sure the message survives
    print(relay.decode_final().decode("utf-8"))

if __name__ == "__main__":
    main()
