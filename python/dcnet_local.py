import argparse
import json
import os
import time

import dcnet

from dh import PublicKey, PrivateKey

def main():
    t0 = time.time()

    p = argparse.ArgumentParser(description="Local, insecure DC-net test")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # load the public system data
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        clients = data["clients"]
        client_ids = [c["id"] for c in clients]
        client_keys = [PublicKey(c["key"]) for c in clients]
        trustees = data["servers"]
        trustee_ids = [t["id"] for t in trustees]
        trustee_keys = [PublicKey(t["key"]) for t in trustees]

    # and session data
    with open(os.path.join(opts.config_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        session_id = data["session-id"]
        nym_keys = [PublicKey(c["dhkey"]) for c in data["clients"]]

    # load the post-shuffle slots
    with open(os.path.join(opts.config_dir, "shuffle.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        slot_keys = [PublicKey(s) for s in data["slots"]]

    # start multiple clients in the same process
    # load private keys from individual files
    clients = []
    for iden in client_ids:
        with open(os.path.join(opts.config_dir, "{}.json".format(iden)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            private_key = PrivateKey(data["private_key"])
        with open(os.path.join(opts.config_dir, "{}-{}.json".format(iden, session_id)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            nym_private_key = PrivateKey(data["private_key"])
        client = dcnet.Client(private_key, trustee_keys)
        client.add_own_nym(nym_private_key)
        client.add_nyms(slot_keys)
        clients.append(client)

    # same with trustees
    trustees = []
    for iden in trustee_ids:
        with open(os.path.join(opts.config_dir, "{}.json".format(iden)), "r", encoding="utf-8") as fp:
            data = json.load(fp)
            private_key = PrivateKey(data["private_key"])
        trustee = dcnet.Trustee(private_key, client_keys)
        trustee.add_nyms(slot_keys)
        trustees.append(trustee)

    # start a single relay
    relay = dcnet.Relay(len(trustees))
    relay.add_nyms(len(clients))
    relay.sync(None)

    trap_keys = []
    for trustee in trustees:
        trustee.sync(None)
        trap_keys.append(trustee.trap_keys[-1].pubkey)

    for client in clients:
        client.sync(None, trap_keys)

    for idx in range(len(trustees)):
        trustee = trustees[idx]
        ciphertext = trustee.produce_interval_ciphertext()
        relay.store_trustee_ciphertext(idx, ciphertext)

    client_ciphertexts = []
    for client in clients:
        client_ciphertexts.append(client.produce_ciphertexts())
    print(relay.process_ciphertext(client_ciphertexts))

    print(time.time() - t0)
    t0 = time.time()

    client_ciphertexts = []
    for client in clients:
        client.send(client.own_nym_keys[0][1], bytes("Hello", "UTF-8"))
        client_ciphertexts.append(client.produce_ciphertexts())
    print(relay.process_ciphertext(client_ciphertexts))

    print(time.time() - t0)
    t0 = time.time()

if __name__ == "__main__":
    main()
