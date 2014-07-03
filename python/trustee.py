import argparse
import json
import os
import random
import requests
import socket
import sys

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

def main():
    global trustee

    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # load the public system data
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        clients = data["clients"]
        client_ids = [c["id"] for c in clients]
        client_keys = [PublicKey(global_group, c["key"]) for c in clients]
        relay_address = data["relays"][0]["ip"].split(":")

    # and session data
    with open(os.path.join(opts.config_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        session_id = data["session-id"]
        nym_keys = [PublicKey(global_group, c["dhkey"]) for c in data["clients"]]

    # load the post-shuffle slots
    with open(os.path.join(opts.config_dir, "shuffle.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        slot_keys = [PublicKey(global_group, s) for s in data["slots"]]

    # start new trustee using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_id = data["id"]
        private_key = PrivateKey(global_group, data["private_key"])
    trustee = dcnet.Trustee(private_key, client_keys)
    trustee.add_nyms(slot_keys)
    trustee.sync(None)

    # connect to the relay
    relay_host = relay_address[0]
    relay_port = int(relay_address[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((relay_host, relay_port))

    # stream the ciphertext to the relay
    while True:
        ciphertext = trustee.produce_ciphertext()
        n = sock.send(ciphertext)

if __name__ == "__main__":
    main()
