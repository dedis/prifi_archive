import argparse
import json
import os
import random
import socket
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

def main():
    global client

    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # load the public system data
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustees = data["servers"]
        trustee_keys = [PublicKey(global_group, t["key"]) for t in trustees]
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

    # start new client using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_id = data["id"]
        private_key = PrivateKey(global_group, data["private_key"])
    with open(os.path.join(opts.config_dir, "{}-{}.json".format(client_id, session_id)), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        nym_private_key = PrivateKey(global_group, data["private_key"])

    client = dcnet.Client(private_key, trustee_keys, NullCertifier(), NullEncoder())
    client.add_own_nym(nym_private_key)
    client.add_nyms(slot_keys)
    client.sync(None, [])

    # connect to the relay
    relay_host = relay_address[0]
    relay_port = int(relay_address[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((relay_host, relay_port))

    # stream the ciphertext to the relay
    for i, slot in enumerate(slot_keys):
        ciphertext = client.produce_ciphertexts()
        cleartext = long_to_bytes(0)
        if slot.element == nym_private_key.element:
            message = bytes("Hello", "UTF-8")
            cleartext = bytearray(dcnet.cell_length)
            length = len(message)
            cleartext[:2] = long_to_bytes(length, 2)
            cleartext[2:2+length] = message
        ciphertext = long_to_bytes(
                bytes_to_long(ciphertext) ^ bytes_to_long(cleartext),
                blocksize=dcnet.cell_length)
        n = sock.send(ciphertext)
        cleartext = sock.recv(dcnet.cell_length)
        length = bytes_to_long(cleartext[:2])
        assert length <= dcnet.cell_length - 2
        print(cleartext[2:2+length], file=sys.stderr)

if __name__ == "__main__":
    main()
