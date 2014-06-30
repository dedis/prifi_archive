import argparse
import json
import os
import random
import requests
import socket

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

def main():
    global relay

    p = argparse.ArgumentParser(description="Basic DC-net relay")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # load addresses and public keys from system config
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_keys = [PublicKey(global_group, c["key"]) for c in data["clients"]]
        trustee_keys = [PublicKey(global_group, t["key"]) for t in data["servers"]]
        n_clients = len(client_keys)
        n_trustees = len(trustee_keys)

    # start up a new relay
    relay = dcnet.Relay(n_trustees, NullAccumulator(), NullDecoder())
    relay.add_nyms(n_clients)
    relay.sync(None)

    # server socket
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(("", opts.port))
    ssock.listen(5)

    # make sure everybody connects
    tsocks = [None] * n_trustees
    for i in range(n_trustees):
        sock, addr = ssock.accept()
        tsocks[i] = sock
    csocks = [None] * n_clients
    for i in range(n_clients):
        sock, addr = ssock.accept()
        csocks[i] = sock

    # transfer some data
    for i in range(n_clients):
        # get trustee ciphertexts
        relay.decode_start()
        for tsock in tsocks:
            tslice = tsock.recv(dcnet.cell_length)
            relay.decode_trustee(tslice)

        # and client upstream ciphertexts
        for csock in csocks:
            cslice = csock.recv(dcnet.cell_length)
            relay.decode_client(cslice)

        # send down to clients
        cleartext = relay.decode_cell()
        for csock in csocks:
            csock.send(cleartext)

if __name__ == "__main__":
    main()
