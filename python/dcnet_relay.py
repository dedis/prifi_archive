import argparse
import json
import os
import random
import requests
import socket

import dcnet

from dh import PublicKey, PrivateKey

def main():
    global relay

    p = argparse.ArgumentParser(description="Basic DC-net relay")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # load addresses and public keys from system config
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_keys = [PublicKey(c["key"]) for c in data["clients"]]
        trustee_keys = [PublicKey(t["key"]) for t in data["servers"]]
        n_clients = len(client_keys)
        n_trustees = len(trustee_keys)

    # start up a new relay
    relay = dcnet.Relay(n_trustees)
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
        
    # get trustee ciphertexts
    for i, tsock in enumerate(tsocks):
        cells_for_nyms = []
        cell_count = 1
        for j in range(n_clients):
            ciphertext = []
            for k in range(cell_count):
                tslice = tsock.recv(dcnet.cell_length)
                ciphertext.append(tslice)
            cells_for_nyms.append(ciphertext)
        relay.store_trustee_ciphertext(i, cells_for_nyms)

    # and client upstream ciphertexts
    ciphertexts = []
    for i, csock in enumerate(csocks):
        cells_for_nyms = []
        cell_count = 1
        for j in range(n_clients):
            cells = []
            for k in range(cell_count):
                cslice = csock.recv(dcnet.cell_length)
                cells.append(cslice)
            cells_for_nyms.append(cells)
        ciphertexts.append(cells_for_nyms)

    # retrieve the cleartext
    print(relay.process_ciphertext(ciphertexts))

if __name__ == "__main__":
    main()
