import argparse
import json
import os
import random
import requests
import select
import socket
from Crypto.Util.number import long_to_bytes, bytes_to_long

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
    # XXX don't rely on connection order hack
    tsocks = [None] * n_trustees
    for i in range(n_trustees):
        sock, addr = ssock.accept()
        tsocks[i] = sock
    csocks = [None] * n_clients
    for i in range(n_clients):
        sock, addr = ssock.accept()
        csocks[i] = sock

    inputs = []
    outputs = []

    downstream_queue = []
    conns = {}

    # XXX define elsewhere
    downcellmax = 64*1024
    socks_address = ("localhost", 8080)

    while True:
        # queue up any downstream data
        # XXX may need to move this into separate per connection threads
        # goroutines make it soooo much cleaner
        readable, writeable, exceptional = select.select(inputs, outputs, inputs, 0)
        for r in readable:
            downstream = memoryview(bytearray(downcellmax))
            n = r.recv_into(downstream[6:])
            # XXX ugly lookup, probably need wrapper struct with cno
            for cno, conn in conns.items():
                if conn == r:
                    print("socks relay down: {} bytes on cno {}".format(n, cno))
                    downstream[:4] = long_to_bytes(cno, 4)
                    downstream[4:6] = long_to_bytes(n, 2)
                    downstream_queue.append(downstream[:6+n])
                    # close the connection to socks relay
                    if n == 0:
                        r.close()
                        inputs.remove(r)
                        del conns[cno]
                    break

        # see if there's anything to send
        if len(downstream_queue) > 0:
            downstream = downstream_queue[0]
            del downstream_queue[:1]
        else:
            downstream = bytearray(6)

        # send downstream to all clients
        cno = bytes_to_long(downstream[:4])
        dlen = bytes_to_long(downstream[4:6])
        if dlen > 0:
            print("downstream to clients: {} bytes on cno {}".format(dlen, cno))
        for csock in csocks:
            n = csock.send(downstream)

        # get trustee ciphertexts
        relay.decode_start()
        for tsock in tsocks:
            tslice = tsock.recv(dcnet.cell_length)
            relay.decode_trustee(tslice)

        # and client upstream ciphertexts
        for csock in csocks:
            cslice = csock.recv(dcnet.cell_length)
            relay.decode_client(cslice)

        # decode the actual upstream
        upstream = relay.decode_cell()
        cno = bytes_to_long(upstream[:4])
        uplen = bytes_to_long(upstream[4:6])

        if cno == 0:
            continue
        conn = conns.get(cno)
        if conn == None:
            # new connection to local socks server
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect(socks_address)
            inputs.append(conn)
            conns[cno] = conn

        print("upstream sending {} bytes on cno {}".format(uplen, cno))
        n = conn.send(upstream[6:6+uplen])

if __name__ == "__main__":
    main()
