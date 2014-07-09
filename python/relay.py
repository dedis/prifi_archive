import argparse
import json
import os
import queue
import random
import requests
import select
import socket
import threading
from Crypto.Util.number import long_to_bytes, bytes_to_long

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

# XXX define elsewhere
downcellmax = 64*1024
socks_address = ("localhost", 8080)

def socks_relay_down(cno, conn, downstream):
    while True:
        buf = memoryview(bytearray(downcellmax))
        n = conn.recv_into(buf[6:])
        print("socks_relay_down: {} bytes on cno {}".format(n, cno))
        buf[:4] = long_to_bytes(cno, 4)
        buf[4:6] = long_to_bytes(n, 2)
        downstream.put(buf[:6+n])

        # close the connection to socks relay
        if n == 0:
            print("socks relay down: cno {} closed".format(cno))
            conn.close()
            return

def socks_relay_up(cno, conn, upstream):
    while True:
        buf = upstream.get()
        dlen = len(buf)

        # client closed connection
        if dlen == 0:
            print("sock_relay_up: closing stream {}".format(cno))
            conn.close()
            return

        n = conn.send(buf)


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

    downstream = queue.Queue()
    conns = {}

    while True:
        # see if there's anything to send
        try:
            downbuf = downstream.get_nowait()
        except queue.Empty:
            downbuf = bytearray(6)

        # send downstream to all clients
        # XXX restructure to do away with extra parsing here
        cno = bytes_to_long(downbuf[:4])
        dlen = bytes_to_long(downbuf[4:6])
        if dlen > 0:
            print("downstream to clients: {} bytes on cno {}".format(dlen, cno))
        for csock in csocks:
            n = csock.send(downbuf)

        # get trustee ciphertexts
        relay.decode_start()
        for tsock in tsocks:
            tslice = tsock.recv(dcnet.cell_length, socket.MSG_WAITALL)
            relay.decode_trustee(tslice)

        # and client upstream ciphertexts
        for csock in csocks:
            cslice = csock.recv(dcnet.cell_length, socket.MSG_WAITALL)
            relay.decode_client(cslice)

        # decode the actual upstream
        outb = relay.decode_cell()
        cno = bytes_to_long(outb[:4])
        uplen = bytes_to_long(outb[4:6])

        if cno == 0:
            continue
        conn = conns.get(cno)
        if conn == None:
            # new connection to local socks server
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect(socks_address)
            upstream = queue.Queue()
            threading.Thread(target=socks_relay_down, args=(cno, conn, downstream,)).start()
            threading.Thread(target=socks_relay_up, args=(cno, conn, upstream,)).start()
            conns[cno] = upstream

        print("upstream sending {} bytes on cno {}".format(uplen, cno))
        upstream.put(outb[6:6+uplen])

if __name__ == "__main__":
    main()
