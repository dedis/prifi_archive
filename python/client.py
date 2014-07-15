import argparse
import json
import os
import queue
import random
import select
import socket
import sys
import threading
from Crypto.Util.number import long_to_bytes, bytes_to_long

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

def read_relay(conn, close):
    slot_idx = 0

    while True:
        # read full header
        header = bytearray(6)
        n = conn.recv_into(header, flags=socket.MSG_WAITALL)
        cno = bytes_to_long(header[:4])
        dlen = bytes_to_long(header[4:])

        # and the payload
        buf = bytearray(dlen)
        n = conn.recv_into(buf, flags=socket.MSG_WAITALL)

        if cno != 0 or dlen != 0:
            print("downstream from relay: cno {} dlen {}".format(cno, dlen))

        # see if any connections were closed by client
        try:
            while True:
                ccno = close.get_nowait()
                print("client closed conn {}".format(ccno))
                conns[ccno].conn.close()
                conns[ccno] = None
        except queue.Empty:
            pass

        # pass along if necessary
        if cno > 0 and cno < len(conns) and conns[cno] is not None:
            if dlen > 0:
                n = conns[cno].conn.send(buf)
            else:
                print("upstream closed conn {}".format(cno))
                # XXX: not concurrency safe
                inputs.remove(conns[cno])
                conns[cno].conn.close()
                conns[cno] = None

        # prepare next upstream
        slot = slot_keys[slot_idx]
        ciphertext = client.produce_ciphertexts()
        cleartext = bytearray(dcnet.cell_length)
        if slot.element == nym_private_key.element:
            try:
                cleartext = upstream_queue.get_nowait()
            except queue.Empty:
                pass
        # XXX pull XOR out into util
        ciphertext = long_to_bytes(
                bytes_to_long(ciphertext) ^ bytes_to_long(cleartext),
                blocksize=dcnet.cell_length)
        n = conn.send(ciphertext)
        slot_idx = (slot_idx + 1) % len(slot_keys)

class ClientConn:
    
    def __init__(self, cno, conn):
        self.cno = cno
        self.conn = conn

    def fileno(self):
        return self.conn.fileno()

def main():
    global client
    # XXX hacky globals to work for now
    global upstream_queue
    global conns
    global slot_keys
    global nym_private_key
    global inputs

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

    # listen for connections
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(("", opts.port))
    ssock.listen(5)

    close_queue = queue.Queue()
    upstream_queue = queue.Queue()
    conns = [None]

    # connect to the relay
    relay_host = relay_address[0]
    relay_port = int(relay_address[1])
    rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rsock.connect((relay_host, relay_port))
    rthread = threading.Thread(target=read_relay, args=(rsock, close_queue,))
    rthread.start()

    inputs = [ssock]
    outputs = []


    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for rinput in readable:

            # new connection
            if rinput is ssock:
                sock, addr = ssock.accept()
                cno = len(conns)
                conn = ClientConn(cno, sock)
                conns.append(conn)
                inputs.append(conn)
                print("new client: cno {}".format(cno))

            # upstream data from client
            else:
                cno, conn = rinput.cno, rinput.conn
                upstream = memoryview(bytearray(dcnet.cell_length))
                n = conn.recv_into(upstream[6:])
                upstream[:4] = long_to_bytes(cno, 4)
                upstream[4:6] = long_to_bytes(n, 2)
                upstream_queue.put(upstream)
                print("client upstream: {} bytes on cno {}".format(n, cno))
                if n == 0:
                    inputs.remove(rinput)
                    close_queue.put(cno)

if __name__ == "__main__":
    main()
