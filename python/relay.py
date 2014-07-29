import argparse
import asyncio
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

# XXX define elsewhere
downcellmax = 64*1024 - 1
socks_address = ("localhost", 8080)

@asyncio.coroutine
def socks_relay_down(cno, reader, writer, downstream):
    while True:
        try:
            buf = yield from reader.read(downcellmax)
        except OSError as e:
            print("socks_relay_down: {}".format(e))
            writer.close()
            return

        data = long_to_bytes(cno, 4) + long_to_bytes(len(buf), 2) + buf

        print("socks_relay_down: {} bytes on cno {}".format(len(buf), cno))
        yield from downstream.put(data)

        # close the connection to socks relay
        if len(buf) == 0:
            print("socks_relay_down: cno {} closed".format(cno))
            writer.close()
            return

@asyncio.coroutine
def socks_relay_up(cno, reader, writer, upstream):
    while True:
        buf = yield from upstream.get()
        dlen = len(buf)

        # client closed connection
        if dlen == 0:
            print("sock_relay_up: closing stream {}".format(cno))
            writer.close()
            return

        print("socks_relay_up: {} bytes on cno {}".format(dlen, cno))
        try:
            writer.write(buf)
            yield from writer.drain()
        except OSError as e:
            print("socks_relay_up: {}".format(e))
            writer.close()
            return


@asyncio.coroutine
def main_loop(tsocks, csocks, conns, downstream):
    loop = asyncio.get_event_loop()

    while True:
        # see if there's anything to send
        try:
            downbuf = downstream.get_nowait()
        except asyncio.QueueEmpty:
            downbuf = bytearray(6)

        # send downstream to all clients
        cno = bytes_to_long(downbuf[:4])
        dlen = bytes_to_long(downbuf[4:6])
        if dlen > 0:
            print("downstream to clients: {} bytes on cno {}".format(dlen, cno))
        for csock in csocks:
            yield from loop.sock_sendall(csock, downbuf)

        # get trustee ciphertexts
        relay.decode_start()
        for tsock in tsocks:
            tslice = yield from loop.sock_recv(tsock, dcnet.cell_length)
            while len(tslice) < dcnet.cell_length:
                tslice += yield from loop.sock_recv(tsock,
                        dcnet.cell_length - len(tslice))
            relay.decode_trustee(tslice)

        # and client upstream ciphertexts
        for csock in csocks:
            cslice = yield from loop.sock_recv(csock, dcnet.cell_length)
            while len(cslice) < dcnet.cell_length:
                cslice += yield from loop.sock_recv(csock,
                        dcnet.cell_length - len(cslice))
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
            # XXX should cnos be reused
            upstream = asyncio.Queue()
            socks_reader, socks_writer = yield from asyncio.open_connection(*socks_address)
            asyncio.async(socks_relay_down(cno, socks_reader, socks_writer, downstream))
            asyncio.async(socks_relay_up(cno, socks_reader, socks_writer, upstream))
            conns[cno] = upstream
            print("new connection: cno {}".format(cno))

        print("upstream from clients: {} bytes on cno {}".format(uplen, cno))
        yield from conns[cno].put(outb[6:6+uplen])


def main():
    global relay

    p = argparse.ArgumentParser(description="Basic DC-net relay")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # load public keys from system config
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        n_clients = len(data["clients"])
        n_trustees = len(data["servers"])

    # start up a new relay
    relay = dcnet.Relay(n_trustees, NullAccumulator(), NullDecoder())
    relay.add_nyms(n_clients)
    relay.sync(None)

    # server socket
    print("Starting relay on {}".format(opts.port))
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("0.0.0.0", opts.port))
    ssock.listen(1024)

    # make sure everybody connects
    print(("Waiting for {} clients and {} " +
            "trustees").format(n_clients, n_trustees))
    ccli, ctru = 0, 0
    csocks = [None] * n_clients
    tsocks = [None] * n_trustees
    while ccli < n_clients or ctru < n_trustees:
        conn, addr = ssock.accept()
        buf = bytes_to_long(conn.recv(1))
        istru, node = buf & 0x80, buf & 0x7f
        conn.setblocking(0)

        if istru and ctru < n_trustees:
            if tsocks[node] is not None:
                sys.exit("Trustee connected twice")
            tsocks[node] = conn
            ctru += 1
        elif ccli < n_clients:
            if csocks[node] is not None:
                sys.exit("Clients connected twice")
            csocks[node] = conn
            ccli += 1
        else:
            sys.exit("Illegal node number")
    print("All clients and trustees connected")

    downstream_queue = asyncio.Queue()
    conns = {}

    # start the main relay loop
    asyncio.async(main_loop(tsocks, csocks, conns, downstream_queue))
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.close()


if __name__ == "__main__":
    main()
