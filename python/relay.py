import argparse
import asyncio
import itertools
import os
import socket
import sys
import time
from Crypto.Util.number import long_to_bytes, bytes_to_long

import config
import dcnet

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

        #print("socks_relay_down: {} bytes on cno {}".format(len(buf), cno))
        yield from downstream.put((cno, buf))

        # close the connection to socks relay
        if len(buf) == 0:
            #print("socks_relay_down: cno {} closed".format(cno))
            writer.close()
            return

@asyncio.coroutine
def socks_relay_up(cno, reader, writer, upstream):
    while True:
        buf = yield from upstream.get()
        dlen = len(buf)

        # client closed connection
        if dlen == 0:
            #print("sock_relay_up: closing stream {}".format(cno))
            writer.close()
            return

        #print("socks_relay_up: {} bytes on cno {}".format(dlen, cno))
        try:
            writer.write(buf)
            yield from writer.drain()
        except OSError as e:
            print("socks_relay_up: {}".format(e))
            writer.close()
            return


@asyncio.coroutine
def main_loop(tsocks, csocks, upstreams, downstream, scheduler):
    loop = asyncio.get_event_loop()

    # branch off two schedulers so trustees can get out ahead
    # XXX tee() can use a lot of memory if one copy gets too far ahead. This
    #   shouldn't be a problem here, but is worth noting
    client_scheduler, trustee_scheduler = itertools.tee(scheduler)

    begin = time.time()
    period = 3
    report = begin + period
    totupcells = 0
    totupbytes = 0
    totdowncells = 0
    totdownbytes = 0

    client_window = 2
    client_inflight = 0

    trustee_window = 10
    trustee_inflight = 0

    while True:
        # do some basic benchmarking
        now = time.time()
        if now > report:
            duration = now - begin
            print(("{} sec: {} cells, {} cells/sec, {} upbytes, {} upbytes/sec, " +
                    "{} downbytes, {} downbytes/sec").format(duration, totupcells,
                    totupcells / duration, totupbytes, totupbytes / duration,
                    totdownbytes, totdownbytes / duration))
            
            report = now + period

        # request future cell from trustees
        try:
            nxt = long_to_bytes(next(trustee_scheduler), 2)
        except StopIteration:
            sys.exit("Scheduler stopped short")

        for tsock in tsocks:
            yield from loop.sock_sendall(tsock, nxt)

        trustee_inflight += 1
        if trustee_inflight < trustee_window:
            continue

        # see if there's anything to send down to clients
        try:
            cno, downbuf = downstream.get_nowait()
        except asyncio.QueueEmpty:
            cno, downbuf = 0, bytearray(0)

        #if len(downbuf) > 0:
        #    print("downstream to clients: {} bytes on cno {}".format(len(downbuf), cno))

        # send downstream to all clients
        cno = long_to_bytes(cno, 4)
        dlen = long_to_bytes(len(downbuf), 2)
        try:
            nxt = long_to_bytes(next(client_scheduler), 2)
        except StopIteration:
            sys.exit("Scheduler stopped short")

        dbuf = cno + dlen + nxt + downbuf
        for csock in csocks:
            yield from loop.sock_sendall(csock, dbuf)

        totdowncells += 1
        totdownbytes += len(downbuf)

        client_inflight += 1
        if client_inflight < client_window:
            continue

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

        client_inflight -= 1
        trustee_inflight -= 1
        totupcells += 1
        totupbytes += dcnet.cell_length

        if cno == 0:
            continue
        conn = upstreams.get(cno)
        if conn == None:
            # new connection to local socks server
            upstream = asyncio.Queue()
            socks_reader, socks_writer = yield from asyncio.open_connection(*socks_address)
            asyncio.async(socks_relay_down(cno, socks_reader, socks_writer, downstream))
            asyncio.async(socks_relay_up(cno, socks_reader, socks_writer, upstream))
            upstreams[cno] = upstream
            #print("new connection: cno {}".format(cno))

        #print("upstream from clients: {} bytes on cno {}".format(uplen, cno))
        yield from upstreams[cno].put(outb[6:6+uplen])


def main():
    global relay

    p = argparse.ArgumentParser(description="Basic DC-net relay")
    p.add_argument("-p", "--port", type=int, metavar="port", required=True, dest="port")
    p.add_argument("config_dir")
    opts = p.parse_args()

    system_config = config.load(config.SystemConfig, os.path.join(opts.config_dir, "system.json"))
    nclients, ntrustees = len(system_config.clients.ids), len(system_config.trustees.ids)

    # start up a new relay
    relay = dcnet.Relay(ntrustees, NullAccumulator(), NullDecoder())
    relay.add_nyms(nclients)
    relay.sync(None)

    # server socket
    print("Starting relay on {}".format(opts.port))
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("0.0.0.0", opts.port))
    ssock.listen(1024)

    # make sure everybody connects
    print(("Waiting for {} clients and {} " + "trustees").format(nclients, ntrustees))
    ccli, ctru = 0, 0
    csocks = [None] * nclients
    tsocks = [None] * ntrustees
    while ccli < nclients or ctru < ntrustees:
        conn, addr = ssock.accept()
        buf = bytes_to_long(conn.recv(1))
        istru, node = buf & 0x80, buf & 0x7f
        conn.setblocking(0)

        if istru and ctru < ntrustees:
            if tsocks[node] is not None:
                sys.exit("Trustee connected twice")
            tsocks[node] = conn
            ctru += 1
        elif ccli < nclients:
            if csocks[node] is not None:
                sys.exit("Clients connected twice")
            csocks[node] = conn
            ccli += 1
        else:
            sys.exit("Illegal node number")
    print("All clients and trustees connected")

    upstreams = {}
    downstream = asyncio.Queue()
    scheduler = itertools.cycle(range(nclients))

    # start the main relay loop
    asyncio.async(main_loop(tsocks, csocks, upstreams, downstream, scheduler))
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.close()


if __name__ == "__main__":
    main()
