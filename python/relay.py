import argparse
import logging
import asyncio
import itertools
import os
import socket
import struct
import sys
import time
from Crypto.Util.number import long_to_bytes, bytes_to_long

import config
import dcnet

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier
from utils import verbosity
import net.message as m

from elgamal import PublicKey, PrivateKey

logger = logging.getLogger(__file__.rpartition('/')[2])
logger.addHandler(logging.NullHandler())

downmax = 1024 * 64 - 1 # Maximum size of downstream messages
# max amount of data in downstream messages after headers
downcellmax = downmax - m.overhead[m.RELAY_DOWNSTREAM]
# XXX define elsewhere
socks_address = ("localhost", 8080)

""" Remote server interactions """
@asyncio.coroutine
def socks_relay_down(cno, reader, writer, downstream):
    """ Forward data from remote server to downstream queue

    cno (int): connection number
    reader (asyncio.StreamReader): reader for remote server
    writer (asyncio.StreamWriter): writer for remote server (to close if there
      is an error)
    downstream (asyncio.Queue): queue to add downstream data to
    """
    while True:
        yield from asyncio.sleep(0.00000001)
        try:
            buf = yield from reader.read(downcellmax)
        except OSError as e:
            logger.error("socks_relay_down: {}".format(e))
            writer.close()
            return

        logger.debug("socks_relay_down: {} bytes on cno {}"
                    .format(len(buf), cno))
        yield from downstream.put((cno, buf))

        # close the connection to socks relay
        if len(buf) == 0:
            logger.info("socks_relay_down: cno {} closed".format(cno))
            writer.close()
            return

@asyncio.coroutine
def socks_relay_up(cno, reader, writer, upstream):
    """ Send messages from upstream to remote server on cno via writer. """
    while True:
        yield from asyncio.sleep(0.00000001)
        buf = yield from upstream.get()
        dlen = len(buf)

        # client closed connection
        if dlen == 0:
            logger.info("sock_relay_up: closing stream {}".format(cno))
            writer.close()
            return

        logger.debug("socks_relay_up: {} bytes on cno {}".format(dlen, cno))
        try:
            writer.write(buf)
            yield from writer.drain()
        except ConnectionResetError as e:
            logger.error("Could not reach socks proxy: {}".format(e))
            writer.close()
            return
        except OSError as e:
            logger.error("socks_relay_up: {}".format(e))
            writer.close()
            return

""" Other Dissent node interactions """
@asyncio.coroutine
def main_loop(relay, tsocks, crsocks, cwsocks, upstreams, downstream, scheduler):
    """ Handle ciphertext from trustees/clients, forwarding to clients, and
    decoding messages from clients.

    relay (dcnet.Relay): The underlying dcnet Relay
    tsocks (socket list): List of sockets to trustees
    crsocks (socket list): List of connections to read from clients
    cwsocks (socket list): List of connections to write downstream traffic to (a
      combination of elements of crsocks and sockets to access points)
    upstreams (int -> asyncio.Queue()): dict of queues for upstream messages on
      active connections, with connection numbers as keys
    downstream (asyncio.Queue()): queue of messages to send downstream to
      clients
    scheduler (int generator): function to generate the next client index
    """
    loop = asyncio.get_event_loop()
    # branch off two schedulers so trustees can get out ahead
    # XXX tee() can use a lot of memory if one copy gets too far ahead. This
    #   shouldn't be a problem here, but is worth noting
    client_scheduler, trustee_scheduler = itertools.tee(scheduler)

    client_window = 2
    client_inflight = 0

    trustee_window = 10
    trustee_inflight = 0

    up = {'cno':0}
    tmsgs = dict((i, m.pack(m.RELAY_TNEXT, nxt=i)) for i in range(len(crsocks)))

    while True:
        yield from asyncio.sleep(0.00000001)

        # request future cell from trustees
        try:
            nxt = next(trustee_scheduler)
        except StopIteration:
            sys.exit("Scheduler stopped short")

        for tsock in tsocks:
            yield from loop.sock_sendall(tsock, tmsgs[nxt])

        trustee_inflight += 1
        if trustee_inflight < trustee_window:
            continue

        # see if there's anything to send down to clients
        try:
            cno, downbuf = downstream.get_nowait()
        except asyncio.QueueEmpty:
            cno, downbuf = 0, bytearray(0)

        logger.info("downstream to clients: {} bytes on cno {}"
                     .format(len(downbuf), cno)) if (cno > 0) else None

        # send downstream to all clients
        try:
            nxt = next(client_scheduler)
        except StopIteration:
            sys.exit("Scheduler stopped short")

        dbuf = m.pack(m.RELAY_DOWNSTREAM, cno=cno, nxt=nxt, data=downbuf)
        for csock in cwsocks:
            yield from loop.sock_sendall(csock, dbuf)

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
        for csock in crsocks:
            cslice = yield from loop.sock_recv(csock, dcnet.cell_length)
            while len(cslice) < dcnet.cell_length:
                cslice += yield from loop.sock_recv(csock,
                        dcnet.cell_length - len(cslice))
            relay.decode_client(cslice)

        # decode the actual upstream
        outb = relay.decode_cell()
        m.unpack(outb, up)

        client_inflight -= 1
        trustee_inflight -= 1

        # Possibly set up asynchronous sending upstream
        if up['cno'] == 0:
            continue
        else:
            cno = up['cno']
            up['cno'] = 0
        conn = upstreams.get(cno)
        if conn == None:
            # new connection to local socks server
            upstream = asyncio.Queue()
            socks_reader, socks_writer = \
                yield from asyncio.open_connection(*socks_address)
            asyncio.async(socks_relay_down(cno, socks_reader,
                                           socks_writer, downstream))
            asyncio.async(socks_relay_up(cno, socks_reader,
                                         socks_writer, upstream))
            upstreams[cno] = upstream

        yield from upstreams[cno].put(up['data'])


""" Setup """
def main():
    logging.basicConfig()
    p = argparse.ArgumentParser(description="Basic DC-net relay")
    p.add_argument("-p", "--port", type=int, help="Port to listen for \
                   connections on", required=True, dest="port")
    p.add_argument("config_dir")
    p.add_argument("-s", "--socks", type=str, metavar="host:port",
                   help="SOCKS proxy address",
                   default="localhost:8080", dest="socks_addr")
    p.add_argument("-v", type=str, help="display more output (default: WARN)",
                   choices=verbosity.keys(), default="WARN", dest="verbose")
    opts = p.parse_args()
    logger.setLevel(verbosity[opts.verbose])

    global socks_address
    saddr, sport = opts.socks_addr.split(":")
    socks_address = saddr, int(sport)

    system_config = config.load(config.SystemConfig,
                                os.path.join(opts.config_dir, "system.json"))
    nclients = len(system_config.clients.ids)
    ntrustees = len(system_config.trustees.ids)
    naps = len(system_config.aps.ids)

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
    print(("Waiting for {} clients, {} trustees, and {} access points")
          .format(nclients, ntrustees, naps))
    ccli, ctru, caps = 0, 0, 0
    crsocks = [None] * nclients
    cwsocks = []
    tsocks = [None] * ntrustees
    apsocks = [None] * naps
    while ccli < nclients or ctru < ntrustees or caps < naps:
        conn, addr = ssock.accept()
        buf = bytearray(1)
        buf[0] = kind = bytes_to_long(conn.recv(1))
        buf.extend(conn.recv(m.sizes[kind] - 1))
        reg = {}
        m.unpack(buf, reg)
        conn.setblocking(0)

        if reg['kind'] == m.TRUSTEE_CONNECT and ctru < ntrustees:
            if tsocks[reg['node']] is not None:
                sys.exit("Trustee connected twice")
            tsocks[reg['node']] = conn
            ctru += 1
        elif reg['kind'] == m.CLIENT_CONNECT and ccli < nclients:
            if crsocks[reg['node']] is not None:
                sys.exit("Clients connected twice")
            crsocks[reg['node']] = conn
            if reg['ap'] == -1:
                cwsocks.append(conn)
            ccli += 1
        elif reg['kind'] == m.AP_CONNECT and caps < naps:
            if apsocks[reg['node']] is not None:
                sys.exit("Access point connected twice")
            apsocks[reg['node']] = conn
            cwsocks.append(conn)
            caps += 1
            global downcellmax
            # Leave room for IP/UDP headers and AP headers
            downcellmax = downmax - 28 - m.overhead[m.AP_DOWNSTREAM] - \
                                        m.overhead[m.RELAY_DOWNSTREAM]
        else:
            sys.exit("Illegal node number or connection type")
    print("All clients, trustees, and access points connected")

    upstreams = {}
    downstream = asyncio.Queue()
    scheduler = itertools.cycle(range(nclients))

    # start the main relay loop
    asyncio.async(main_loop(relay, tsocks, crsocks, cwsocks,
                            upstreams, downstream, scheduler))
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    loop.close()


if __name__ == "__main__":
    main()
