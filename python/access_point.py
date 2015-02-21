import argparse
import logging
import asyncio
import os
import socket
import sys
import struct
from Crypto.Util.number import long_to_bytes, bytes_to_long

from net.multicast import MulticastWriter
import net.message as m
from net.utils import verbosity
import config

logger = logging.getLogger(__file__.rpartition('/')[2])
logger.addHandler(logging.NullHandler())

# messages by type coming from clients
up_queues = {m.CLIENT_ACK:asyncio.PriorityQueue()}
# messages by type coming from relay
down_queues = {m.RELAY_DOWNSTREAM:asyncio.Queue()}
conns = {} # Client ID (int) -> StreamWriter
ccount = 0 # Number of clients that have ever connected to this AP
clients_lock = asyncio.Lock() # Protect WRITE access to ccount, the conns dict,
                              # and the keys in ack_map.

#### Error Correction ####
down_set = {} # Set of messages broadcast but not acknowledged
down_set_lock = asyncio.Lock() # Protect WRITE access to down_set
ack_map = {} # Client ID -> (message ID (int), ack count (int))
retransmit_queue = asyncio.Queue() # Queue of (Client ID, message ID) to resend
window = 1 # Number of times an ack should be repeated before retransmitting
threshold = 0.01 # Maximum proportion of all messages that have to be resent
                 # before displaying warnings

""" Primary Forwarding """
@asyncio.coroutine
def open_relay(errc, relay_addr, node_id, agroup, aport):
    """ Open a connection to the relay and start processing.

    errc (bool): Whether to do error correction
    relay_addr (host (str), port (int)): The relay's address
    node_id (int): This access point's index
    agroup (str): The multicast address
    aport (int): The multicast port
    """
    loop = asyncio.get_event_loop()
    try:
        relay_reader, relay_writer = \
            yield from asyncio.open_connection(*relay_addr)
    except Exception as e:
        logger.critical("Unable to connect to relay {}: {}"
                        .format(relay_addr, e))
        asyncio.get_event_loop().stop()
        return
    node = m.pack(m.AP_CONNECT, node=node_id)
    relay_writer.write(node)
    try:
        mwriter = MulticastWriter(loop, agroup, aport)
    except OSError as e:
        logger.critical("Failed to creat multicast writer on {}:{}:  {}"
                     .format(agroup, aport, e))
        asyncio.get_event_loop().stop()
        return
    asyncio.async(handle_downstream(errc, relay_reader, mwriter))

@asyncio.coroutine
def handle_downstream(errc, reader, mwriter):
    """ Forward relay traffic to clients, possibly over multicast

    errc (bool): Whether to do error correction
    reader (asyncio.StreamReader): Reader for the relay
    mwriter (net.MulticastWriter): Writer for multicast (None for no multicast)
    """
    mid = 0
    while True:
        yield from asyncio.sleep(0.00000001)
        try:
            down = yield from m.read_stream(reader)
        except Exception as e:
            logger.critical("Could not read from relay: {}".format(e))
            asyncio.get_event_loop().stop()
            return
        # Wrap the relay's message
        rkind = down.pop('kind')
        rdwn = m.pack(rkind, **down)
        mid += 1
        dbuf = m.pack(m.AP_DOWNSTREAM, mid=mid, data=rdwn)
        if mwriter != None:
            # Broadcast the message
            mwriter.write(dbuf)
            try:
                yield from mwriter.drain()
            except Exception as e:
                logger.error("Failed to write multicast: {}".format(e))
                return
            if not errc:
                continue
            # Store the data for possible resending
            yield from down_set_lock
            try:
                down_set[mid] = ({x for x in conns.keys()}, dbuf)
            finally:
                down_set_lock.release()
        else:
            yield from clients_lock
            # Lock here because the entire key set has to be static for
            # iteration to work
            try:
                for conn in conns:
                    yield from conn.write(dbuf)
            finally:
                clients_lock.release()


""" Error correction """
@asyncio.coroutine
def handle_acks():
    """ Re-send messages specified in retransmit_queue. """
    retransmits = 0
    while True:
        yield from asyncio.sleep(0.00000001)
        cid, mid = yield from retransmit_queue.get()
        try:
            conns[cid].write(down_set[mid][1])
            retransmits += 1
            ratio = retransmits / (mid * ccount)
            if ratio >= threshold:
                logger.warn("retransmits {} / mid {}: {}"
                            .format(retransmits, mid, ratio))
        except KeyError:
            # Already successfully retransmitted.
            continue
        logger.info("Retransmitted message {} to client {}".format(mid, cid))
        try:
            yield from conns[cid].drain()
        except ConnectionResetError as e:
            logger.error("Failed to retransmit: {}".format(e))

@asyncio.coroutine
def client_listener(reader, writer):
    """ Set up and handle TCP connections to clients. This is the callback for
    the asyncio.Server. """
    global ccount
    yield from clients_lock
    try:
        cid = ccount
        ccount += 1
        conns[cid] = writer
        ack_map[cid] = [0,0]
    finally:
        clients_lock.release()

    while True:
        yield from asyncio.sleep(0.00000001)
        try:
            up = yield from m.read_stream(reader)
        except Exception as e:
            logger.error("Could not read from client {}: {}".format(cid, e))
            yield from clients_lock
            try:
                conns.pop(cid)
            finally:
                clients_lock.release()
                writer.close()
            return
        if up['kind']  == m.CLIENT_ACK:
            if up['mid'] == ack_map[cid][0]:
                # If this is a repeated ack, possibly retransmit it
                ack_map[cid][1] += 1
                if ack_map[cid][1] >= window:
                    yield from retransmit_queue.put((cid, ack_map[cid][0] + 1))
            else:
                # If this is a new ack, update our record of messages the sender
                # is missing.
                yield from down_set_lock
                try:
                    for mid in range(ack_map[cid][0] + 1, up['mid'] + 1):
                        cids, buf = down_set.pop(mid)
                        if len(cids) > 1:
                            cids.remove(cid)
                            down_set[mid] = (cids, buf)
                finally:
                    down_set_lock.release()
                ack_map[cid] = [up['mid'], 0]


""" Setup """
def main():
    logging.basicConfig()
    p = argparse.ArgumentParser(description="Access Point for efficiently \
                                forwarding relay messages to clients")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    p.add_argument("--no-errc", help="run without error correction",
                   action="store_false", default=True, dest="errc")
    p.add_argument("-v", type=str, help="display more output (default: WARN)",
                   choices=verbosity.keys(), default="WARN", dest="verbose")
    opts = p.parse_args()
    logger.setLevel(verbosity[opts.verbose])

    system_config = config.load(config.SystemConfig,
            os.path.join(opts.config_dir, "system.json"))
    private = config.load(config.Private, opts.private_data)

    try:
        node_id = system_config.aps.ids.index(private.id)
    except ValueError:
        sys.exit("Access point is not in system config")

    logger.info("Starting access point on {}"
                 .format(system_config.aps.ports[node_id]))

    # Prepare to handle clients
    server = asyncio.start_server(client_listener,
                                  host="0.0.0.0",
                                  port=system_config.aps.ports[node_id],
                                  backlog=1024)
    if opts.errc:
        asyncio.async(handle_acks())

    # Prepare to handle relay
    rhost = system_config.relay.host
    rport = system_config.relay.port
    loop = asyncio.get_event_loop()
    asyncio.async(open_relay(opts.errc, (rhost, rport), node_id,
                             system_config.aps.mcasts[node_id][0],
                             system_config.aps.mcasts[node_id][1]))

    # Start event loop
    try:
        loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.close()

if __name__ == "__main__":
    main()
