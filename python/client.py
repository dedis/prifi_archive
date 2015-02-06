import argparse
import asyncio
import os
import sys
import math
import logging

import config
import dcnet
from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from net.multicast import MulticastReader
from net.utils import verbosity
import net.message as m

### Upstream traffic
# Connections from the outside world to this client
conns = [None]
# elements of conns that have been closed
close_queue = asyncio.Queue()
# message queue to draw from when sending ciphertext to relay
upstream_queue = asyncio.Queue()
# The maximum number of bytes to pull from upstream_queue at a time
upcellmax = dcnet.cell_length - m.overhead[m.CLIENT_UPSTREAM]

### Downstream traffic
# Dictionary of all message types the client expects to receive from upstream,
# mapped to queues to store those messages.
downstream_queues = {m.RELAY_DOWNSTREAM:asyncio.Queue()}

### Error correction
# Set of message ids we have received
down_set = set()
down_set_lock = asyncio.Lock()
# Highest message id such that no messages below this id are missing
max_mid = 0
max_mid_lock = asyncio.Lock()
# Temporary set of any out-of-order messages received (such that lower-id
# messages are missing). Message ID -> unpacked message (dict)
extras = {}

#XXX Hacky globals to work for now
cno_limit = 0 # Maximum number of connections to the upstream server
cno_offset = 0 # Offset to start indexing this client's connections from.
logger = None

""" Relay Interactions """
@asyncio.coroutine
def open_relay(client, host, rport, ap_id, node_id):
    """ Open a connection to the relay and start listening for downstream

    client (dcnet.Client): The underlying Client object
    host (str): The IP address of the relay
    rport (int): The port number of the relay
    ap_id (int): The index of the access point this client is connected to (-1
      if none)
    node_id (int): This client's index """
    try:
        relay_reader, relay_writer = \
            yield from asyncio.open_connection(host, rport)
    except Exception as e:
        logger.critical("Unable to connect to relay on {}:{} - {}"
                .format(host, rport, e))
        asyncio.get_event_loop().stop()
        return
    node = m.pack(m.CLIENT_CONNECT, node=node_id, ap=ap_id)
    relay_writer.write(node)
    yield from relay_writer.drain()
    asyncio.async(process_downstream(relay_writer, client, close_queue))
    if ap_id == -1:
        asyncio.async(read_relay(relay_reader))

@asyncio.coroutine
def read_relay(reader):
    """ Read messages from the relay.

    reader (asyncio.StreamReader): reader connected to the relay
    """
    while True:
        yield from asyncio.sleep(0.00000001)
        try:
            down = yield from m.read_stream(reader)
        except Exception as e:
            logger.error("{} Could not read from upstream: {}".format(cno_offset, e))
            return
        if 'blen' in down and down['blen'] > 0:
            logger.info("{} read {} from upstream".format(cno_offset,
            down['blen']))
        yield from downstream_queues[down['kind']].put(down)

@asyncio.coroutine
def process_downstream(writer, client, close):
    """ Handle downstream messages and write the next round's ciphertext

    writer (asyncio.StreamWriter): StreamWriter to the relay
    client (dcnet.Client): Underlying dcnet.Client object
    close (asyncio.Queue): Connections to the outside world that need to be
      closed
    """

    while True:
        yield from asyncio.sleep(0.00000001)
        down = yield from downstream_queues[m.RELAY_DOWNSTREAM].get()
        cno = down['cno']

        # see if any connections were closed by outside client
        # TODO: Move this to its own coroutine?
        try:
            while True:
                ccno = close.get_nowait()
                if conns[ccno]:
                    logger.info("client closed conn {}".format(ccno))
                    conns[ccno].close()
                    conns[ccno] = None
        except asyncio.QueueEmpty:
            pass

        # pass along if necessary
        cno -= cno_offset
        if cno > 0 and cno < len(conns) and conns[cno] is not None:
            if down['blen'] > 0:
                try:
                    conns[cno].write(down['data'])
                    yield from conns[cno].drain()
                    logger.info("{} bytes to connection {}"
                                .format(down['blen'], cno + cno_offset))
                except OSError:
                    conns[cno].close()
                    conns[cno] = None
            else:
                logger.info("upstream closed conn {}".format(cno))
                conns[cno].close()
                conns[cno] = None

        # prepare next upstream
        ciphertext = client.produce_ciphertexts(down['nxt'])
        writer.write(ciphertext)
        try:
            yield from writer.drain()
        except ConnectionResetError as e:
            logger.critical("Could not write to relay: {}".format(e))
            asyncio.get_event_loop().stop()
            return


""" Access Point Interactions """
@asyncio.coroutine
def open_ap(errc, apid, aaddr, maddr, timeout, node_id):
    """ Open a TCP connection to the access point, and optionally start
    listening for multicasts

    errc (bool): Whether to do error detection/correction
    apid (int): The index of the access point this client is connected to (>= 0)
    aadr (host (str), port (int)): address of the access point
    maddr (group (str), port (int)): Address of the multicast
    timeout (float): Number of seconds of no messages to wait before resending
                     an ack
    node_id (int): This client's index """
    try:
        ap_reader, ap_writer = yield from asyncio.open_connection(*aaddr)
    except Exception as e:
        logger.critical("Unable to connect to access point on {} - {}"
                .format(aaddr, e))
        asyncio.get_event_loop().stop()
        return
    mreader = MulticastReader(asyncio.get_event_loop(), *maddr)
    if maddr != None and errc:
        asyncio.async(read_ap(mreader, ap_writer))
        asyncio.async(read_ap(ap_reader, ap_writer))
        asyncio.async(process_acks(ap_writer, timeout))
    else:
        asyncio.async(read_ap(mreader, None))

def read_ap(reader, writer):
    """ Read messages from a StreamReader and sort them for processing """
    rdwn = {}
    while True:
        yield from asyncio.sleep(0.00000001)
        try:
            down = yield from m.read_stream(reader)
        except Exception as e:
            logger.critical("{} Could not read from access point: {}"
                            .format(cno_offset, e))
            asyncio.get_event_loop().stop()
            return
        m.unpack(down['data'], rdwn)
        if writer == None:
            yield from downstream_queues[rdwn['kind']].put(rdwn)
            continue
        global max_mid
        yield from max_mid_lock
        try:
            if down['mid'] == max_mid + 1:
                # If this was the next expected message, flush extras
                yield from downstream_queues[rdwn['kind']].put(rdwn)
                max_mid = down['mid']
                while max_mid + 1 in extras:
                    max_mid += 1
                    rdwn = extras.pop(max_mid)
                    yield from downstream_queues[rdwn['kind']].put(rdwn)
                if down['mid'] != max_mid:
                    # If we filled in blanks, ack
                    writer.write(m.pack(m.CLIENT_ACK, mid=max_mid))
                    yield from writer.drain()
            else:
                # If this was unexpected/out of order, save it in extras and
                # retransmit the last ack
                extras[down['mid']] = rdwn
                writer.write(m.pack(m.CLIENT_ACK, mid=max_mid))
                yield from writer.drain()
        finally:
            max_mid_lock.release()

@asyncio.coroutine
def process_acks(writer, timeout):
    """ Periodically ping if nothing has been received from the access point.

    writer: asyncio.StreamWriter to the access point
    timeout: seconds to wait before resending an ack """
    while True:
        old = max_mid
        yield from asyncio.sleep(timeout)
        if old == max_mid and old > 0:
            writer.write(m.pack(m.CLIENT_ACK, mid=max_mid))
            logger.warn("Acked {} after timeout".format(max_mid))


""" Cleartext Source Interactions """
@asyncio.coroutine
def handle_client(reader, writer):
    """ Get upstream text from an outside client """
    cno = len(conns)
    if cno >= cno_limit:
        sys.exit("Client reached connection limit ({})".format(cno_limit))
    conns.append(writer)
    logger.info("new client: cno {}".format(cno))

    while True:
        yield from asyncio.sleep(0.00000001)

        try:
            buf = yield from reader.read(upcellmax)
        except OSError:
            yield from close_queue.put(cno)
            return

        data = m.pack(m.CLIENT_UPSTREAM, cno=cno + cno_offset, data=buf)

        logger.debug("client upstream: {} bytes on cno {}".format(len(buf), cno))
        yield from upstream_queue.put(data)
        if len(buf) == 0:
            yield from close_queue.put(cno)
            return


""" Setup """
def main():
    logging.basicConfig()
    # XXX hacky globals to work for now
    global cno_limit
    global cno_offset

    # Parse arguments and config files
    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("-p", "--port", type=int,
                   help="port to listen for outside connections on",
                   required=True, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    p.add_argument("-a", "--ap", type=int, default=-1,
                   dest="ap_id", help="index of the AP to connect through")
    p.add_argument("-m", "--multicast", action="store_true", dest="mcast",
                   help="listen for multicasts from access point")
    p.add_argument("--no-errc", help="run without error correction",
                   action="store_false", default=True, dest="errc")
    p.add_argument("-t", "--timeout",  default=0.3,
                   help="max time in seconds to wait for next AP msg before \
                         resending ack",
                   type=float, dest="timeout")
    p.add_argument("-v", type=str, help="display more output (default: WARN)",
                   choices=verbosity.keys(), default="WARN", dest="verbose")
    opts = p.parse_args()

    system_config = config.load(config.SystemConfig,
                                os.path.join(opts.config_dir, "system.json"))
    session_config = config.load(config.SessionConfig,
                                 os.path.join(opts.config_dir, "session.json"))
    nym_config = config.load(config.PseudonymConfig,
                             os.path.join(opts.config_dir, "pseudonym.json"))
    private = config.load(config.Private, opts.private_data)
    session_private = config.load(config.Private, os.path.join(opts.config_dir,
            "{}-{}.json".format(private.id, session_config.session_id)))

    try:
        node_id = system_config.clients.ids.index(private.id)
    except ValueError:
        sys.exit("Client is not in system config")

    global logger
    lnode = str(node_id).rjust(math.ceil(math.log10(len(system_config.clients.ids))))
    lname = __file__.rpartition('/')[2].rpartition('.')[0] + lnode
    logger = logging.getLogger(lname)
    logger.addHandler(logging.NullHandler())
    logger.setLevel(verbosity[opts.verbose])

    # Initialize the dcnet-level Client
    client = dcnet.Client(private.secret, system_config.trustees.keys,
                          NullCertifier(), NullEncoder())
    client.set_message_queue(upstream_queue)
    client.add_own_nym(session_private.secret)
    client.add_nyms(nym_config.slots.keys)
    client.sync(None, [])
    assert len(client.own_nyms) >= 1

    # XXX abstract this away
    nym_index = client.own_nym_keys[0][1]
    nslots = len(nym_config.slots.keys)
    cno_limit = (1 << 16) // nslots
    cno_offset = cno_limit * nym_index

    # listen for connections
    server = asyncio.start_server(handle_client, host="0.0.0.0",
            port=opts.port, backlog=1024)

    # Possibly set up the access point
    if opts.ap_id != -1:
        if opts.mcast:
            mcast = tuple(system_config.aps.mcasts[opts.ap_id])
        else:
            mcast = None
        ahost = system_config.aps.hosts[opts.ap_id]
        aport = system_config.aps.ports[opts.ap_id]
        asyncio.async(open_ap(opts.errc, opts.ap_id,
                              (ahost, aport), mcast, opts.timeout, node_id))

    # connect to the relay and start reading
    asyncio.async(open_relay(client, system_config.relay.host,
                             system_config.relay.port,
                             opts.ap_id, node_id))

    # Start the asyncio event loop
    loop = asyncio.get_event_loop()
    logger.info("Starting client on {}".format(opts.port))
    try:
        if server != None:
            loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    if server != None:
        server.close()
    loop.close()


if __name__ == "__main__":
    main()

