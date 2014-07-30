import argparse
import asyncio
import json
import os
import random
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

import config
import dcnet

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

@asyncio.coroutine
def open_relay(host, port, node):
    try:
        relay_reader, relay_writer = yield from asyncio.open_connection(host, port)
    except:
        sys.exit("Unable to connect to relay on {}:{}".format(host, port))
    relay_writer.write(long_to_bytes(node, 1))
    asyncio.async(read_relay(relay_reader, relay_writer, upstream_queue, close_queue))

@asyncio.coroutine
def read_relay(reader, writer, upstream, close):
    slot_idx = 0

    while True:
        header = yield from reader.readexactly(6)
        cno = bytes_to_long(header[:4])
        dlen = bytes_to_long(header[4:])

        buf = yield from reader.readexactly(dlen)

        if cno != 0 or dlen != 0:
            print("downstream from relay: cno {} dlen {}".format(cno, dlen))

        # see if any connections were closed by client
        try:
            while True:
                ccno = close.get_nowait()
                if conns[ccno]:
                    print("client closed conn {}".format(ccno))
                    conns[ccno].close()
                    conns[ccno] = None
        except asyncio.QueueEmpty:
            pass

        # pass along if necessary
        if cno > 0 and cno < len(conns) and conns[cno] is not None:
            if dlen > 0:
                try:
                    conns[cno].write(buf)
                    yield from conns[cno].drain()
                except OSError:
                    print("dropped {} bytes on {}".format(dlen, cno))
                    conns[cno].close()
                    conns[cno] = None
            else:
                print("upstream closed conn {}".format(cno))
                conns[cno].close()
                conns[cno] = None

        # prepare next upstream
        slot = slot_keys[slot_idx]
        ciphertext = client.produce_ciphertexts()
        cleartext = bytearray(dcnet.cell_length)
        if slot.element == nym_private_key.element:
            try:
                cleartext = upstream.get_nowait()
            except asyncio.QueueEmpty:
                pass
        # XXX pull XOR out into util
        ciphertext = long_to_bytes(
                bytes_to_long(ciphertext) ^ bytes_to_long(cleartext),
                blocksize=dcnet.cell_length)
        writer.write(ciphertext)
        yield from writer.drain()
        slot_idx = (slot_idx + 1) % len(slot_keys)


@asyncio.coroutine
def handle_client(reader, writer):
    cno = len(conns)
    conns.append(writer)
    print("new client: cno {}".format(cno))
    
    while True:
        try:
            buf = yield from reader.read(dcnet.cell_length - 6)
        except OSError:
            yield from close_queue.put(cno)
            return
            
        data = bytearray(dcnet.cell_length)
        data[:4] = long_to_bytes(cno, 4)
        data[4:6] = long_to_bytes(len(buf), 2)
        data[6:6+len(buf)] = buf

        print("client upstream: {} bytes on cno {}".format(len(buf), cno))
        yield from upstream_queue.put(data)
        if len(buf) == 0:
            yield from close_queue.put(cno)
            return


def main():
    global client
    # XXX hacky globals to work for now
    global conns
    global upstream_queue
    global close_queue
    global slot_keys
    global nym_private_key

    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("-p", "--port", type=int, metavar="port", required=True, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    system_config = config.load(config.SystemConfig, os.path.join(opts.config_dir, "system.json"))
    session_config = config.load(config.SessionConfig, os.path.join(opts.config_dir, "session.json"))
    pseudonym_config = config.load(config.PseudonymConfig, os.path.join(opts.config_dir, "pseudonym.json"))
    private = config.load(config.Private, opts.private_data)
    session_private = config.load(config.Private, os.path.join(opts.config_dir,
            "{}-{}.json".format(private.id, session_config.session_id)))

    # XXX hack for now
    slot_keys = pseudonym_config.slots.keys
    nym_private_key = session_private.secret

    try:
        node = system_config.clients.ids.index(private.id)
    except ValueError:
        sys.exit("Client is not in system config")

    client = dcnet.Client(private.secret, system_config.trustees.keys, NullCertifier(), NullEncoder())
    client.add_own_nym(session_private.secret)
    client.add_nyms(pseudonym_config.slots.keys)
    client.sync(None, [])

    conns = [None]
    close_queue = asyncio.Queue()
    upstream_queue = asyncio.Queue()

    # connect to the relay and start reading
    asyncio.async(open_relay(system_config.relay.host, system_config.relay.port, node))

    # listen for connections
    loop = asyncio.get_event_loop()
    print("Starting client on {}".format(opts.port))
    server = asyncio.start_server(handle_client, host=None,
            port=opts.port, backlog=1024)
    try:
        loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.close()


if __name__ == "__main__":
    main()

