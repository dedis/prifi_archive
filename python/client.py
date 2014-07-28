import argparse
import asyncio
import json
import os
import random
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

import dcnet
from dcnet import global_group

from cells.null import NullDecoder, NullEncoder
from certify.null import NullAccumulator, NullCertifier

from elgamal import PublicKey, PrivateKey

@asyncio.coroutine
def open_relay(host, port):
    try:
        relay_reader, relay_writer = yield from asyncio.open_connection(host, port)
    except:
        print("Unable to connect to relay on {}:{}".format(host, port))
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
                print("client closed conn {}".format(ccno))
                conns[ccno] = None
        except asyncio.QueueEmpty:
            pass

        # pass along if necessary
        if cno > 0 and cno < len(conns) and conns[cno] is not None:
            if dlen > 0:
                conns[cno].write(buf)
                yield from conns[cno].drain()
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
        buf = yield from reader.read(dcnet.cell_length - 6)
        data = bytearray(dcnet.cell_length)
        data[:4] = long_to_bytes(cno, 4)
        data[4:6] = long_to_bytes(len(buf), 2)
        data[6:6+len(buf)] = buf

        print("client upstream: {} bytes on cno {}".format(len(buf), cno))
        yield from upstream_queue.put(data)
        if len(buf) == 0:
            writer.close()
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

    conns = [None]
    close_queue = asyncio.Queue()
    upstream_queue = asyncio.Queue()

    # connect to the relay
    relay_host = relay_address[0]
    relay_port = int(relay_address[1])
    asyncio.async(open_relay(relay_host, relay_port))

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

