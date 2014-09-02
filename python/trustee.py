import argparse
import os
import socket
import sys
import logging

import config
import dcnet
import net.message as m
from utils import verbosity
logger = logging.getLogger(__file__.rpartition('/')[2])
logger.addHandler(logging.NullHandler())

def main():
    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    p.add_argument("-v", type=str, help="display more output (default: WARN)",
                   choices=verbosity.keys(), default="WARN", dest="verbose")
    opts = p.parse_args()
    logger.setLevel(verbosity[opts.verbose])

    # XXX error handling
    system_config = config.load(config.SystemConfig,
            os.path.join(opts.config_dir, "system.json"))
    session_config = config.load(config.SessionConfig,
            os.path.join(opts.config_dir, "session.json"))
    private = config.load(config.Private, opts.private_data)

    try:
        node_id = system_config.trustees.ids.index(private.id)
    except ValueError:
        sys.exit("Trustee is not in system config")
    node = m.pack(m.TRUSTEE_CONNECT, node=node_id)

    trustee = dcnet.Trustee(private.secret, system_config.clients.keys)
    trustee.add_nyms(session_config.clients.keys)
    trustee.sync(None, None)

    # connect to the relay
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((system_config.relay.host, system_config.relay.port))
        conn.send(node)
    except OSError as e:
        sys.exit("Could not connect to relay: {}".format(e))

    # stream the ciphertext to the relay
    nsize = m.sizes[m.RELAY_TNEXT]
    tnxts = {}
    tnxt = {}
    try:
        while True:
            buf = conn.recv(nsize, socket.MSG_WAITALL)
            try:
                nxt = tnxts[buf]
            except KeyError:
                m.unpack(buf, tnxt)
                nxt = tnxt['nxt']
                tnxts[buf] = nxt
            ciphertext = trustee.produce_ciphertext(nxt)
            n = conn.send(ciphertext)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error("Could not read from relay: {}".format(e))
    conn.close()


if __name__ == "__main__":
    main()
