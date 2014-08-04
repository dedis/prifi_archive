import argparse
import os
import socket
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

import config
import dcnet

def main():
    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("-p", "--port", type=int, metavar="port", required=True, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # XXX error handling
    system_config = config.load(config.SystemConfig, os.path.join(opts.config_dir, "system.json"))
    session_config = config.load(config.SessionConfig, os.path.join(opts.config_dir, "session.json"))
    private = config.load(config.Private, opts.private_data)

    try:
        node = 0x80 | system_config.trustees.ids.index(private.id)
    except ValueError:
        sys.exit("Trustee is not in system config")

    trustee = dcnet.Trustee(private.secret, system_config.clients.keys)
    trustee.add_nyms(session_config.clients.keys)
    trustee.sync(None)

    # connect to the relay
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((system_config.relay.host, system_config.relay.port))
    conn.send(long_to_bytes(node, 1))

    # stream the ciphertext to the relay
    try:
        while True:
            # XXX ignore nxt for now
            nxt = bytes_to_long(conn.recv(2, socket.MSG_WAITALL))
            ciphertext = trustee.produce_ciphertext()
            n = conn.send(ciphertext)
    except KeyboardInterrupt:
        pass
    conn.close()


if __name__ == "__main__":
    main()
