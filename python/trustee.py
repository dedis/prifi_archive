import argparse
import os
import socket
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

import config_utils
import system_config
import session_config

import dcnet

def main():
    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("-p", "--port", type=int, metavar="port", required=True, dest="port")
    p.add_argument("config_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # XXX error handling
    system = system_config.load(os.path.join(opts.config_dir, "system.json"))
    session = session_config.load(os.path.join(opts.config_dir, "session.json"))
    private = config_utils.load_private(opts.private_data)

    try:
        node = 0x80 | system.trustees.ids.index(private.id)
    except ValueError:
        sys.exit("Trustee is not in system config")

    trustee = dcnet.Trustee(private.secret, system.clients.keys)
    trustee.add_nyms(session.clients.keys)
    trustee.sync(None)

    # connect to the relay
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((system.relay.host, system.relay.port))
    conn.send(long_to_bytes(node, 1))

    # stream the ciphertext to the relay
    while True:
        ciphertext = trustee.produce_ciphertext()
        n = conn.send(ciphertext)


if __name__ == "__main__":
    main()
