import argparse
import json
import os
import random
import requests

from bottle import request, route, run

import dcnet

@route("/client_ciphertext", method="POST")
def client_ciphertext():
    return _client_ciphertext(request.json)

def _client_ciphertext(client_data):
    client_id = client_data["client_id"]
    data = client_data["data"]
    relay.decode_client(client_id, data)
    # XXX hardcoded for now
    if relay.client_received == 10 and relay.trustee_received == 3:
        print(relay.decode_final().decode("utf-8"))
        relay.decode_start()
    return None

@route("/trustee_ciphertext", method="POST")
def trustee_ciphertext():
    return _trustee_ciphertext(request.json)

def _trustee_ciphertext(trustee_data):
    trustee_id = trustee_data["trustee_id"]
    data = trustee_data["data"]
    relay.decode_trustee(trustee_id, data)
    # XXX hardcoded for now
    if relay.client_received == 10 and relay.trustee_received == 3:
        print(relay.decode_final().decode("utf-8"))
        relay.decode_start()
    return None

def main():
    global relay
def main():
    global relay

    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    opts = p.parse_args()

    relay = dcnet.Relay()
    relay.decode_start()

    # start the http server
    run(port=opts.port)

if __name__ == "__main__":
    main()
