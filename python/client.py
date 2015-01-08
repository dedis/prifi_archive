import argparse
import json
import os
import random
import requests

from bottle import request, route, run

import dcnet

@route("/interval_conclusion", method="POST")
def interval_conclusion():
    return _interval_conclusion(request.json)

def _interval_conclusion(interval_data):
    # run for one cell (first client gets ownership)
    # XXX hack to get payload_len for now
    message = "This is client-0's message.".encode("utf-8")
    payload_len = len(message)
    client_id = client.id
    # XXX recalculating public key is bad
    # but this code will be replaced shortly anyway
    if pow(dcnet.G, client.private_key, dcnet.P) != slots[0]:
        message = None
    
    cell = client.encode(payload_len, message)
    d = {
        "client_id" : client_id,
        "data" : cell,
    }
    r = relay_call("client_ciphertext", d)
    return None

def relay_call(name, data):
    return requests.post("http://{}/{}".format(relay_address, name),
                        headers={"content-type" : "application/json"},
                        data=json.dumps(data))

def main():
    global client
    global relay_address
    global slots

    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("data_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # start new client using id and key from per-session private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_id = data["id"]
        private_key = data["private_key"]
        client = dcnet.Client(client_id, private_key)
    # load addresses from system config
    with open(os.path.join(opts.data_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        # XXX only using first relay for now
        relay_address = data["relays"][0]["ip"]
    # and public keys from session config
    with open(os.path.join(opts.data_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_keys = [t["dhkey"] for t in data["servers"]]
        client.compute_secrets(trustee_keys)
    # and slots from the post-shuffle config
    with open(os.path.join(opts.data_dir, "shuffle.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        slots = data["slots"]

    # start the http server
    run(port=opts.port)

if __name__ == "__main__":
    main()
