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
    # XXX hack to get payload_len for now
    message = "This is client-0's message.".encode("utf-8")
    payload_len = len(message)
    
    trustee_id = trustee.id
    cell = trustee.encode(payload_len)
    d = {
        "trustee_id" : trustee_id,
        "data" : cell,
    }
    r = relay_call("trustee_ciphertext", d)
    return None

def relay_call(name, data):
    return requests.post("http://{}/{}".format(relay_address, name),
                        headers={"content-type" : "application/json"},
                        data=json.dumps(data))

def main():
    global trustee
    global relay_address

    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("-p", "--port", type=int, metavar="N", default=8888, dest="port")
    p.add_argument("data_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # start new trustee using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_id = data["id"]
        private_key = data["private_key"]
        trustee = dcnet.Trustee(trustee_id, private_key)
    # load addresses from system config
    with open(os.path.join(opts.data_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        # XXX only using first relay for now
        relay_address = data["relays"][0]["ip"]
    # and public keys from session config
    with open(os.path.join(opts.data_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_keys = [c["dhkey"] for c in data["clients"]]
        trustee.compute_secrets(client_keys)

    # start the http server
    run(port=opts.port)

if __name__ == "__main__":
    main()
