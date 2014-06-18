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
    if client_id > 0:
        message = None
    
    cell = client.encode(payload_len, message)
    d = {
        "client_id" : client_id,
        "data" : cell,
    }
    r = relay_call("client_ciphertext", d)
    return None

def relay_call(name, data):
    # XXX don't hardcode port
    return requests.post("http://localhost:{}/{}".format(11111, name),
                        headers={"content-type" : "application/json"},
                        data=json.dumps(data))

def main():
    global client

    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("data_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # start new client using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_id = data["n"]
        private_key = data["private_key"]
        client = dcnet.Client(client_id, private_key)
    with open(os.path.join(opts.data_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_public_keys = data["trustee_public_keys"]
        client.compute_secrets(trustee_public_keys)

    # start the http server
    run(port=client_id + 12345)

if __name__ == "__main__":
    main()
