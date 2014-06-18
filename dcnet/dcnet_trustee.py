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
    # XXX don't hardcode port
    return requests.post("http://localhost:{}/{}".format(11111, name),
                        headers={"content-type" : "application/json"},
                        data=json.dumps(data))

def main():
    global trustee

    p = argparse.ArgumentParser(description="Basic DC-net trustee")
    p.add_argument("data_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # start new trustee using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        trustee_id = data["n"]
        private_key = data["private_key"]
        trustee = dcnet.Trustee(trustee_id, private_key)
    with open(os.path.join(opts.data_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_public_keys = data["client_public_keys"]
        trustee.compute_secrets(client_public_keys)

    # start the http server
    run(port=trustee_id + len(client_public_keys) + 12345)

if __name__ == "__main__":
    main()
