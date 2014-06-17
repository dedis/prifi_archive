import argparse
import json
import os
import random
import requests

from bottle import request, route, run

import dcnet

@route("/exchange", method="POST")
def exchange():
    return _exchange(request.json)

def _exchange(exchange_data):
    exchange_id = exchange_data["exchange_id"]
    client_id = exchange_data["client_id"]
    transmission = exchange_data["data"]
    messages = client.handle_exchange(0, client_id, transmission)
    if messages is not None:
        for i, message in enumerate(messages):
            print("{}: {}".format(i, message))
    return None

@route("/start", method="POST")
def start():
    return _start(request.json)

def _start(start_data):
    # run for one exchange (each client gets one slot)
    exchange_id, client_id = 0, client.id
    message = "This is client-{}'s message.".format(client_id)
    transmission = client.prepare_exchange(exchange_id, message)
    d = {
        "exchange_id" : exchange_id,
        "client_id" : client_id,
        "data" : transmission,
    }
    for i in range(client.n_clients):
        r = client_call(client, i, "exchange", d)
    return None

def client_call(me, client_id, name, data):
    if me.id == client_id:
        return globals()["_" + name](data)
    return requests.post("http://localhost:{}/{}".format(client_id + 12345, name),
                        headers={"content-type" : "application/json"},
                        data=json.dumps(data))

def main():
    global client

    p = argparse.ArgumentParser(description="Basic DC-net client")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=8, dest="n_clients")
    p.add_argument("data_dir")
    p.add_argument("private_data")
    opts = p.parse_args()

    # start new client using id and key from private_data
    with open(opts.private_data, "r", encoding="utf-8") as fp:
        data = json.load(fp)
        client_id = data["n"]
        private_key = data["private_key"]
        client = dcnet.Client(client_id, private_key)
    with open(os.path.join(opts.data_dir, "client.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        public_keys = data["public_keys"][:opts.n_clients]
        client.compute_secrets(public_keys)

    # start the http server
    run(port=client_id + 12345)

if __name__ == "__main__":
    main()
