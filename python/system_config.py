import argparse
import json
import os
import random
import shutil

import config_utils
from config_utils import Config


def generate(clients, trustees):
    version = 1
    group_id = 1

    relay = Config.Relay("localhost", 12345)

    client_keys, client_secrets = config_utils.generate_keys(clients)
    trustee_keys, trustee_secrets = config_utils.generate_keys(trustees)
    client_ids, trustee_ids = config_utils.generate_ids(client_keys, trustee_keys)

    clients = Config.Clients(client_ids, client_keys)
    trustees = Config.Trustees(trustee_ids, trustee_keys)

    system = SystemConfig(version, group_id, relay, clients, trustees)

    private = [Config.Private(i, s) for i, s in zip(client_ids +
            trustee_ids, client_secrets + trustee_secrets)]

    return system, private


def load(filename):
    with open(filename, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    version = data["version"]
    group_id = data["group-id"]

    relay = data["relay"]
    relay = Config.Relay(relay["host"], relay["port"])

    clients = data["clients"]
    trustees = data["trustees"]

    client_ids, trustee_ids = config_utils.load_ids(clients, trustees)
    client_keys, trustee_keys = config_utils.load_keys(clients, trustees)

    clients = Config.Clients(client_ids, client_keys)
    trustees = Config.Trustees(trustee_ids, trustee_keys)

    return SystemConfig(version, group_id, relay, clients, trustees)


def save(config, filename):
    relay = {
        "host" : config.relay.host,
        "port" : config.relay.port,
    }
    clients = config_utils.save_clients(config.clients)
    trustees = config_utils.save_trustees(config.trustees)
    system = {
        "version" : config.version,
        "group-id" : config.group_id,
        "relay" : relay,
        "clients" : clients,
        "trustees" : trustees,
    }

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(system, fp)


def main():
    p = argparse.ArgumentParser(description="Generate system configuration")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="trustees")
    p.add_argument("output_dir")
    opts = p.parse_args()

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    system, private = generate(opts.clients, opts.trustees)
    save(system, os.path.join(opts.output_dir, "system.json"))
    for priv in private:
        filename = "{}.json".format(priv.id)
        filename = os.path.join(opts.output_dir, filename)
        config_utils.save_private(priv, filename)


if __name__ == "__main__":
    main()
