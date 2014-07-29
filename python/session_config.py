import argparse
import json
import os
import random
import shutil

import config_utils
from config_utils import Config
import system_config

class SessionConfig:
    def __init__(self, group_id, session_id, clients, trustees):
        self.group_id = group_id
        self.session_id = session_id
        self.clients = clients
        self.trustees = trustees


def generate(system):
    group_id = system.group_id
    session_id = 1

    client_ids, trustee_ids = system.clients.ids, system.trustees.ids
    client_keys, client_secrets = config_utils.generate_keys(len(client_ids))
    trustee_keys, trustee_secrets = config_utils.generate_keys(len(trustee_ids))

    clients = Config.Clients(client_ids, client_keys)
    trustees = Config.Trustees(trustee_ids, trustee_keys)

    session = SessionConfig(group_id, session_id, clients, trustees)

    private = [Config.Private(i, s) for i, s in zip(client_ids +
            trustee_ids, client_secrets + trustee_secrets)]

    return session, private


def load(filename):
    with open(filename, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    group_id = data["group-id"]
    session_id = data["session-id"]

    clients = data["clients"]
    trustees = data["trustees"]

    client_ids, trustee_ids = config_utils.load_ids(clients, trustees)
    client_keys, trustee_keys = config_utils.load_keys(clients, trustees)

    clients = Config.Clients(client_ids, client_keys)
    trustees = Config.Trustees(trustee_ids, trustee_keys)

    return SessionConfig(group_id, session_id, clients, trustees)

def save(config, filename):
    clients = config_utils.save_clients(config.clients)
    trustees = config_utils.save_trustees(config.trustees)
    system = {
        "group-id" : config.group_id,
        "session-id" : config.session_id,
        "clients" : clients,
        "trustees" : trustees,
    }

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(system, fp)


def main():
    p = argparse.ArgumentParser(description="Generate session configuration")
    p.add_argument("output_dir")
    opts = p.parse_args()

    # XXX assumes hardcoded system config location
    system = system_config.load(os.path.join(opts.output_dir, "system.json"))

    session, private = generate(system)
    save(session, os.path.join(opts.output_dir, "session.json"))
    for priv in private:
        filename = "{}-{}.json".format(priv.id, session.session_id)
        filename = os.path.join(opts.output_dir, filename)
        config_utils.save_private(priv, filename)


if __name__ == "__main__":
    main()
