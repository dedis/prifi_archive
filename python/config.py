import argparse
import json
import os
import random
import shutil

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from elgamal import PublicKey, PrivateKey
from dcnet import global_group

long_to_pub = lambda x: PublicKey(global_group, x)
pub_to_long = lambda x: x.element

long_to_priv = lambda x: PrivateKey(global_group, x)
priv_to_long = lambda x: x.secret

class Relay:
    HOST = "host"; PORT = "port"

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def save(self):
        return {
            Relay.HOST : self.host,
            Relay.PORT : self.port,
        }

    @classmethod
    def load(cls, data):
        host = data[Relay.HOST]
        port = data[Relay.PORT]
        return cls(host, port)

class Nodes:
    ID = "id"; KEY = "key"

    def __init__(self, ids, keys):
        self.ids = ids
        self.keys = keys

    def save(self):
        return [{
            Nodes.ID : id,
            Nodes.KEY : pub_to_long(key),
        } for id, key in zip(self.ids, self.keys)]

    @classmethod
    def load(cls, data):
        ids = [d[Nodes.ID] for d in data]
        keys = [long_to_pub(d[Nodes.KEY]) for d in data]
        return cls(ids, keys)

    @classmethod
    def generate(cls, n):
        secrets = [PrivateKey(global_group) for _ in range(n)]
        keys = [key.public_key() for key in secrets]

        id = lambda x: SHA256.new(long_to_bytes(pub_to_long(x))).hexdigest()
        ids = [id(key) for key in keys]

        privates = [Private(id, secret) for id, secret in zip(ids, secrets)]

        return cls(ids, keys), privates

class Clients(Nodes):
    pass

class Trustees(Nodes):
    pass

class Slots:
    def __init__(self, keys):
        self.keys = keys

    def save(self):
        return [pub_to_long(key) for key in self.keys]

    @classmethod
    def load(cls, data):
        keys = [long_to_pub(d) for d in data]
        return cls(keys)

class Private:
    ID = "id"; SECRET = "secret"

    def __init__(self, id, secret):
        self.id = id
        self.secret = secret

    def save(self):
        return {
            Private.ID : self.id,
            Private.SECRET : priv_to_long(self.secret),
        }

    @classmethod
    def load(cls, data):
        id = data[Private.ID]
        secret = long_to_priv(data[Private.SECRET])
        return cls(id, secret)


class SystemConfig:
    VERSION = "version"; GROUP_ID = "group-id"
    RELAY = "relay"; CLIENTS = "clients"; TRUSTEES = "trustees"

    def __init__(self, version, group_id, relay, clients, trustees):
        self.version = version
        self.group_id = group_id
        self.relay = relay
        self.clients = clients
        self.trustees = trustees

    def save(self):
        return {
            SystemConfig.VERSION : self.version,
            SystemConfig.GROUP_ID : self.group_id,
            SystemConfig.RELAY : self.relay.save(),
            SystemConfig.CLIENTS : self.clients.save(),
            SystemConfig.TRUSTEES : self.trustees.save(),
        }

    @classmethod
    def load(cls, data):
        version = data[SystemConfig.VERSION]
        group_id = data[SystemConfig.GROUP_ID]
        relay = Relay.load(data[SystemConfig.RELAY])
        clients = Clients.load(data[SystemConfig.CLIENTS])
        trustees = Trustees.load(data[SystemConfig.TRUSTEES])
        return cls(version, group_id, relay, clients, trustees)

    @classmethod
    def generate(cls, nclients, ntrustees):
        version = 1
        group_id = 1
        relay = Relay("localhost", 12345)
        clients, client_privates = Clients.generate(nclients)
        trustees, trustee_privates = Trustees.generate(ntrustees)
        privates = client_privates + trustee_privates
        return cls(version, group_id, relay, clients, trustees), privates


class SessionConfig:
    GROUP_ID = "group-id"; SESSION_ID = "session-id"
    CLIENTS = "clients"; TRUSTEES = "trustees"

    def __init__(self, group_id, session_id, clients, trustees):
        self.group_id = group_id
        self.session_id = session_id
        self.clients = clients
        self.trustees = trustees

    def save(self):
        return {
            SessionConfig.GROUP_ID : self.group_id,
            SessionConfig.SESSION_ID : self.session_id,
            SessionConfig.CLIENTS : self.clients.save(),
            SessionConfig.TRUSTEES : self.trustees.save(),
        }

    @classmethod
    def load(cls, data):
        group_id = data[SessionConfig.GROUP_ID]
        session_id = data[SessionConfig.SESSION_ID]
        clients = Clients.load(data[SessionConfig.CLIENTS])
        trustees = Trustees.load(data[SessionConfig.TRUSTEES])
        return cls(group_id, session_id, clients, trustees)

    @classmethod
    def generate(cls, system_config):
        group_id = system_config.group_id
        session_id = 1

        client_ids = system_config.clients.ids
        trustee_ids = system_config.trustees.ids
        ids = client_ids + trustee_ids

        clients, client_privates = Clients.generate(len(client_ids))
        trustees, trustee_privates = Trustees.generate(len(trustee_ids))
        privates = client_privates + trustee_privates

        for id, private in zip(ids, privates):
            private.id = id

        return cls(group_id, session_id, clients, trustees), privates


class PseudonymConfig:
    GROUP_ID = "group-id"; SESSION_ID = "session-id"
    SLOTS = "slots"

    def __init__(self, group_id, session_id, slots):
        self.group_id = group_id
        self.session_id = session_id
        self.slots = slots

    def save(self):
        return {
            PseudonymConfig.GROUP_ID : self.group_id,
            PseudonymConfig.SESSION_ID : self.session_id,
            PseudonymConfig.SLOTS : self.slots.save()
        }

    @classmethod
    def load(cls, data):
        group_id = data[PseudonymConfig.GROUP_ID]
        session_id = data[PseudonymConfig.SESSION_ID]
        slots = Slots.load(data[PseudonymConfig.SLOTS])
        return cls(group_id, session_id, slots)
        
    @classmethod
    def generate(cls, session_config):
        group_id = session_config.group_id
        session_id = session_config.session_id

        slot_keys = session_config.clients.keys
        random.shuffle(slot_keys)
        slots = Slots(slot_keys)
 
        return cls(group_id, session_id, slots)


def load(cls, filename):
    with open(filename, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    return cls.load(data)

def save(obj, filename):
    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(obj.save(), fp)


def main():
    p = argparse.ArgumentParser(description="Generate system configuration")
    p.add_argument("-c", "--clients", type=int, metavar="clients", default=10, dest="clients")
    p.add_argument("-t", "--trustees", type=int, metavar="trustees", default=3, dest="trustees")
    p.add_argument("-s", "--seed", type=str, metavar="seed", default=None, dest="seed")
    p.add_argument("output_dir")
    opts = p.parse_args()

    shutil.rmtree(opts.output_dir, True)
    os.mkdir(opts.output_dir)

    if opts.seed is not None:
        random.seed(opts.seed)

    system_config, privates = SystemConfig.generate(opts.clients, opts.trustees)
    session_config, session_privates = SessionConfig.generate(system_config)
    pseudonym_config = PseudonymConfig.generate(session_config)

    save(system_config, os.path.join(opts.output_dir, "system.json"))
    save(session_config, os.path.join(opts.output_dir, "session.json"))
    save(pseudonym_config, os.path.join(opts.output_dir, "pseudonym.json"))

    for private in privates:
        save(private, os.path.join(opts.output_dir, "{}.json".format(private.id)))

    session_id = session_config.session_id
    for private in session_privates:
        save(private, os.path.join(opts.output_dir, "{}-{}.json".format(private.id, session_id)))

    print("Generated configs for {} client, {} trustees".format(opts.clients, opts.trustees))


if __name__ == "__main__":
    main()
