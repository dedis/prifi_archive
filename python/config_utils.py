import json
import random

from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long

from elgamal import PublicKey, PrivateKey
from dcnet import global_group

# classes to make things easier
class Config:
    class Relay:
        def __init__(self, host, port):
            self.host = host
            self.port = port

    class Nodes:
        def __init__(self, ids, keys):
            self.ids = ids
            self.keys = keys

    class Clients(Nodes):
        pass

    class Trustees(Nodes):
        pass

    class Private:
        def __init__(self, id, secret):
            self.id = id
            self.secret = secret

    class Slots:
        def __init__(self, keys):
            self.keys = keys


# generating helpers
def generate_keys(n):
    private_keys = [PrivateKey(global_group) for _ in range(n)]
    public_keys = [key.public_key() for key in private_keys]
    return public_keys, private_keys

def _key2id(key):
    return SHA256.new(long_to_bytes(key.element)).hexdigest()

def generate_ids(*args):
    return [[_key2id(key) for key in arg] for arg in args]

# loading helpers
def _unpack(key, *args, func=None):
    if func is None:
        func = lambda x: x
    return [[func(x[key]) for x in arg] for arg in args]

def load_ids(*args):
    return _unpack("id", *args)

def load_keys(*args):
    long2key = lambda x: PublicKey(global_group, x)
    return _unpack("key", *args, func=long2key)

def load_slots(arg):
    return [PublicKey(global_group, x) for x in arg]

def load_private(filename):
    with open(filename, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    
    id = data["id"]
    secret = PrivateKey(global_group, data["secret"])

    return Config.Private(id, secret)

# saving helpers
def _save_nodes(nodes):
    return [{
        "id" : id,
        "key" : key.element,
    } for id, key in zip(nodes.ids, nodes.keys)]

save_clients = _save_nodes
save_trustees = _save_nodes

def save_slots(slots):
    return [key.element for key in slots.keys]

def save_private(private, filename):
    with open(filename, "w", encoding="utf-8") as fp:
        json.dump( { "id" : private.id, "secret" : private.secret.secret }, fp)

