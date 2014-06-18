import functools
import operator
import random

# Borrowed Benjamin's daga prime and generator
P = 124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154806151119
G = 99656004450068572491707650369312821808187082634000238991378622176696343491115105589981816355495019598158936211590631375413874328242985824977217673016350079715590567506898528605283803802106354523568154237112165652810149860207486982093994904778268429329328161591283210109749627870113664380845204583563547255062
Q = (P - 1) // 2

def shared_secret(public, private):
    return pow(public, private, P)

def randbits(rand, bits):
    return rand.randrange((1 << bits) - 1)

def secret_streams(private_key, public_keys):
    return [random.Random(shared_secret(p, private_key)) for p in public_keys]

class Client:

    def __init__(self, client_id, private_key):
        self.id = client_id
        self.private_key = private_key

    def compute_secrets(self, trustee_keys):
        # complete the Diffie-Hellman exchange to generate streams
        self.n_peers = len(trustee_keys)
        self.prsgs = secret_streams(self.private_key, trustee_keys)

    def encode(self, payload_len, message):
        # combine all the coin flips
        coins = [randbits(self.prsgs[i], payload_len) for i in range(self.n_peers)]
        data = functools.reduce(operator.xor, coins, 0)

        # add message if present
        if message != None:
            message = int.from_bytes(message, "big")
            data ^= message
        return data

class Trustee:

    def __init__(self, trustee_id, private_key):
        self.id = trustee_id
        self.private_key = private_key

    def compute_secrets(self, client_keys):
        self.n_peers = len(client_keys)
        self.prsgs = secret_streams(self.private_key, client_keys)

    def encode(self, payload_len):
        coins = [randbits(self.prsgs[i], payload_len) for i in range(self.n_peers)]
        data = functools.reduce(operator.xor, coins, 0)
        return data

class Relay:

    def __init__(self):
        pass

    def decode_start(self):
        self.data = 0
        self.client_received = 0
        self.trustee_received = 0

    def decode_client(self, client_id, payload):
        self.data ^= payload
        self.client_received += 1

    def decode_trustee(self, trustee_id, payload):
        self.data ^= payload
        self.trustee_received += 1

    def decode_final(self):
        return self.data.to_bytes(self.data.bit_length() + 7 // 8, "big")
