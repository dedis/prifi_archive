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

class Client:

    def __init__(self, client_id, private_key):
        self.id = client_id
        self.private_key = private_key
        self.slot_size = 512

    def compute_secrets(self, public_keys):
        # complete the Diffie-Hellman exchange
        self.public_keys = public_keys
        self.n_clients = len(self.public_keys)
        self.shared_secrets = [shared_secret(public_key, self.private_key) for public_key in self.public_keys]

        # use shared secrets to seed pseudo-random streams for longer messages
        self.prsgs = [random.Random(secret) for secret in self.shared_secrets]

        # we're the leader
        if self.id == 0:
            self.received = 0
            self.exchange = list()

    def prepare_exchange(self, exchange_id, message):
        transmission = list()
        for slot in range(self.n_clients):
            # combine all the coin flips
            coins = [randbits(self.prsgs[i], self.slot_size) for i in range(self.n_clients) if i != self.id]
            data = functools.reduce(operator.xor, coins, 0)

            # add message if it's my turn
            if slot == self.id:
                message = message.encode("utf-8")
                message = int.from_bytes(message, "big")
                assert message.bit_length() <= self.slot_size
                data ^= message

            # add the slot
            transmission.append(data)

        return transmission

    def handle_exchange(self, exchange_id, client_id, data):
        # only the leader should ever receive
        assert self.id == 0

        # make sure all slots are present
        assert len(data) == self.n_clients

        # update the current state of exchange
        self.exchange.append(data)
        self.received += 1

        # if we have all the pieces, extract the message
        if self.received == self.n_clients:
            messages = [0] * self.n_clients
            for share in self.exchange:
                for i, slot in enumerate(share):
                    messages[i] ^= slot

            for i, message in enumerate(messages):
                messages[i] = message.to_bytes(self.slot_size // 8, "big")
                messages[i] = messages[i].decode("utf-8")

            self.received = 0
            self.exchange = list()
            return messages
