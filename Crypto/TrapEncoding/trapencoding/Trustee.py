'''
Created on Jun 23, 2014

@author: eleanor
'''
import Crypto.Hash
import Crypto.Random.random.StrongRandom
from bitstring import Bits

H = Crypto.Hash.SHA

class Trustee:
    '''
    classdocs
    '''

    def __init__(self, session_id, private_key, owner_pub_keys):
        '''
        Constructor
        '''
        self.sid = session_id
        self.priv = private_key
        self.pubs = owner_pub_keys

    def check(self, interval_hash, owner_trap_secrets, cells):
        for i in range(owner_trap_secrets):
            secret = owner_trap_secrets[i]
            N = Crypto.Random.random.StrongRandom(H(secret, "Noise"))
            R = Crypto.Random.random.StrongRandom(H(secret, "Position"))
            # TODO: Trustees probably don't need the
            # to know the header.
            _, chunks = cells[i]
            if not self.__check_cell(N, R, chunks):
                return False
        return True

    def __check_cell(self, noise_gen, pos_gen, chunks):
        size = len(chunks[0])  # TODO: This will fail on empty chunks
        for chunk in chunks:
            back_chunk = Bits(uint=noise_gen.getrandombits(size), length=size)
            this_bit = pos_gen.randint(0, size - 1)
            if back_chunk[this_bit] != chunk[this_bit]:
                print("Mismatch on chunk {0} at {1}:"
                      .format(chunk, this_bit))
                print("Got {0}({1}), expected {2}({3})"
                      .format(chunk, chunk[this_bit],
                              back_chunk, back_chunk[this_bit]))
                return False
        return True
