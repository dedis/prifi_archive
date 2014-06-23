'''
Created on Jun 23, 2014

@author: eleanor
'''
import random
import Crypto.Hash

H = Crypto.Hash.SHA.new()

class TrapClient:
    '''
    classdocs
    '''

    def __init__(self, owner_private_key, trap_encoder):
        '''
        Constructor - called at the beginning of a session
        '''
        self.slot_priv = owner_private_key
        self.trap_alg = trap_encoder

    def interval_init(self, trustee_secrets, sid, first_cell):
        '''
        trustee_secrets (Secret list) -- list of slot-trustee shared secrets
        '''
        self.Tt = {}
        self.h = H.new((sid, first_cell, "IntervalInit"))
        for s in trustee_secrets:
            self.Tt[s] = self.h.digest() ** s
        self.T = H.new(self.Tt)
        random.seed((self.T, "Noise"))
        self.N = random.getstate()
        random.seed((self.T, "Position"))
        self.R = random.getstate()

    def encode_cell(self, payload, noise_gen, pos_gen, wordsize):
        '''
        Runs on a client each time it wants to put data in a cell
        '''
        te = self.trap_alg(wordsize, self.N, self.R)
        return te.encode(payload)
