'''
Created on Jun 23, 2014

@author: eleanor
'''

class TrapClient:
    '''
    classdocs
    '''

    def __init__(self, owner_private_key):
        '''
        Constructor - called at the beginning of a session
        '''
        self.slot_priv = owner_private_key
    
    def interval_init(self, trustee_secrets):
        '''
        trustee_secrets (Secret list) -- list of slot-trustee shared secrets
        '''
        return
    
    def encode_cell(self, payload, noise_gen, pos_gen, wordsize):
        '''
        Runs on a client each time it wants to put data in a cell
        '''
        return
    