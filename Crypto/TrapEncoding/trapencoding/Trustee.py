'''
Created on Jun 23, 2014

@author: eleanor
'''

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
        
    def check(self, interval_hash, owner_trap_secrets, encodeds): 
        return