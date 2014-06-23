'''
Created on Jun 23, 2014

@author: eleanor
'''

class Relay:
    '''
    classdocs
    '''

    def __init__(self, trap_encoder):
        '''
        Constructor
        '''
        self.te = trap_encoder

    def decode_cell(self, header, chunks):
        return self.te.decode(header, chunks)
