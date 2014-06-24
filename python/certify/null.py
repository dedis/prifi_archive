#!/usr/bin/env python

class NullAccumulator:
    def before(self, ciphertexts):
        return ciphertexts

    def after(self, cleartexts):
        return cleartexts

class NullCertifier:
    def certify(self, ciphertexts):
        return ciphertexts

    def verify(self, cleartexts):
        return cleartexts

