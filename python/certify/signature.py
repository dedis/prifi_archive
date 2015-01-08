#!/usr/bin/env python
from Crypto.Hash import SHA256

class SignatureAccumulator:
    def before(self, ciphertexts):
        self.signatures = [cph[1] for cph in ciphertexts]
        return [cph[0] for cph in ciphertexts]

    def after(self, cleartexts):
        return (cleartexts, self.signatures)

class SignatureCertifier:
    def __init__(self, key, client_keys):
        self.key = key
        self.client_keys = client_keys
        h = SHA256.new()
        self.hdata = h.digest()

    def certify(self, ciphertexts):
        return (ciphertexts, self.key.sign(self.hdata))

    def verify(self, cleartexts):
        signatures = cleartexts[1]
        assert len(signatures) == len(self.client_keys)
        for idx in len(signatures):
            sign = signatures[idx]
            assert self.client_keys[idx].verify(self.hdata, signatures[idx])

        h = SHA256.new()
        for slot in cleartexts[0]:
            for cell in slot:
                h.update(cell)
        self.hdata = h.digest()

        return cleartexts[0]

