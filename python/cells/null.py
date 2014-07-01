#!/usr/bin/env python

class NullChecker:
    def __init__(self, arg=None):
        return

    def reset(self, arg=None):
        return

    def check(self, cell):
        return True

class NullEncoder:
    def encode(self, cell):
        return cell

    def decoded_size(self, size):
        return size

    def encoded_size(self, size):
        return size

    def reset(self, arg=None):
        return

class NullDecoder:
    def decode(self, cell):
        return cell

