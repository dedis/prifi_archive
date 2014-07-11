#!/usr/bin/env python

class NullChecker:
    def __init__(self, arg=None):
        return

    def trap_noise(self, count):
        return [bytes(1)] * count

    def check(self, cell):
        return True

class NullEncoder:
    def __init__(self, arg=None):
        return

    def encode(self, cell):
        return cell

    def decoded_size(self, size):
        return size

    def encoded_size(self, size):
        return size

class NullDecoder:
    def __init__(self, arg=None):
        return

    def decode(self, cell):
        return cell

