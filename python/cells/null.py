#!/usr/bin/env python

class NullEncoder:
    def encode(self, cell):
        return cell

    def decoded_size(self, size):
        return size

    def encoded_size(self, size):
        return size

class NullDecoder:
    def decode(self, cell):
        return cell

