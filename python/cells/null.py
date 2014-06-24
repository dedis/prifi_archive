#!/usr/bin/env python

class NullEncoder:
    def encode(self, cell):
        return cell

    def max_size(self, in_size):
        return in_size

class NullDecoder:
    def decode(self, cell):
        return cell

