import binascii
import logging

from Crypto.Util.number import bytes_to_long

def string_to_long(s):
    s = bytes("".join(s.split()), "UTF-8")
    s = binascii.a2b_hex(s)
    return bytes_to_long(s)

verbosity = {"DEBUG":logging.DEBUG,
             "INFO":logging.INFO,
             "WARN":logging.WARNING,
             "ERROR":logging.ERROR,
             "CRITICAL":logging.CRITICAL}
