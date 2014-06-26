#!/usr/bin/env python
'''
Created on Jun 25, 2014

@author: eleanor
'''
import random
import string
import numpy
import time
from bitstring import Bits, BitArray

chunks_per_cell = 75
chunk_size = 32
### Number of bytes of header prepended to each encoded cell
header_size = -(-chunks_per_cell // 8)

class InversionEncoder:
    """ Class for encoding cells according to the inversion scheme.
    
    NOTE: This currently only supports encoding cells with sizes that are
    multiples of the chunk size. We could pad odd length cells, but this would
    require either additional overhead (a length field or a flag of some kind)
    or processing at another layer.

    Attributes:
      seed (object): The base seed to use for both random number generators
      chunk_size (int): The number of bits per chunk of output.
      noise_state (tuple): The result of a call to random.getstate() when
        random has been seeded appropriately, such that calling
        random.setstate(noise_state) will result in a PRNG that generates
        the expected next noise bits.
      position_state (tuple): Same as noise_state for the trap bit position
        generator
    """
    def __init__(self, seed):
        self.seed = seed
        random.seed((seed, "Noise"))
        self.noise_state = random.getstate()
        random.seed((seed, "Position"))
        self.position_state = random.getstate()

    def reset(self):
        """ Reset the random generators """
        random.seed((self.seed, "Noise"))
        self.noise_state = random.getstate()
        random.seed((self.seed, "Position"))
        self.position_state = random.getstate()

    def encode(self, cell):
        """ Takes plaintext to encode and returns a tuple (header, chunks) Note:
        This means that for an n-bit input_text with chunks size k, the total
        important output data produced will take up n + (n/k) bits because the
        header adds (n/k) bits of overhead.

        inputs:
          input_text (bytes): The data to encode
        """
        chunks = bits_to_chunks(Bits(cell))
        assert(len(chunks) <= chunks_per_cell)
        noise, positions = self.__generate_traps(len(chunks))
        header, enc = self.__encode_chunks(noise, positions, chunks)
        full_header = Bits(header + [False] * (header_size * 8 - len(header)))
        byte_head = full_header.tobytes()
        debug(2, "Header: {0}.\n Full header: {4}\n enc: {1}\n or: {2}.\n" + \
              "Together: {3}"
              .format(Bits(header), enc, BitArray().join(enc).tobytes(),
                      Bits(byte_head + BitArray().join(enc).tobytes()),
                      full_header))
        return byte_head + BitArray().join(enc).tobytes()

    def decoded_size(self, size):
        """ The size in bytes of the decoded version of an encoded string that
        is size bytes long """
        return size - header_size

    def encoded_size(self, size):
        """ The size in bytes of the encoded version of a decoded string that
        is size bytes long """
        return size + header_size

    def verify(self, cell):
        """ Checks that the trap bit in each chunk in cipherchunks is correct.
            Precondition: noise_state and position_state should be in the
            initial state for the cell to be checked.

          inputs:
            cell (Bits list): The chunks output of encode, with the header as
              the first chunk (the header will be ignored)
            output: True if it all matches, False otherwise.
        """
        _, cipherchunks = encoded_bytes_to_header_chunks(cell)
        if (len(cipherchunks) < 1):
            print("Warning: Attempt to verify empty ciphertext")
            return True
        noise, positions = self.__generate_traps(len(cipherchunks))
        for i in range(len(cipherchunks)):
            back_chunk = noise[i]
            this_bit = positions[i]
            debug(2, "back_chunk: {0}. this_bit: {1}. cipherchunks: {2}"
                  .format(back_chunk, this_bit, cipherchunks))
            if back_chunk[this_bit] != cipherchunks[i][this_bit]:
                print("Mismatch on chunk {0} at {1}:"
                      .format(i, this_bit))
                print("Got {0}({1}), expected {2}({3})"
                      .format(cipherchunks[i], cipherchunks[i][this_bit],
                              back_chunk, back_chunk[this_bit]))
                return False
        return True

    def __generate_traps(self, num_chunks):
        """ Generate num_chunks terms of the noise and trap position sequences.

          inputs:
            noise_state, position_state (tuple): Random states as described above
            chunk_size (int): The number of bits per noise chunk to generate
            num_chunks (int): The number of terms to generate
          outputs:
            noise (Bits list): List of chunk_size-bit noise chunks
            positions (int list): List of trap bit positions (ints between 0 and
              chunk_size)
        """
        random.setstate(self.noise_state)
        noise = [Bits(uint=random.getrandbits(chunk_size),
                      length=chunk_size)\
                 for _ in range(num_chunks)]
        self.noise_state = random.getstate()
        random.setstate(self.position_state)
        positions = [random.randint(0, chunk_size - 1)\
                     for _ in range(num_chunks)]
        self.position_state = random.getstate()
        return noise, positions

    def __encode_chunks(self, noise, positions, chunks):
        """ Encodes a list of Bits objects.

          inputs:
            noise (Bits list): The list of noise chunks to encode around
            positions (int list): The position of the trap bit in each chunk
            chunks (Bits list): The output of bits_to_chunks, to be encoded
          outputs:
            new_header (Boolean list): One element per chunk, True if that chunk
              is inverted and false otherwise.
            new_chunks (Bits list): List of the encoded chunks, represented as
              Bits
        """
        new_chunks = []
        new_header = []
        for i in range(len(chunks)):
            debug(2, "i: {0}. chunk: {1}. Position: {2}. noise: {3}."
                  .format(i, chunks[i], positions[i], noise[i]))
            if chunks[i][positions[i]] == noise[i][positions[i]]:
                new_chunks += [chunks[i]]
                new_header += [False]
            else:
                new_chunks += [~chunks[i]]
                new_header += [True]
        return new_header, new_chunks

def bits_to_chunks(in_bin):
    """ in_bin (Bits): the input message
        chunk_size (int): the chunk length in bits
    """
    return [in_bin[i:i + chunk_size]\
            for i in range(0, len(in_bin), chunk_size)]

def encoded_bytes_to_header_chunks(cell):
    header_bytes = cell[:header_size]
    cipherchunks = bits_to_chunks(Bits(cell[header_size:]))
    cipherheader = Bits(Bits(header_bytes)[:len(cipherchunks)])
    debug(2, "Full initial header was: {3}.\n Header size was: {4}\n" + \
        "{0}.\n Chunks was: {1}.\n Original was: {2}" .format(cipherheader,
        cipherchunks, Bits(cell), Bits(header_bytes), header_size))
    return cipherheader, cipherchunks

class InversionDecoder:
    def decode(self, cell):
        """ Takes the output of encode and returns it decoded (in bytes).
        """
        cipherheader, cipherchunks = encoded_bytes_to_header_chunks(cell)
        plain_chunks = self.__decode_chunks(cipherheader, cipherchunks)
        joined = BitArray().join(plain_chunks)
        return joined.tobytes()

    def __decode_chunks(self, head, chunks):
        """ Takes encoded input and returns the decoded chunks (i.e., the
            input to __encode_chunks).
        """
        plain_chunks = []
        for i in range(len(chunks)):
            invert = head[i]
            decoded = chunks[i]
            if invert:
                decoded = ~decoded
            plain_chunks += [decoded]
        return plain_chunks

###### Tests ######
def test_correctness(e, d):
    for i in range(10):
        debug(2, "Getting random string...")
        to_test = rand_string(random.randint(1, 75) * 4)
        debug(1, "Testing encoding/decoding {0} of 10".format(i))
        e.reset()
        if test_encode_verify_decode(e, d, to_test) == False:
            return False
    print("[+] Passed correctness!")
    return True

def test_encode_verify_decode(e, d, message):
    encoded = e.encode(bytes(message, "utf-8"))
    debug(2, "Encoded: {0}\n or:{1}".format(encoded, Bits(encoded)))
    e.reset()
    if e.verify(encoded) == False:
        print("[x] Failed encoding: Problem with trap bits for {0}"
              .format(message))
        return False
    new_text = d.decode(encoded).decode("utf-8")
    if new_text != message:
        print("[x] Failed decoding: Expected {0} but got {1}"
              .format(new_text, message))
        return False
    if not test_size_reporting(e, encoded, bytes(new_text, "utf-8")):
        return False
    return True

def test_size_reporting(e, encoded, decoded):
    if e.decoded_size(len(encoded)) != len(decoded):
        print("[x] Failed decoded size for {2}:\n Expected {0}, got {1}"
              .format(len(decoded), e.decoded_size(len(encoded)), decoded))
        return False
    if e.encoded_size(len(decoded)) != len(encoded):
        print("[x] Failed encoded size for {2}:\n Expected {0}, got {1}"
              .format(len(encoded), e.encoded_size(len(decoded)), decoded))
        return False
    return True

def rand_string(length=5):
    chars = list(string.ascii_uppercase + string.digits)
    ret = []
    for _ in range(length):
        ret += [random.choice(chars)]
    return ''.join(ret)

debug_level = 1
def debug(level, msg):
    if level <= debug_level:
        print(msg)

if __name__ == '__main__':
    e = InversionEncoder(1)
    d = InversionDecoder()
    test_correctness(e, d)
