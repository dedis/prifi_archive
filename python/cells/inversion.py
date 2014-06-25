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

class InversionEncoder:
    """ Class for encoding cells according to the inversion scheme.
    
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
    def __init__(self, seed, chunk_size):
        self.seed = seed
        self.chunk_size = chunk_size
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
        chunks = self.__bits_to_chunks(Bits(cell), self.chunk_size)
        noise, positions = self.__generate_traps(len(chunks))
        return self.__encode_chunks(noise, positions, chunks)

    def decoded_size(self, size):
        size = size * 8  # Convert from bytes to bits
        bits_size = (size * self.chunk_size - self.chunk_size + 1) / \
                    (self.chunk_size + 1)
        print("decoded size for size {0}: {1}".format(size, bits_size))
        return (bits_size + 7) / 8

    def encoded_size(self, size):
        size = size * 8  # Convert from bytes to bits
        bits_size = size + ((size + (self.chunk_size - 1)) / self.chunk_size)
        print("encoded size for size {0}: {1}".format(size, bits_size))
        return (bits_size + 7) / 8

    def verify(self, cell):
        """ Checks that the trap bit in each chunk in cipherchunks is correct.
            Precondition: noise_state and position_state should be in the
            initial state for the cell to be checked.

          inputs:
            cell (Bits list): The chunks output of encode, with the header as
              the first chunk (the header will be ignored)
            output: True if it all matches, False otherwise.
        """
        if (len(cell) < 2):
            print("Warning: Attempt to verify empty ciphertext")
            return True
        cipherchunks = cell[1:]
        noise, positions = self.__generate_traps(len(cipherchunks))
        for i in range(len(cipherchunks)):
            back_chunk = noise[i]
            this_bit = positions[i]
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
        noise = [Bits(uint=random.getrandbits(self.chunk_size),
                      length=self.chunk_size)\
                 for _ in range(num_chunks)]
        self.noise_state = random.getstate()
        random.setstate(self.position_state)
        positions = [random.randint(0, self.chunk_size - 1)\
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
            if chunks[i][positions[i]] == noise[i][positions[i]]:
                new_chunks += [chunks[i]]
                new_header += [False]
            else:
                new_chunks += [~chunks[i]]
                new_header += [True]
        return [Bits(new_header)] + new_chunks

    def __bits_to_chunks(self, in_bin, chunk_l):
        """ in_bin (Bits): the input message
            chunk_l (int): the chunk length in bits
        """
        return [in_bin[i:i + chunk_l] for i in range(0, len(in_bin), chunk_l)]


class InversionDecoder:
    def decode(self, cell):
        """ Takes the output of encode and returns it decoded (in bytes).
        """
        cipherheader = cell[0]
        cipherchunks = cell[1:]
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
        to_test = rand_string(300)
        debug(1, "Testing encoding/decoding {0} of 10".format(i))
        e.reset()
        if test_encode_verify_decode(e, d, to_test) == False:
            return False
    print("[+] Passed correctness!")
    return True

def test_encode_verify_decode(e, d, message):
    encoded = e.encode(bytes(message, "utf-8"))
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

def test_size_reporting(e, encoded, decoded):
    if e.decoded_size(len(encoded)) == len(decoded):
        print("[+] Passed decoded size")
    else:
        print("[x] Failed decoded size for {2}: Expected {0}, got {1}"
              .format(len(decoded), e.decoded_size(len(encoded)), decoded))
    if e.encoded_size(len(decoded)) == len(encoded):
        print("[+] Passed encoded size")
    else:
        print("[x] Failed encoded size for {2}: Expected {0}, got {1}"
              .format(len(encoded), e.encoded_size(len(decoded)), decoded))

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

# Performance tests
def vary_message_size(e, min_bytes, max_bytes):
    print("Testing performance of strings from {0} to {1} kilobytes."
          .format(min_bytes / 1000, max_bytes / 1000))
    print("Size\tAvg Time\tAvg time per kB\tAvg kB/second")
    i = 0
    while min_bytes * (2 ** i) <= max_bytes:
        test_message_size(e, min_bytes * (2 ** i))
        i += 1
    print("Done!")

def test_message_size(e, total_bytes, trials=10):
    times = []
    for _ in range(trials):
        message = rand_string(total_bytes)
        times += [speed_encode_msg(e, bytes(message, "utf-8"))]
    print("{0}\t{1}\t{2}\t{3}"
          .format(total_bytes / 1000,
                  numpy.mean(times),
                  numpy.mean(times) / total_bytes / 1000,
                  total_bytes / 1000 / numpy.mean(times)))
    return total_bytes / 1000 / numpy.mean(times)

def speed_encode_msg(e, message):
    start = time.time()
    e.encode(message)
    stop = time.time()
    return stop - start

if __name__ == '__main__':
    e = InversionEncoder(1, 32)
    d = InversionDecoder()
    test_correctness(e, d)
#     vary_message_size(e, 128, 16 * 1024)
