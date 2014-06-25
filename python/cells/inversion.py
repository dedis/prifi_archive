#!/usr/bin/env python
'''
Created on Jun 25, 2014

@author: eleanor
'''
import random
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
          input_text (str): The string to encode
        """
        chunks = __bits_to_chunks(Bits(bytes(cell, "utf_8")), self.chunk_size)
        noise, positions = self.__generate_traps(len(chunks))
        return self.__encode_chunks(noise, positions, chunks)

    def decoded_size(self, size):
        size = size * 8  # Convert from bytes to bits
        return (size - self.chunk_size + 1) / (self.chunk_size + 1)

    def encoded_size(self, size):
        size = size * 8  # Convert from bytes to bits
        return size + ((size + (self.chunk_size - 1)) / self.chunk_size)

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
        noise, positions = self.__generate_traps(self.noise_state,
                                                 self.position_state,
                                                 len(cipherchunks[0]),
                                                 len(cipherchunks))
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
        noise = [Bits(random.getrandbits(self.chunk_size))\
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
        for i in len(chunks):
            if chunks[i] == \
            noise[i][positions[i]]:
                new_chunks += [chunks[i]]
                new_header += [False]
            else:
                new_chunks += [~chunks[i]]
                new_header += [True]
        return [Bits(new_header)] + new_chunks

class InversionDecoder:
    def decode(self, cell):
        """ Takes the output of encode and returns its decoded plaintext (str).
        """
        cipherheader = cell[0]
        cipherchunks = cell[1:]
        plain_chunks = self.__decode_chunks(cipherheader, cipherchunks)
        joined = BitArray().join(plain_chunks)
        bytes_joined = joined.tobytes()
        return bytes_joined.decode("utf-8")

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

def __bits_to_chunks(in_bin, chunk_l):
    """ in_bin (Bits): the input message
        chunk_l (int): the chunk length in bits
    """
    return [in_bin[i:i + chunk_l] for i in range(0, len(in_bin), chunk_l)]
