#!/usr/bin/env python
'''
Created on Jun 25, 2014

@author: eleanor
'''
import random
import string
import math
from utils import debug
from bitstring import Bits, BitArray

cell_bit_length = 12 * 8  # Bits per cell
chunk_size = 8  # bits per chunk
# number of bytes needed to represent the length in bits of the data
length_field_size = math.ceil(math.ceil(math.log2(cell_bit_length)) / 8)
# number of chunks needed to represent the length in bits of the data
length_field_chunks = math.ceil(length_field_size * 8 / chunk_size)
# number of chunks of data (length field excluded) that can fit in a cell
chunks_per_cell = math.floor((cell_bit_length - length_field_size * 8) / (1 + chunk_size))
# number of bytes needed to represent the inversion bits
invert_header_size = math.ceil(math.ceil(chunks_per_cell / chunk_size) * chunk_size / 8)
# number of chunks needed to represent the inversion bits
invert_header_chunks = math.ceil(invert_header_size * 8 / chunk_size)
# maximum number of bytes of data that encode can be called on
max_in_size = chunks_per_cell * chunk_size // 8 - invert_header_size
debug(1, "cell_bit_length: {0} ".format(cell_bit_length) + \
"chunk_size: {0} ".format(chunk_size) + \
"length_field_size: {0} ".format(length_field_size) + \
"length_field_chunks: {0} ".format(length_field_chunks) + \
"chunks_per_cell: {0} ".format(chunks_per_cell) + \
"invert_header_size: {0} ".format(invert_header_size) + \
"invert_header_chunks {0} ".format(invert_header_chunks) + \
"max_in_size: {0} ".format(max_in_size))

class InversionChecker():
    def __init__(self, seed=None):
        """ Note: If seed is not passed in constructor, it must be passed with
        reset before encoding.
        """
        self.seed = seed
        if seed != None:
            random.seed((seed, "Noise"))
            self.noise_state = random.getstate()
            random.seed((seed, "Position"))
            self.position_state = random.getstate()

    def reset(self, seed=None):
        """ Reset the random generators """
        if seed != None:
            self.seed = seed
        random.seed((self.seed, "Noise"))
        self.noise_state = random.getstate()
        random.seed((self.seed, "Position"))
        self.position_state = random.getstate()

    def check(self, cell):
        """ Checks that the trap bit in each chunk in cipherchunks is correct.
            Precondition: noise_state and position_state should be in the
            initial state for the cell to be checked.

          inputs:
            cell (Bits list): The chunks output of encode
            output: True if it all matches, False otherwise.
        """
        cipherchunks = bits_to_chunks(Bits(cell))
        if (len(cipherchunks) < 1):
            print("Warning: Attempt to check empty ciphertext")
            return True
        noise, positions = self._generate_traps(len(cipherchunks))
        for i in range(len(cipherchunks)):
            back_chunk = noise[i]
            this_bit = positions[i]
            debug(2, "back_chunk: {0}. this_bit: {1}. num chks: {3}. cipherchunks: {2}"
                  .format(back_chunk, this_bit, cipherchunks, len(cipherchunks)))
            if back_chunk[this_bit] != cipherchunks[i][this_bit]:
                print("Mismatch on chunk {0} at {1}:"
                      .format(i, this_bit))
                print("Got {0}({1}), expected {2}({3})"
                      .format(cipherchunks[i], cipherchunks[i][this_bit],
                              back_chunk, back_chunk[this_bit]))
                return False
        return True

    def _generate_traps(self, num_chunks):
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

class InversionEncoder(InversionChecker):
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
    def encode(self, cell):
        """ Takes plaintext to encode and returns a list of bytes encoding it.
        An n-bit input_text with chunks size k, the total
        important output data produced will take up n + (n/k) bits because the
        header adds (n/k) bits of overhead.

        inputs:
          cell (bytes): The data to encode
        """
        assert(self.encoded_size(len(cell)) <= cell_bit_length / 8)
        length_b = Bits(uint=len(cell) * 8, length=length_field_size * 8)
        length_p = Bits([False] * \
                        (length_field_chunks * chunk_size - len(length_b)) + \
                        length_b)
        chunks = bits_to_chunks(length_p + Bits(cell),
                                padchunks=True, padcell=True)
        assert(len(chunks) >= 1)
        noise, positions = self._generate_traps(len(chunks) + \
                                                invert_header_chunks)
        header_chunks, enc = self.__encode_chunks(noise, positions, chunks)
        header = BitArray().join(header_chunks)
        inv_h = Bits(header + [False] * \
                              math.ceil(invert_header_size * 8 - len(header)))
        inv_B = inv_h.tobytes()
        enc_b = BitArray().join(enc)
        enc_B = enc_b.tobytes()
        debug(2, "Length: {0}\n ByteLength: {1}\n Invert Header: {2}."
                  .format(len(cell) * 8, length_b, Bits(header)) + \
              "\n Full header: {0}\n enc: {1}\n Together: {2}"
                      .format(inv_h + enc[:length_field_chunks], enc,
                              Bits(inv_B + enc_B)) + \
              "\n  Cell: {0}\n len+cell bits: {1}"
                      .format(Bits(cell), length_p + Bits(cell)))
        return inv_B + enc_B

    def decoded_size(self, size):
        """ The size in bytes of the decoded version of an encoded string that
        is size bytes long
        Note: We can't tell exactly the decoded size without looking at the
        length field, so this returns a max size that will be within one
        chunk_size of the actual answer.
        """
        return max_in_size

    def encoded_size(self, size):
        """ The size in bytes of the encoded version of a decoded string that
        is size bytes long """
        chunks = math.ceil(8 * (size + length_field_size) / chunk_size)
        if chunks < chunks_per_cell:
            chunks = chunks_per_cell
        return math.ceil(chunks * chunk_size / 8) + \
            invert_header_size * (chunks - chunks_per_cell + 1)

    def __encode_chunks(self, noise, positions, chunks):
        """ Encodes a list of Bits objects.

          inputs:
            noise (Bits list): The list of noise chunks to encode around
            positions (int list): The position of the trap bit in each chunk
            chunks (Bits list): The output of bits_to_chunks, to be encoded
          outputs:
            header_chunks (Bits list): Bits indicating whether each chunk of
              new_chunks is inverted or not. This field is also encoded into
              chunks, where the first bit of each chunk indicates whether it is
              inverted.
            new_chunks (Bits list): List of the encoded chunks, represented as
              Bits
        """
        new_chunks = []
        new_header = []
        header_noise = noise[:invert_header_chunks]
        noise = noise[invert_header_chunks:]
        header_positions = positions[:invert_header_chunks]
        positions = positions[invert_header_chunks:]
        for i in range(len(chunks)):
            debug(2, "i: {0}. chunk: {1}. Position: {2}. noise: {3}."
                  .format(i, chunks[i], positions[i], noise[i]))
            if chunks[i][positions[i]] == noise[i][positions[i]]:
                new_chunks += [chunks[i]]
                new_header += [False]
            else:
                new_chunks += [~chunks[i]]
                new_header += [True]
            debug(2, "Encoded chunk {0} which was {1} as {2} to avoid {3} of {4}."
                  .format(i, chunks[i], new_chunks[-1], positions[i], noise[i]))
        header_chunks = bits_to_chunks(new_header, padchunks=True, prepend=1)
        debug(2, "new header: {0}\n header chunks: {1},\n header_noise: {2}"
              .format(Bits(new_header), header_chunks, header_noise) + \
                "\n header_positions: {0}".format(header_positions))
        for i in range(len(header_noise)):
            if header_chunks[i][header_positions[i]] != \
              header_noise[i][header_positions[i]]:
                header_chunks[i] = ~header_chunks[i]
        return header_chunks, new_chunks

class InversionDecoder:
    def decode(self, cell):
        """ Takes the output of encode and returns it decoded (in bytes).
        """
        _, cipherheader, cipherchunks = encoded_bytes_to_header_chunks(cell)
        plain_chunks = self.__decode_chunks(cipherheader, cipherchunks)
        joined = BitArray().join(plain_chunks)
        return joined.tobytes()

    def __decode_chunks(self, head, chunks):
        """ Takes encoded input and returns the decoded chunks
        inputs:
          head (Bits): The inversion bits as a single bit list. Must be the
            same length as chunks (trailing bits will be ignored)
          chunks (Bits list): The data chunks, excluding the length field added
            in encode
        """
        plain_chunks = []
        for i in range(len(chunks)):
            invert = head[i]
            decoded = chunks[i]
            if invert:
                decoded = ~decoded
            plain_chunks += [decoded]
        return plain_chunks

###### Shared helper functions ######

def bits_to_chunks(in_bin, padcell=False, padchunks=False, prepend=0):
    """ in_bin (Bits): the input message
        padcell (bool): If True, blank chunks will be added so the output fills
          a cell (with room left for inversion bits)
        padchunks (bool): If True, if the last chunk is less than chunk_size,
          zeros will be appended until it fills a chunk
        prepend (int): The number of bits to be prepended to each chunk. If this
          is set to greater than zero, then chunk_size - prepend bits of data
          and prepend zero-bits at the beginning will be in each output chunk.
          This is used for the alternate encoding scheme used for the inversion
          header.
    """
    new_chunks = [Bits([False] * prepend + in_bin[i:i + chunk_size - prepend])\
            for i in range(0, len(in_bin), chunk_size - prepend)]
    if padchunks:
        new_chunks[-1] = Bits(new_chunks[-1] + \
                          [False] * (chunk_size - len(new_chunks[-1])))
    if padcell:
        extra_chunks = chunks_per_cell - len(new_chunks)
        new_chunks.extend([Bits([False] * chunk_size)] * extra_chunks)
    return new_chunks

def encoded_bytes_to_header_chunks(cell, trim=True):
    """ Converts an encoded list of bytes to a tuple (length, header, chunks),
    where length is the number of bits of data in the plaintext, header is the
    inversion bits, and chunks is a list of chunks of data.
    If trim is True, any padding added during encode will be removed.
    """
    # Separate the inversion bits
    header = bits_to_chunks(Bits(cell)[:invert_header_size * chunk_size])
    offset = invert_header_size + length_field_size
    # Separate the length field from the data chunks
    length_chunks = bits_to_chunks(Bits(cell[invert_header_size:offset]))
    # Decode the inversion bits
    for i in range(len(header)):
        if header[i][0] == 1:
            # Flip chunks of inversion bits if needed
            header[i] = ~header[i]
        # Remove the prepended bits from encode
        header[i] = header[i][1:]
    # De-chunk so the inversion bits are a single bitstring
    header = BitArray().join(header)
    # Decode the length field
    for i in range(len(length_chunks)):
        if header[i] == 1:
            length_chunks[i] = ~length_chunks[i]
    # Trim the length field bits from the inversion header
    header = header[len(length_chunks):]
    # parse the length field
    length = BitArray().join(length_chunks).unpack("uint")[0]
    if trim:
        cipherchunks = bits_to_chunks(Bits(cell[offset:])[:length])
    else:
        cipherchunks = bits_to_chunks(Bits(cell[offset:]))
    # Trim any extra inversion header bits
    cipherheader = Bits(header[:len(cipherchunks)])
    debug(2, "Full initial header was: {0}".format(Bits(cell[:offset])) + \
          "\n invert header: {0}.".format(header) + \
          "\n cipherheader: {0}".format(cipherheader) + \
          "\n len cipherheader {0}".format(len(cipherheader)) + \
          "\n cipherchunks {0}".format(cipherchunks) + \
          "\n len cipherchunks: {0}.".format(len(cipherchunks)) + \
          "\n Original was: {0}".format(Bits(cell)) + \
          "\n length bin: {0}".format(Bits(cell[invert_header_size:offset])) + \
          "\n length: {0}".format(length) + \
          "\n length chunks: {0}".format(length_chunks))
    return length, cipherheader, cipherchunks


###### Tests ######
def test_correctness(e, d):
    for i in range(10):
        debug(2, "Getting random string...")
        random.seed()
        to_test = rand_string(random.randint(1, max_in_size))
        debug(2, "Testing encoding/decoding {0} of 10".format(i))
        e.reset()
        if test_encode_check_decode(e, d, to_test) == False:
            return False
    print("[+] Passed correctness!")
    return True

def test_encode_check_decode(e, d, message):
    encoded = e.encode(bytes(message, "utf-8"))
    debug(2, "Encoded: {0}\n or:{1}".format(encoded, Bits(encoded)))
    e.reset()
    new_text = d.decode(encoded).decode("utf-8")
    if new_text != message:
        print("[x] Failed decoding:\n Expected {0}\n but got {1}"
              .format(message, new_text))
        return False
    if e.check(encoded) == False:
        print("[x] Failed checking: Problem with trap bits for {0}"
              .format(message))
        return False
    if not test_size_reporting(e, encoded, bytes(message, "utf-8")):
        return False
    return True

def test_size_reporting(e, encoded, decoded):
    if e.encoded_size(len(decoded)) != len(encoded):
        print("[x] Failed encoded size for {2}:\n Expected {0}, got {1}"
              .format(len(encoded), e.encoded_size(len(decoded)), decoded))
        return False
    if e.decoded_size(len(encoded)) < len(decoded):
        print("[x] Failed decoded size for {2}:\n Expected {0}, got {1}"
              .format(len(decoded), e.decoded_size(len(encoded)), decoded))
        return False
    return True

def rand_string(length=5):
    chars = list(string.ascii_uppercase + string.digits)
    ret = []
    for _ in range(length):
        ret += [random.choice(chars)]
    return ''.join(ret)

if __name__ == '__main__':
    e = InversionEncoder(1)
    d = InversionDecoder()
    test_correctness(e, d)
