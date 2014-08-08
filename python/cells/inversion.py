#!/usr/bin/env python
'''
Created on Jun 25, 2014

@author: eleanor
'''
import random
import string
import math
import unittest
from utils import debug
from bitstring import Bits, BitArray
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256

cell_bit_length = 24 * 8  # Bits per cell
chunk_size = 8  # bits per chunk
# number of chunks of data that can fit in a cell
chunks_per_cell = math.floor((cell_bit_length) / +\
                             (1 + 1 / chunk_size + chunk_size))
# number of bytes needed to represent the inversion bits
invert_header_size = math.ceil(math.ceil(chunks_per_cell / (chunk_size - 1)) * \
                               chunk_size / 8)
# number of chunks needed to represent the inversion bits
invert_header_chunks = math.ceil(invert_header_size * 8 / chunk_size)
# maximum number of bytes of data that encode can be called on
max_in_size = chunks_per_cell * chunk_size // 8
debug(1, "cell_bit_length: {0} ".format(cell_bit_length) + \
"chunk_size: {0} ".format(chunk_size) + \
"chunks_per_cell: {0} ".format(chunks_per_cell) + \
"invert_header_size: {0} ".format(invert_header_size) + \
"invert_header_chunks {0} ".format(invert_header_chunks) + \
"max_in_size: {0} ".format(max_in_size))

class InversionBase():
    def __init__(self, seeds):
        self.noise_states = []
        h = SHA256.new()
        for seed in seeds:
            h.update(long_to_bytes(seed))
            random.seed(seed)
            self.noise_states.append(random.getstate())
        random.seed(h.digest())
        self.position_state = random.getstate()

    def trap_noise(self, count, kind="Cells"):
        """ Generate num_chunks terms of the noise sequence
          inputs:
            count: Number of CELLS of unit to generate
            kind: "Cells" or "Chunks"
          outputs:
            noise (Bits list): List of chunk_size-bit noise chunks
        """
        noises = {}
        noise = [Bits(cell_bit_length)] * count
        for i in range(len(self.noise_states)):
            noises[i] = []
            random.setstate(self.noise_states[i])
            debug(2, " noisestates {0} is {1}".format(i, self.noise_states[i]))
            for celldx in range(count):
                noises[i].append(random.getrandbits(cell_bit_length))
                debug(2, " xoring {0} into {1}".format(noises[i][-1], noise[celldx]))
                noise[celldx] ^= Bits(uint=noises[i][-1], length=cell_bit_length)
            self.noise_states[i] = random.getstate()
        noise = [n.tobytes() for n in noise]
        if kind == "Chunks":
            for i in range(len(noise)):
                assert(len(Bits(noise[i])) == cell_bit_length)
                chunks = bits_to_chunks(Bits(noise[i]))
                assert(len(chunks) == chunks_per_cell + invert_header_chunks), \
                    "Wrong number of chunks in chunk {0}: Expected {1} got {2}"\
                    .format(i, invert_header_chunks + chunks_per_cell, len(chunks))
                noise[i] = chunks
            debug(2, "Cell noises: {0}\n noise: {1}".format(noises, noise))
        else:
            debug(2, "Cell noises: {0}\n noise: {1}".format(noises,
                                                        [Bits(n) for n in noise]))
        return noise

    def trap_positions(self, num_chunks):
        """ Generate num_chunks terms of the trap position sequence.
          outputs:
            positions (int list): List of trap bit positions (ints between 0 and
              chunk_size)
          """
        random.setstate(self.position_state)
        positions = [random.randint(0, chunk_size - 1)\
                     for _ in range(num_chunks)]
        self.position_state = random.getstate()
        return positions

    def cell_trap_mask(self, noise, positions):
        """ Generates a mask that's 0 for all non trap bits and the trap bit for
        trap bits.
        Assumes noise and positions are chunk-wise """
        pos_mask = BitArray().join(
            [Bits([False] * (chunk_size - 1) + [True]) << (chunk_size - pos - 1) \
            for pos in positions])
        if len(noise) > 1:
            noise = BitArray().join(noise)
        return pos_mask & noise

class InversionChecker(InversionBase):
    def check(self, cell, fast=True):
        """ Checks that the trap bit in each chunk in cipherchunks is correct.
            Precondition: noise_state and position_state should be in the
            initial state for the cell to be checked.

          inputs:
            cell (Bits list): The chunks output of encode
            output: True if it all matches, False otherwise.
        """
        cell = Bits(uint=bytes_to_long(cell), length=cell_bit_length)
        cipherchunks = bits_to_chunks(cell)
        if (len(cipherchunks) < 1):
            print("Warning: Attempt to check empty ciphertext")
            return True
        [noise] = self.trap_noise(1, "Chunks")
        positions = self.trap_positions(len(cipherchunks))
        assert(len(cipherchunks) == len(noise) == len(positions)), \
            "Cipherchunks len: {0} Noise len: {1}. pos len: {2}"\
            .format(len(cipherchunks), len(noise), len(positions))
        mask = self.cell_trap_mask(noise, positions)
        return mask & cell == mask

class InversionEncoder(InversionBase):
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
        assert self.encoded_size(len(cell)) <= cell_bit_length // 8, \
               "encoded size for {0} byte cell is {1} but only {2} will fit" \
               .format(len(cell), self.encoded_size(len(cell)), max_in_size)
        chunks = bits_to_chunks(Bits(cell), padchunks=True, padcell=True)
        assert(len(chunks) >= 1)
        [noise] = self.trap_noise(1, "Chunks")
        positions = self.trap_positions(len(chunks) + invert_header_size)
        header_chunks, enc = self.__encode_chunks(noise, positions, chunks)
        joined = self.__join_encoded(header_chunks, enc)
        masked = self.__trap_mask_cell(noise, positions, joined)
        debug(2, "Length: {0}\n"
                  .format(len(cell) * 8) + \
              "\n  Cell: {0}\n"
                      .format(Bits(cell)) + \
              "\n joined: {0}\n masked: {1}".format(Bits(joined), Bits(masked)))
        return masked

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
        chunks = math.ceil(8 * size / chunk_size)
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
        assert(len(chunks) == len(positions) == len(noise)), \
            "Lengths mismatch: Chunks: {0} Positions: {1} noise: {2}" \
            .format(len(chunks), len(positions), len(noise))
        for i in range(len(chunks)):
            debug(4, "i: {0}. chunk: {1}. Position: {2}. noise: {3}."
                  .format(i, chunks[i], positions[i], noise[i]))
            if chunks[i][positions[i]] == noise[i][positions[i]]:
                new_chunks += [chunks[i]]
                new_header += [False]
            else:
                new_chunks += [~chunks[i]]
                new_header += [True]
            debug(3, "Encoded chunk {0} which was {1} as {2} to avoid {3} of {4}."
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

    def __join_encoded(self, header_chunks, data_chunks):
        header = BitArray().join(header_chunks)
        inv_h = Bits(header + [False] * \
                              math.ceil(invert_header_size * 8 - len(header)))
        inv_B = inv_h.tobytes()
        enc_b = BitArray().join(data_chunks)
        enc_B = enc_b.tobytes()
        assert(len(inv_B + enc_B) > 1)
        debug(3, " Chunks: {0}.\n Invert Header: {1}."
                  .format(bits_to_chunks(Bits(inv_B + enc_B)), Bits(header)) + \
              "\n Full header: {0}\n enc: {1}\n Together: {2}"
                      .format(inv_h + data_chunks[:invert_header_size],
                              data_chunks, Bits(inv_B + enc_B)))
        return inv_B + enc_B

    def __trap_mask_cell(self, noise, positions, joined):
        noise = BitArray().join(noise)
        return (noise ^ Bits(joined)).tobytes()

class InversionDecoder:
    def decode(self, cell):
        """ Takes the output of encode and returns it decoded (in bytes).
        """
        cipherheader, cipherchunks = encoded_bytes_to_header_chunks(cell)
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
    header_chunks = bits_to_chunks(Bits(cell)[:invert_header_chunks * chunk_size])
    offset = invert_header_size
    # Decode the inversion bits
    header_decoded_chunks = []
    for i in range(len(header_chunks)):
        # Remove the prepended bits from encode
        header_decoded_chunks.append(header_chunks[i][1:])
        if header_chunks[i][0] == 1:
            # Flip chunks of inversion bits if needed
            header_decoded_chunks[-1] = ~header_decoded_chunks[-1]
    # De-chunk so the inversion bits are a single bitstring
    header = BitArray().join(header_decoded_chunks)
    cipherchunks = bits_to_chunks(Bits(cell[offset:]))
    # Trim any extra inversion header bits
    cipherheader = Bits(header[:len(cipherchunks)])
    debug(3, "Full initial header was: {0}".format(Bits(cell[:offset])) + \
          "\n header_chunks: {0}".format(header_chunks) + \
          "\n header_decoded_chunks: {0}".format(header_decoded_chunks) + \
          "\n invert header: {0}.".format(header) + \
          "\n cipherheader: {0}".format(cipherheader) + \
          "\n len cipherheader {0}".format(len(cipherheader)) + \
          "\n cipherchunks {0}".format(cipherchunks) + \
          "\n len cipherchunks: {0}.".format(len(cipherchunks)) + \
          "\n Original was: {0}".format(Bits(cell)) + \
          "\n length bin: {0}".format(Bits(cell[invert_header_size:offset])))
    return cipherheader, cipherchunks


###### Tests ######

class Test(unittest.TestCase):
    def setUp(self):
        self.c = InversionChecker([1, 2])
        self.decode_helper = InversionBase([1, 2])
        self.e = InversionEncoder([1, 2])
        self.d = InversionDecoder()

    def test_correctness(self):
        for i in range(10):
            debug(2, "Getting random string...")
            random.seed()
            to_test = self.rand_string(random.randint(1, max_in_size))
            debug(2, "Testing encoding/decoding {0} of 10".format(i))
            self.encode_check_decode(to_test)
        debug(1, "[+] Passed correctness")

    def encode_check_decode(self, message="", msg_b=None):
        if msg_b == None:
            msg_b = bytes(message, "utf-8")
        size = len(msg_b)
        encoded = Bits(self.e.encode(msg_b))
        noise = Bits(self.decode_helper.trap_noise(1)[0])
        debug(2, "Encoded: {0}-len {1}\n  noise: {2}-len {3}"
              .format(len(encoded), encoded, len(noise), noise))
        to_decode = encoded ^ noise
        debug(2, "Encoded: {0}-len {1}\n  noise: {2}-len {3}\n to_decode: {4}"
              .format(len(encoded), encoded, len(noise),
                      noise, to_decode))
        new_text_b = self.d.decode(to_decode.tobytes())
        self.assertEqual(new_text_b[:size], msg_b,
                         msg="[x] Failed decoding:\n Expected {0}\n but got {1}"
                              .format(msg_b, new_text_b))
        self.assertTrue(self.c.check(to_decode.tobytes()),
                        msg="[x] Failed checking: Problem with trap bits for {0}"
                        .format(msg_b))
        self.size_reporting(encoded.tobytes(), msg_b)
        debug(1, "[+] Passed encode/check/decode for {0}".format(msg_b))

    def size_reporting(self, encoded, decoded):
        self.assertEqual(self.e.encoded_size(len(decoded)), len(encoded),
            msg="[x] Failed encoded size for {2}:\n Expected {0}, got {1}"
                  .format(len(encoded),
                          self.e.encoded_size(len(decoded)), decoded))
        self.assertGreaterEqual(self.e.decoded_size(len(encoded)), len(decoded),
            msg="[x] Failed decoded size for {2}:\n Expected {0}, got {1}"
                  .format(len(decoded),
                          self.e.decoded_size(len(encoded)), decoded))

    def rand_string(self, length=5):
        chars = list(string.ascii_uppercase + string.digits)
        ret = []
        for _ in range(length):
            ret += [random.choice(chars)]
        return ''.join(ret)

if __name__ == '__main__':
    unittest.main()
