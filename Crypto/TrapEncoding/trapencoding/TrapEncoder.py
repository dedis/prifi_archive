from abc import ABCMeta, abstractmethod

class TrapEncoder:
    """ Interface for classes that take data and encode them around trap bits.

    Attributes:
      chunk_size (int): The number of bits per chunk to have in the output.
        Note that this must be equal to the size of the chunks yielded by
        background_stream.
      background_stream (BitArray generator): A generator function that yields
        the next block of the background cipherstream
      trap_bit_gen (int generator): A generator function that yields the
        position of the trap bit in the next block.
      background (list of BitArrays): The background stream chunks that
        this encoder has already used (needed for verification)
      trap_bits (list of int): The trap bits that correspond to blocks this
        encoder has already used (needed for verification)

    Subclasses should implement encode_chunks and decode_chunks.

    """
    __metaclass__ = ABCMeta

    def __init__(self, chunk_size, trap_bit_gen, background_stream):
        """ Initializes all attributes to specified or empty values """
        self.chunk_size = chunk_size
        self.trap_bit_gen = lambda:(yield trap_bit_gen.randint(0, chunk_size - 1))
        self.background_stream = lambda:(yield trap_bit_gen.getrandombits(chunk_size))
        self.trap_bits = []
        self.background = []

    @abstractmethod
    def encode(self, input_text):
        """ Takes plaintext to encode and returns a tuple (index, header,
        chunks), where index is the index of the first chunk of the background
        cipherstream used in encoding this text, and chunks is list of Bits
        objects
            encoding the plaintext
            """
        return

    @abstractmethod
    def decode(self, cipherheader, cipherchunks):
        """ Takes a list of Bits objects (cipherchunks) and their corresponding
            header bits indicating whether they should be flipped (cipherheader)
            and returns the plaintext.
            """
        return

    def verify(self, output_chunks, index):
        """ Checks output_chunks against self.background and self.trap_bits,
            starting at index, to make sure none of the trap bits are flipped.
            True if all trap bits are correct, false otherwise.
            """
        rounds = 0
        finger = index
        for chunk in output_chunks:
            rounds += 1
            back_chunk = self.background[finger]
            this_bit = self.trap_bits[finger]
            if back_chunk[this_bit] != chunk[this_bit]:
                print("Mismatch on chunk {0} at {1}:"
                      .format(rounds, this_bit))
                print("Got {0}({1}), expected {2}({3})"
                      .format(chunk, chunk[this_bit],
                              back_chunk, back_chunk[this_bit]))
                return False
            else:
                finger += 1
        return True
