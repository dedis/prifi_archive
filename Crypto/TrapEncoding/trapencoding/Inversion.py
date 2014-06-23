from trapencoding.TrapEncoder import TrapEncoder
from bitstring import Bits, BitArray

class InversionEncoder(TrapEncoder):

    def encode(self, input_text):
        index = len(self.trap_bits)
        chunks = self.chunk(Bits(bytes(input_text, "utf_8")))
        head, cchunks = self.__encode_chunks(chunks)
        return index, head, cchunks

    def decode(self, cipherheader, cipherchunks):
        plain_chunks = self.__decode_chunks(cipherheader, cipherchunks)
        joined = BitArray().join(plain_chunks)
        bytes_joined = joined.tobytes()
        return bytes_joined.decode("utf-8")

    def __encode_chunks(self, chunks):
        """ Takes the chunked input and returns a list of encoded chunks.
            Updates self.background and self.trap_bits.

            The encoded chunks are either 0 followed by the Bits representation
            of a chunk
            or 1 followed by the bitwise negation of such a chunk.
            """
        new_chunks = []
        new_header = []
        for chunk in chunks:
            self.background += [next(self.background_stream())]
            self.trap_bits += [next(self.trap_bit_gen())]
            if chunk[self.trap_bits[-1]] == \
            self.background[-1][self.trap_bits[-1]]:
                new_chunks += [chunk]
                new_header += [0]
            else:
                new_chunks += [~chunk]
                new_header += [1]
        return (new_header, new_chunks)

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

    def chunk(self, in_bin):
        """ chunk_l (int): the chunk length in bits
            in_bin (Bits): the input message
        """
        chunk_l = self.chunk_size
        return [in_bin[i:i + chunk_l] for i in range(0, len(in_bin), chunk_l)]
