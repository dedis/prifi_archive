import TrapEncoder
import TrapTests
from Crypto.Hash.SHA import SHA1Hash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
from bitstring import Bits, BitArray

class InversionEncoder(TrapEncoder.TrapEncoder):
    
    def __init__(self, trap_bit_gen, background_stream_gen, key,
                 hashAlg=SHA1Hash):
        """ Calls the parent constructor, and also creates the cipher to use
        
        key (_RSAobj) -- an RSA key for use in encoding/decoding. The output
          chunk_size is determined based on the length of the key.
        """
        super(InversionEncoder, self).__init__(key.size() + 1, trap_bit_gen,
                   background_stream_gen)
        self.key = key
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=hashAlg)
        # From the PKCS1_OAEP PyCrypto documentation: Input messages can be
        # no longer than the RSA modulus in bytes, minus 2, minus twice the
        # hash output size.
        self.input_chunks_size = 8 * \
            (int(key.size() / 8) - 2 - 2 * (hashAlg.digest_size))
    
    def encode(self, input_text):
        index = len(self.trap_bits)
        chunks = self.chunk(Bits(bytes(input_text, "utf_8")))
        return (index, self.__encode_chunks(chunks))
    
    def decode(self, cipherchunks, index):
        plain_chunks = self.__decode_chunks(cipherchunks)
        joined = BitArray().join(plain_chunks)
        bytes_joined = joined.tobytes()
        return bytes_joined.decode("utf-8")

    def __encode_chunks(self, chunks):
        """ Takes the chunked input and returns a list of encoded chunks.
            Updates self.background and self.trap_bits.
            
            The encoded chunks are either 0 followed by the Bits representation
            of a PKCS1_OAEP-encrypted chunk with length equal to the RSA key's,
            or 1 followed by the bitwise negation of such a chunk.
            """
        new_chunks = []
        for chunk in chunks:
            self.background += [next(self.background_stream())]
            self.trap_bits += [next(self.trap_bit_gen())]
            byte_chunk = chunk.tobytes()
            candidate = Bits(bin='0b0') + Bits(self.cipher.encrypt(byte_chunk))
            if candidate[self.trap_bits[-1]] == \
            self.background[-1][self.trap_bits[-1]]:
                new_chunks += [candidate]
            else:
                new_chunks += [~candidate]
        return new_chunks
    
    def __decode_chunks(self, chunks):
        """ Takes encoded input and returns the decoded chunks (i.e., the
            input to __encode_chunks).
            """
        plain_chunks = []
        for chunk in chunks:
            invert = chunk[0]
            to_decode = chunk[1:]
            if invert:
                to_decode = ~to_decode
            plain_chunks += [Bits(self.cipher.decrypt(to_decode.tobytes()))]
        return plain_chunks

    def chunk(self, in_bin):
        """ chunk_l (int): the chunk length in bits
            in_bin (Bits): the input message
        """
        chunk_l = self.input_chunks_size
        return [in_bin[i:i + chunk_l] for i in range(0, len(in_bin), chunk_l)]

if __name__ == '__main__':
    key = RSA.generate(1024)
    # Randomly choose a trap bit
    trap_bit_gen = lambda:(yield random.randint(0,1025))
    # Background stream is blocks of 1025 random bits
    back_gen = lambda:(yield BitArray()
    .join([Bits(random.getrandbits(1))] +\
          [Bits(random.getrandbits(8)) for i in range(128)]))
    IE = InversionEncoder(trap_bit_gen, back_gen, key)
    TrapTests.correctness(IE)
    TrapTests.vary_message_size(IE, 128, 16 * 1024)
    