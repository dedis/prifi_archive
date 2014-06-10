# Analysis

## Goals
The purpose of trap encoding is to make the text in the current slot owner's
slot satisfy the following properties:

1. The owner of slot o can reliabably produce a message that accomodates the slot
    o trap bits
2. The relay(s), upon acquiring the clients' DC-net ciphertexts from all clients
    online in this interval for slot o AND the trustees' DC-net ciphertexts for
    a given slot o, can decode the trap-encoded contents of slot o.
3. With high probability, a client other than the owner of slot o will not be
    able to produce a message that accomodates the slot o trap bits.

## Overview of Trap Encoding Schemes
To this end, we propose a scheme where a background cipherstream for slot o,
generated from the shared secrets between each trustee and the owner of slot o
combined with well-known session identifiers, is used to check trap bits.

Trap bit positions are generated from the same information as well as some
differentiator.
The client who owns slot o should generate the next trap bit
position and encode the next chunk of her output so that the bit at that
position is the same as the corresponding bit of the background stream. For this
scheme to work, the following additional property must be satisfied:

* Lemma 1: The trap-encoded output should reveal no information about the
     position of the trap bits.

## Argument
We argue that any scheme fulfilling these requirements fulfills the 3 goals
listed above.

### 1. The owner can encode messages
The first property is easily satisfied: The background stream and the trap
bit positions are both functions of the shared secrets between the slot owner
and each trustee, and well known information including the session ID and the
slot number.

### 2. The relay can decode messages
TODO

### 3. Disruptors cannot easily forge messages
We assume the applicability of the lemma above, which will be proven in the
next section. Assuming every bit has an equal probability of being the trap bit,
a disruptor attempting to transmit a message in a slot owned by a different
client has a 1/`b` chance of flipping a trap bit per bit she flips in a `b`-bit
chunk.
To successfully transmit a disrupted `d` bit message, the disruptor must
therefore either guess all of the shared trap secrets (with probability 1/(`m`
times `k`), for `m` trustees and `k`-bit secrets), or guess the position of the
trap bit in each block she intends to flip (with probability (1/`b`)^(`d`/`b`)).
An adequate trap encoding scheme must therefore have

```
b^(d/b) = m*k.
```

And any scheme satisfying this will be as hard to forge as guessing keys.
