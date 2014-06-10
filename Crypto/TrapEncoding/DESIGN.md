Trap-encoding Design
====================
The owner of a scheduled DC-net cell trap-encodes the cell's cleartext data
before transmitting it anonymously via DC-nets.

Trap-encoding logically consists of the following abstract procedures:

- `TrapInit` (on trustees): At the start of a session (after the shuffle), each
    trustee runs TrapInit to form a Diffie-Hellman secret between itself and
    each anonymous slot-owner key that emerged from the shuffle.
- `TrapSched` (on trustees): During the setup stage for each interval, each
    trustee runs the TrapSetup procedure once for unique owner-key for whom one
    or more cells are scheduled during the interval.
- `TrapEncode` (on clients): the owner of a given cell (any client who holds the
    private key corresponding to the cell's public owner-key) can optionally run
    the TrapEncode procedure to transmit useful data in the cell's transmission
    slot.
- `TrapDecode` (on relay): once the relay collects the clients' DC-net
    ciphertexts for a given cell from each of the clients online in this
    interval, and combines them with the trustees' DC-net ciphertexts for that
    cell, the relay uses TrapDecode to extract the cell's cleartext content.
- `TrapCheck` (on trustees): after an interval has completed, the relay sends
    the trustees (perhaps in the background) a transcript of the results of all
    communication during the interval, and the trustees run TrapCheck on each
    cell to ensure that no trap-bits were flipped (indicating DC-nets
    disruption).

`TrapInit(SID,Kt,[K'o]) -> ([M])`
---
Runs on trustee after a shuffle, to compute shared secrets between trustees and
slot owners.

### inputs:
- `SID`: session ID of this session
- `Kt`: this trustee's well-known private key
- `[K'o]`: list of public owner-keys that came out of the shuffle.

### outputs:
- `SM`: a map from each `K'o` in the shuffle's output to a trap-encoding secret
    shared between trustee `t` and owner `o`
- `[Commits]`: a list of commitments to trap-encoding secrets, one for each
    owner `o` in the same order as shuffle output.

### pseudocode:
- For each `K'o` in the owner-keys in the shuffle output:
	- Use Diffie-Hellman to compute a shared master secret `Mo = K'o^Kt`
	- Compute `HMAC_Mo{SID,"TrapInit"}` to yield shared secret for trap-encoding
    - Use this hash to pick a pseudorandom secret suitable for the system's
        discrete-log group
	- Save this pseudorandom secret So in trustee's internal map `MT`, indexed
        by `K'o`
    - Compute commitment `g^So` and include that in outputs, to be published in
        session initiation info for accountability.

`TrapSched(SID,SM,Sched) -> ([Noise])`:
---
Runs on trustee at the beginning of each interval, just after scheduling, to
produce per-interval temporary trap secrets and trap-noise to be XORed into each
cell's payload.

### inputs:
- `SID`: session ID of this session
- `SM`: map of trap-encoding secrets indexed by `K'o`, produced in `TrapInit`
- `Sched`: the transmission schedule for the upcoming interval - a list of cells
    to be transmitted in this interval, including for each scheduled cell:
	- `Cell`: cell number, unique within the session identified by `SID`
    - `K'o`: public key of anonymous owner of this cell (who gets to transmit in
        this cell)
    - `Wordsize`: number of bits per codeword for this cell: a power of two from
        between 2 and 64.  (There will be one trap bit per codeword.)
    - `Length`: number of codewords comprising this cell.  (Total number of bits
        is length * wordsize.)

### outputs:
- `[Noise]`: a list of data buffers, one per cell, containing the trap-noise
    generated for each cell, to be XORed into trustee's DC-nets stream for cell.

### pseudocode:
- Find `FirstCell`, the cell number of first cell comprising this interval
    (simply the Cell number from the first cell in the transmission schedule).
- create initially empty map `RM`: `K -> R` mapping public owner-keys `K` to
    pseudorandom stream generators `R`
- for each cell descriptor `(Cell,K'o,Wordsize,Length)` in the transmission
    schedule Sched, in sequence:
	- If there have been previous cells owned by `K'o` in this interval, find
        existing pseudorandom stream `R <- RM[K'o]`.  If not:
        - Lookup `So`, the long-term owner/trustee shared trap-secret in `SM`
            shared with owner `K'o`
		- Choose pseudorandom well-known unique generator `h =
            H{SID,FirstCell,"TrapSched"}` for this interval
		- Compute `h^So`, the per-interval secret between this trustee t and
            owner `K'o`
		- Use `h^So` to seed a new pseudorandom stream generator `R`, and
            store `R` in `RM[K'o]` for reuse in future cells in this interval.
	- Pull `Length*Wordsize` bits from `R`, padded up to the next byte boundary,
        to form the `Noise` for this cell.

`TrapEncode(SID,[K't],SchedInfo,Payload) -> (EncodedPayload)`
---
Runs on client that owns next cell, whose scheduling info is `SchedInfo =
(Cell,K'o,Wordsize,Length)`.  Client owns private key Ko corresponding to `K'o`.

### inputs:
- `SID`: session ID
- `[K't]`: list of public keys of all trustees
- `SchedInfo`: scheduling info slot for this cell, a tuple of
    `(Cell,K'o,Wordsize,Length)`
- `Payload`: buffer containing `Wordsize*Length` bits of cleartext data to
    be trap-encoded

### outputs:
- `EncodedPayload`: trap-encoded payload for this cell to be XORed into DC-nets
    stream for this cell.

### pseudocode:
- For each trustee `t`:
	- if not already computed in this session:
		- use Diffie-Hellman to compute long-term shared secret `K't^Ko` between
            us (owner) and trustee `t`.  Memoize.
        - compute `HMAC_Mo{SID,"TrapInit"}` to yield per-session shared secret
            for trap-encoding.
        - from this compute the pseudorandom per-session shared secret `So`.
            Memoize for rest of session.
	- if not already computed in this interval:
		- compute the well-known pseudorandom generator `h =
            H{SID,FirstCell,"TrapSched"}` for this interval.
		- compute per-interval trap-secret shared with trustee `t`, `Tt = h^So`.
- if not already computed in this interval:
    - Compute composite trap-secret `T = H{T1,...,Tn}`, a hash of the
        per-interval trap-secrets shared with each trustee.
	- Use this composite trap-secret and `"Noise"` to seed a new pseudorandom
        stream generator `R`. Memoize for rest of interval.
    - Seed another pseudorandom stream generator `R'` with `T` and `"Trap"`.
        Memoize for rest of interval.
- pull `Length` bytes from `R` to form the `TrapMap` for this cell, one byte
    per payload codeword.
- pull `Length * Wordsize` from `R'` to form `Noise` for this cell.
- mask all but the low 1 through 5 bits in each `TrapMap` byte, to select which
    of the 2 through 64 bits of each codeword will be the trap bit.
- Initialize a `Header` of `Length` 0-bits
- for each `codeword`:
    - pull the next (`Wordsize`) bits from input `Payload`
	- compare the trap bit for payload `codeword` with corresponding trap bit in
        `Noise` codeword.  If NOT equal:
		- invert all `Wordsize` bits of this `codeword`.
        - set the corresponding bit of the `Header` to 1
	- Append this `codeword` to `EncodedPayload`.
- After all of `Payload` has been processed, output `Header` (padded to the
    nearest byte) prepended to
    `EncodedPayload`

`TrapDecode(Co,Wordsize,Length) -> (DecodedPayload)`:
---
Runs on relay once all ciphertext from clients and trustees has been collected
for this cell.

### inputs:
- `Co`: The encoded contents of this cell (owned by `o`). This is the result of
    xoring all clients' and trustees' ciphertext.
- `Wordsize`: The number of bits per chunk, where each chunk contains one trap
    bit
- `Length`: The number of chunks in this cell's payload

### outputs:
- `DecodedPayload`: The original payload for this cell (the `Payload` argument
    to `TrapEncode`)

### pseudocode:
- Separate out the first `Length` bits (padded to the nearest byte) and
    interpret as the `Header`.
- Allocate `Length*Wordsize` bits for `DecodedPayload` (padded to the nearest
    byte
- For each `Wordsize` bit `codeword` in the rest of `Co`:
    - If the corresponding bit in `Heaader` is 1, copy the bitwise negation of
        `codeword` to the next `Wordsize` bits of `DecodedPayload`
    - Otherwise, copy `codeword` to the next `Wordsize` bits of
        `DecodedPayload`.
- Output `DecodedPayload`.

`TrapCheck(SID,SM',[Cc],[Sched_o]) -> (ok, Other)`:
---
Runs on all trustees after the end of an interval, after all trap-encoding
secrets have been revealed

### inputs:
- `SID`: session ID
- `[To]'`: List of composite per-interval trap secrets for each slot owner `o`.
    `To` is `H{To1,...,Ton}`, where `Toj` is the per-interval trap encoding
    secret between `o` and trustee `j`.
- `[Cc]`: The encoded cleartext in each cell
- `[Sched_o]`: List of the scheduling information for each cell. Each list
    element is a tuple of `(Cell | K'o | Wordsize | Length)`.

### outputs:
- `ok`: a boolean indicating whether or not all trap bits were correct
- `Other`: Any other information necessary for starting the blame process
    (TODO)

### pseudocode:
- compute the well-known pseudorandom generator
    `h = H{SID, FirstCell, "TrapSched"}` for this interval
- For each cell `c` owned by slow-owner `o`:
    - If not already computed in this interval:
        - Use `To` and `"Noise`" to seed a new pseudorandom stream generator
            `Ro`. Memoize for the rest of the interval.
        - Use `To` and `"Trap`" to seed a new pseudorandom stream generator
            `Ro'`. Memoize for the rest of the interval.
    - Pull `Length` bytes from `Ro'` to form the `TrapMap` for this cell, as in
        `TrapEncode`, and mask similarly.
    - Pull `Length * Wordsize` bytes from `Ro` to form the `Noise` for this
        cell.
    - Ignore the `Header` bits of `Cc`. For each chunk of `Wordsize` bits in the
        rest of `Cc`:
        - Assert that the trap bit for this chunk is equal to the trap bit in
            the corresponding chunk of `Noise`. If not equal, set `ok` to
            false and/or enter `blame`.
- If all trap bits were correct, set `ok` to true
