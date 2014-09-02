""" The purpose of this module is to streamline header formats and make it
easier to change them.

To wrap a message with a header: Call pack with the message type code and the
header components as keyword args (other than length, which is calculated).

To decode a message with a header: Call unpack, which returns a dictionary.
Unpack detects the message type.

To modify this file to add a message type:
- Add a short code
- Add an entry to fields, with 'data' last if present, and the remaining
  elements sorted

To modify this file to change a header entry:
- Change fcodes, where fcodes['name'] is the struct format code
- Add it to any appropriate fields entries
"""

import struct
import dcnet
import asyncio

# Short codes to indicate the message type
NIL                = 0x00
RELAY_DOWNSTREAM   = 0x01
RELAY_TNEXT        = 0x02
CLIENT_UPSTREAM    = 0x03
CLIENT_ACK         = 0x04
CLIENT_CONNECT     = 0x05
TRUSTEE_CONNECT    = 0x06
AP_CONNECT         = 0x07
AP_DOWNSTREAM      = 0x08
AP_PING            = 0x09

#fields. Order doesn't matter.
fcodes = {'kind':'b', # The message type code
          'cno':'i',  # The connection number
          'nxt':'H',  # The next slot
          'blen':'H', # Length of the data field, computed in pack
          'mid':'i',  # Message ID
          'node':'b', # The node identification number
          'ap':'h',   # The access point index, if applicable (-1 if none)
          'rkind':'b',# The kind of the relay message being forwarded
          'data':''}  # Vairable length data. blen must be in fields if present.

# Dictionary mapping short codes to field names. Note the order.
fields = {NIL:               ('kind',),
          RELAY_DOWNSTREAM:  ('kind', 'blen', 'cno', 'nxt', 'data'),
          RELAY_TNEXT:       ('kind', 'nxt'),
          CLIENT_UPSTREAM:   ('kind', 'blen', 'cno', 'data'),
          CLIENT_ACK:        ('kind', 'mid'),
          CLIENT_CONNECT:    ('kind', 'ap', 'node'),
          TRUSTEE_CONNECT:   ('kind', 'node'),
          AP_CONNECT:        ('kind', 'node'),
          AP_DOWNSTREAM:     ('kind', 'blen', 'mid', 'data')}

#### The rest of this file should not need to change with field changes ####

# The format code of the header for each type
structs = dict((k, struct.Struct("".join([fcodes[f] for f in fields[k]])))\
            for k in fields)

sizes = dict((code, structs[code].size) for code in fields)
sizes[CLIENT_UPSTREAM] = dcnet.cell_length
overhead = dict((code, structs[code].size) for code in fields)

def pack(kind, data=None, **kwargs):
    """ message type-aware wrapper for struct.pack """
    if data != None:
        kwargs['blen'] = len(data)
        vals = [kwargs[k] for k in fields[kind][1:-1]]
        packed = structs[kind].pack(kind, *tuple(vals)) + data
        return packed.ljust(sizes[kind], b'\00')
    else:
        vals = [kwargs[k] for k in fields[kind][1:]]
        return structs[kind].pack(kind, *tuple(vals))

def unpack(buf, ret):
    kind = buf[0]
    hlen = overhead[kind]
    out = structs[kind].unpack(buf[:hlen])
    for k,v in zip(fields[kind],out):
        ret[k] = v
    try:
        ret['data'] = buf[hlen:hlen + ret['blen']]
    except KeyError:
        pass
    except IndexError:
        # buffer was shorter than data. That's ok, just put everything in data.
        ret['data'] = buf[hlen:]

@asyncio.coroutine
def read_stream(reader):
    """ Use reader to read a message. Returns an unpacked dictionary. """
    kind = yield from reader.readexactly(1)
    try:
        head = yield from reader.readexactly(overhead[kind[0]] - 1)
    except KeyError:
        raise KeyError("Invalid message type {}".format(kind[0]))
    ret = {}
    unpack(kind + head, ret)
    try:
       ret['data'] = yield from reader.readexactly(ret['blen'])
    except KeyError:
       pass
    return ret
