import asyncio
import socket
from Crypto.Util.number import bytes_to_long, long_to_bytes

VERSION = b'\x05'

METH_NO_AUTH = b'\x00'
METH_GSS = b'\x01'
METH_USER_PASS = b'\x02'
METH_NONE = b'\xff'

ADDR_IPv4 = b'\x01'
ADDR_DOMAIN = b'\x03'
ADDR_IPv6 = b'\x04'

CMD_CONNECT = b'\x01'
CMD_BIND = b'\x02'
CMD_ASSOCIATE = b'\x03'

REP_SUCCEEDED = b'\x00'
REP_GENERAL_FAILURE = b'\x01'
REP_CONNECTION_NOT_ALLOWED = b'\x02'
REP_NETWORK_UNREACHABLE = b'\x03'
REP_HOST_UNREACHABLE = b'\x04'
REP_CONNECTION_REFUSED = b'\x05'
REP_TTL_EXPIRED = b'\x06'
REP_COMMAND_NOT_SUPPORTED = b'\x07'
REP_ADDR_TYPE_NOT_SUPPORTED = b'\x08'


@asyncio.coroutine
def read_socks_addr(client_reader, atyp):
    if atyp == ADDR_IPv4:
        addr = yield from client_reader.readexactly(4)
        return socket.inet_ntop(socket.AF_INET, addr)
    elif atyp == ADDR_DOMAIN:
        addr_len = yield from client_reader.readexactly(1)
        addr_len = bytes_to_long(addr_len)
        addr = yield from client_reader.readexactly(addr_len)
        return addr.decode("UTF-8")
    elif atyp == ADDR_IPv6:
        addr = yield from client_reader.readexactly(16)
        return socket.inet_ntop(socket.AF_INET6, addr)
    else:
        return None

def socks_reply(err=None, addr=None):
    rep = REP_SUCCEEDED if err is None else REP_GENERAL_FAILURE
    if addr is not None:
        try:
            atyp = ADDR_IPv4
            ip, port = addr
            addr = socket.inet_pton(socket.AF_INET, ip) + long_to_bytes(port, 2)
        except:
            try:
                atyp = ADDR_IPv6
                ip, port, flow_info, scope_id = addr
                addr = socket.inet_pton(socket.AF_INET6, ip) + long_to_bytes(port, 2)
            except:
                atyp = ADDR_IPv4
                addr = bytearray(6)
                rep = REP_ADDR_TYPE_NOT_SUPPORTED
    else:
        atyp = ADDR_IPv4
        addr = bytearray(6)
    return VERSION + rep + b'\x00' + atyp + addr


@asyncio.coroutine
def socks_forward(reader, writer):
    total = 0
    try:
        data = yield from reader.read(256)
        while data:
            total += len(data)
            yield from writer.drain()
            writer.write(data)
            data = yield from reader.read(256)
        writer.write_eof()
    except:
        pass
    writer.close()
    print("Forwarded {} bytes on connection".format(total))

@asyncio.coroutine
def socks_accept(client_reader, client_writer):
    # we only support version 5 and NoAuth for now
    ver = yield from client_reader.readexactly(1)
    nmethods = yield from client_reader.readexactly(1)
    if ver != VERSION:
        print("SocksVersionNotSupported: {}".format(ver))
        return
    nmethods = bytes_to_long(nmethods)
    methods = yield from client_reader.readexactly(nmethods)
    for meth in methods:
        if meth == bytes_to_long(METH_NO_AUTH):
            break
    else:
        print("AuthenticationMethodNotSupported")
        client_writer.write(VERSION + METH_NONE)
        return

    # continue using NoAuth
    client_writer.write(VERSION + METH_NO_AUTH)

    ver = yield from client_reader.readexactly(1)
    cmd = yield from client_reader.readexactly(1)
    rsv = yield from client_reader.readexactly(1)
    atyp = yield from client_reader.readexactly(1)

    upstream_addr = yield from read_socks_addr(client_reader, atyp)
    upstream_port = yield from client_reader.readexactly(2)
    upstream_port = bytes_to_long(upstream_port)

    if cmd == CMD_CONNECT:
        try:
            upstream_reader, upstream_writer = yield from asyncio.open_connection(upstream_addr, upstream_port)
        except:
            print("Unable to connect to upstream host")
            client_writer.write(socks_reply(err=REP_GENERAL_FAILURE))
            client_writer.close()
            return

        print("New connection to {}:{}".format(upstream_addr, upstream_port))
        sockname = client_writer.transport.get_extra_info('sockname')
        client_writer.write(socks_reply(addr=sockname))

        # start forwarding streams in both directions
        asyncio.async(socks_forward(client_reader, upstream_writer))
        asyncio.async(socks_forward(upstream_reader, client_writer))

    else:
        print("CommandNotSupported: {}".format(cmd))
        client_writer.write(socks_reply(err=REP_COMMAND_NOT_SUPPORTED))
        client_writer.close()


def main():
    loop = asyncio.get_event_loop()
    print("Starting asyncio SOCKS5 server on 8080")
    server = asyncio.start_server(socks_accept, host=None, port=8080)
    try:
        loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.close()


if __name__=='__main__':
    main()

