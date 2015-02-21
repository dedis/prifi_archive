import argparse
import asyncio
import socket
import logging

from Crypto.Util.number import bytes_to_long, long_to_bytes

from utils import verbosity

logger = logging.getLogger(__file__.rpartition('/')[2])
logger.addHandler(logging.NullHandler())

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
def read_addr(reader, atyp):
    if atyp == ADDR_IPv4:
        addr = yield from reader.readexactly(4)
        return socket.inet_ntop(socket.AF_INET, addr)
    elif atyp == ADDR_DOMAIN:
        addr_len = yield from reader.readexactly(1)
        addr_len = bytes_to_long(addr_len)
        addr = yield from reader.readexactly(addr_len)
        return addr.decode("utf-8")
    elif atyp == ADDR_IPv6:
        addr = yield from reader.readexactly(16)
        return socket.inet_ntop(socket.AF_INET6, addr)
    else:
        return None

def make_reply(err=None, addr=None):
    rep = REP_SUCCEEDED if err is None else REP_GENERAL_FAILURE
    if addr is not None:
        try:
            atyp = ADDR_IPv4
            ip, port = addr
            addr = socket.inet_pton(socket.AF_INET, ip)
            addr += long_to_bytes(port, 2)
        except:
            try:
                atyp = ADDR_IPv6
                ip, port, flow_info, scope_id = addr
                addr = socket.inet_pton(socket.AF_INET6, ip)
                addr += long_to_bytes(port, 2)
            except:
                atyp = ADDR_IPv4
                addr = bytearray(6)
                rep = REP_ADDR_TYPE_NOT_SUPPORTED
    else:
        atyp = ADDR_IPv4
        addr = bytearray(6)
    return VERSION + rep + b'\x00' + atyp + addr


class Socks5Server:
    def __init__(self, loop=None, host=None, port=8080):
        self.loop = loop if loop is not None else asyncio.get_event_loop()
        self.host = host
        self.port = port

    @asyncio.coroutine
    def _forward(self, reader, writer):
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
        logger.info("Forwarded %d bytes", total)

    @asyncio.coroutine
    def _handle_client(self, reader, writer):
        # only support version 5 and NoAuth for now
        ver = yield from reader.readexactly(1)
        nmethods = yield from reader.readexactly(1)
        if ver != VERSION:
            ver = bytes_to_long(ver)
            logger.warn("SocksVersionNotSupported: %02x", ver)
            return
        nmethods = bytes_to_long(nmethods)
        methods = yield from reader.readexactly(nmethods)
        for meth in map(long_to_bytes, methods):
            if meth == METH_NO_AUTH:
                break
        else:
            logger.warn("AuthenticationMethodNotSupported")
            writer.write(VERSION + METH_NONE)
            return

        # continue using NoAuth
        writer.write(VERSION + METH_NO_AUTH)

        ver = yield from reader.readexactly(1)
        cmd = yield from reader.readexactly(1)
        rsv = yield from reader.readexactly(1)
        atyp = yield from reader.readexactly(1)

        up_addr = yield from read_addr(reader, atyp)
        up_port = yield from reader.readexactly(2)
        up_port = bytes_to_long(up_port)

        if cmd == CMD_CONNECT:
            try:
                up_reader, up_writer = (yield from
                        asyncio.open_connection(up_addr, up_port,
                        loop=self.loop))
            except:
                logger.warn("GeneralFailure: %s:%d", up_addr, up_port)
                writer.write(make_reply(err=REP_GENERAL_FAILURE))
                writer.close()
                return

            logger.info("New connection %s:%d", up_addr, up_port)
            sockname = writer.transport.get_extra_info('sockname')
            writer.write(make_reply(addr=sockname))

            # start forwarding streams in both directions
            asyncio.async(self._forward(reader, up_writer), loop=self.loop)
            asyncio.async(self._forward(up_reader, writer), loop=self.loop)

        else:
            cmd = bytes_to_long(cmd)
            logger.warn("CommandNotSupported: %02x".format(cmd))
            writer.write(make_reply(err=REP_COMMAND_NOT_SUPPORTED))
            writer.close()
            return

    def run(self):
        self.server = asyncio.start_server(self._handle_client,
                host=self.host, port=self.port, loop=self.loop)
        logger.info("SOCKS5 server listening on %d", self.port)
        self.loop.run_until_complete(self.server)
        self.loop.run_forever()

    def close(self):
        self.server.close()


if __name__=='__main__':
    logging.basicConfig()

    p = argparse.ArgumentParser(description="A SOCKS5 server")
    p.add_argument("-p", "--port", type=int, metavar="port",
            default=8080, dest="port")
    p.add_argument("-v", "--verbosity", type=str, choices=verbosity.keys(),
                   default="WARN", dest="verbose")
    opts = p.parse_args()
    logger.setLevel(verbosity[opts.verbose])

    server = Socks5Server(port=opts.port)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    server.close()
