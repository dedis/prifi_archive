import socket
import asyncio
import struct

class MulticastReaderProtocol(asyncio.StreamReaderProtocol):
    def datagram_received(self, data, addr):
        self._stream_reader.feed_data(data)

    def error_received(self, exc):
        self._stream_reader.set_exception(exc)

class MulticastReader(asyncio.StreamReader):
    def __init__(self, loop, group, port):
        # Set up the multicast socket
        addrinfo = socket.getaddrinfo(group, None)[0]
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((group, port))
        group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        if addrinfo[0] == socket.AF_INET: # IPv4
            mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            mreq = group_bin + struct.pack('@I', 0)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

        # Start reading
        super().__init__(loop=loop)
        loop._make_datagram_transport(sock,
                                      MulticastReaderProtocol(self, loop=loop))

    def readexactly(self, n):
        return self.read(n)

class MulticastWriter(asyncio.StreamWriter):
    def __init__(self, loop, group, port):
        # Set up the multicast socket
        self.dst = (group, port)
        addrinfo = socket.getaddrinfo(group, None)[0]
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl_bin = struct.pack('@i', 0)
        if addrinfo[0] == socket.AF_INET:  # IPv4
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        else:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS)
        sock.setblocking(False)

        # Set up StreamWriter part
        reader = asyncio.StreamReader(loop=loop)
        protocol = MulticastReaderProtocol(reader, loop=loop)
        transport = loop._make_datagram_transport(sock, protocol)
        super().__init__(transport, protocol, None, loop)

    def write(self, data):
        self._transport.sendto(data, self.dst)
