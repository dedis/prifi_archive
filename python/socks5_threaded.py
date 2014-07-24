import socket
import threading
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
CMD_BIND = b'\x01'
CMD_ASSOCIATE = b'\x01'

REP_SUCCEEDED = b'\x00'
REP_GENERAL_FAILURE = b'\x01'
REP_CONNECTION_NOT_ALLOWED = b'\x02'
REP_NETWORK_UNREACHABLE = b'\x03'
REP_HOST_UNREACHABLE = b'\x04'
REP_CONNECTION_REFUSED = b'\x05'
REP_TTL_EXPIRED = b'\x06'
REP_COMMAND_NOT_SUPPORTED = b'\x07'
REP_ADDR_TYPE_NOT_SUPPORTED = b'\x08'


def read_socks_addr(conn, atyp):
    if atyp == ADDR_IPv4:
        return socket.inet_ntop(socket.AF_INET, conn.recv(4, socket.MSG_WAITALL))
    elif atyp == ADDR_DOMAIN:
        addr_len = bytes_to_long(conn.recv(1))
        return conn.recv(addr_len, socket.MSG_WAITALL).decode("UTF-8")
    elif atyp == ADDR_IPv6:
        return socket.inet_ntop(socket.AF_INET6, conn.recv(16, socket.MSG_WAITALL))
    else:
        return None


def socks_reply(err=None, addr=None):
    rep = REP_SUCCEEDED if err is None else REP_GENERAL_FAILURE
    if addr is not None:
        ip, port = addr
        try:
            atyp = ADDR_IPv4
            addr = socket.inet_pton(socket.AF_INET, ip) + long_to_bytes(port, 2)
        except:
            atyp = ADDR_IPv4
            addr = bytearray(6)
            rep = REP_ADDR_TYPE_NOT_SUPPORTED
    else:
        atyp = ADDR_IPv4
        addr = bytearray(6)
    return VERSION + rep + b'\x00' + atyp + addr


def socks_forward(src, dst):
    buf, total = bytearray(256), 0
    try:
        n = src.recv_into(buf)
        while n > 0:
            total += n
            dst.sendall(buf[:n])
            n = src.recv_into(buf)
        dst.shutdown(socket.SHUT_RDWR)
    except:
        pass
    src.close()
    dst.close()
    print("Forwarded {} bytes on connection".format(total))


def new_connection(conn, addr):
    # we only support version 5 and NoAuth for now
    ver, nmethods = conn.recv(1), conn.recv(1);
    if ver != VERSION:
        print("SocksVersionNotSupported: {}".format(ver))
        return
    nmethods = bytes_to_long(nmethods)
    methods = conn.recv(nmethods, socket.MSG_WAITALL);
    for meth in methods:
        if meth == bytes_to_long(METH_NO_AUTH):
            break
    else:
        print("AuthenticationMethodNotSupported")
        conn.sendall(VERSION + METH_NONE)
        return

    # continue using NoAuth
    conn.sendall(VERSION + METH_NO_AUTH)

    ver, cmd = conn.recv(1), conn.recv(1);
    rsv, atyp = conn.recv(1), conn.recv(1);

    upstream_addr = read_socks_addr(conn, atyp)
    upstream_port = bytes_to_long(conn.recv(2, socket.MSG_WAITALL))

    if cmd == CMD_CONNECT:
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((upstream_addr, upstream_port))
        except Exception as e:
            print("Unable to connect to upstream host")
            conn.sendall(socks_reply(err=REP_GENERAL_FAILURE))
            conn.close()
            return

        print("New connection to {}:{}".format(upstream_addr, upstream_port))
        conn.sendall(socks_reply(addr=conn.getsockname()))

        # start forwarding streams in both directions
        threading.Thread(target=socks_forward, args=(conn,upstream,)).start()
        threading.Thread(target=socks_forward, args=(upstream,conn,)).start()

    else:
        print("CommandNotSupported: {}".format(cmd))
        conn.sendall(socks_reply(err=REP_COMMAND_NOT_SUPPORTED))
        conn.close()


def main():
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(("0.0.0.0", 8080))
    ssock.listen(5)
    try:
        while True:
            handler = threading.Thread(target=new_connection, args=ssock.accept())
            handler.daemon = True
            handler.start()
    except KeyboardInterrupt:
        pass
    ssock.close()


if __name__=='__main__':
    main()
