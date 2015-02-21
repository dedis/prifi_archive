import argparse
import asyncio
import random
import socks5
import time
import os
from Crypto.Util.number import bytes_to_long, long_to_bytes

@asyncio.coroutine
def test_client(i, dest, host, port, socks):
    yield from asyncio.sleep(random.random())

    start = time.time()
    reader, writer = yield from asyncio.open_connection(host, port)

    if socks:
        connect = socks5.VERSION + b'\x01' + socks5.METH_NO_AUTH
        writer.write(connect)

        ver_meth = yield from reader.readexactly(2)
        assert ver_meth == socks5.VERSION + socks5.METH_NO_AUTH

        addr =dest.encode("UTF-8")
        request = (socks5.VERSION + socks5.CMD_CONNECT + b'\x00' +
                socks5.ADDR_DOMAIN + long_to_bytes(len(addr)) + addr +
                long_to_bytes(8080, 2))
        writer.write(request)

        ver_rep_res = yield from reader.readexactly(3)
        assert ver_rep_res == socks5.VERSION + socks5.REP_SUCCEEDED + b'\x00'

        atyp = yield from reader.readexactly(1)
        addr = yield from socks5.read_addr(reader, atyp)
        port = yield from reader.readexactly(2)

    payload = 'GET / HTTP/1.0\r\n\r\n'.encode("UTF-8")
    writer.write(payload)

    total = 0
    data = yield from reader.read(256)
    while data:
        total += len(data)
        data = yield from reader.read(256)
    writer.close()
    duration = time.time() - start
    return total, duration

def main():
    p = argparse.ArgumentParser(description="SOCKS5 client for benchmarking")
    p.add_argument("-c", "--connections", type=int, metavar="conns",
                   default=256, dest="nconns")
    p.add_argument("--host", type=str, metavar="client host",
            default="localhost")
    p.add_argument("port", type=int, metavar="client port")
    p.add_argument("--dest", type=str, metavar="server to request",
                   default="remote")
    p.add_argument("--socks", action="store_true", default=True, dest="socks")
    p.add_argument("--no-socks", action="store_false", default=False, dest="socks")
    opts = p.parse_args()

    loop = asyncio.get_event_loop()
    conns = asyncio.gather(*(asyncio.async(test_client(i, opts.dest, opts.host,
          opts.port, opts.socks)) for i in range(opts.nconns)))
    try:
        loop.run_until_complete(conns)
        throughput = [t / d for t, d in conns.result()]
        latency = [d for t, d in conns.result()]
        total = [t for t, d in conns.result()]
        print("{} clients: {} bytes, {} bytes/sec, {}s latency"
              .format(opts.nconns, sum(total) / opts.nconns,
                      sum(throughput) / opts.nconns, sum(latency) / opts.nconns))
    except KeyboardInterrupt:
        pass


if __name__=='__main__':
    main()

