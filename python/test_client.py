import argparse
import asyncio
import socks5
import time
from Crypto.Util.number import bytes_to_long, long_to_bytes

@asyncio.coroutine
def test_client(i, dest, port, socks):
    reader, writer = yield from asyncio.open_connection(dest, port)

    if socks:
        connect = socks5.VERSION + b'\x01' + socks5.METH_NO_AUTH
        writer.write(connect)

        ver_meth = yield from reader.readexactly(2)
        assert ver_meth == socks5.VERSION + socks5.METH_NO_AUTH

        addr = "www.google.com".encode("UTF-8")
        request = (socks5.VERSION + socks5.CMD_CONNECT + b'\x00' +
                socks5.ADDR_DOMAIN + long_to_bytes(len(addr)) + addr +
                long_to_bytes(80, 2))
        writer.write(request)

        ver_rep_res = yield from reader.readexactly(3)
        assert ver_rep_res == socks5.VERSION + socks5.REP_SUCCEEDED + b'\x00'

        atyp = yield from reader.readexactly(1)
        addr = yield from socks5.read_socks_addr(reader, atyp)
        port = yield from reader.readexactly(2)
    
    payload = 'GET / HTTP/1.0\r\n\r\n'.encode("UTF-8")
    writer.write(payload)

    total, start = 0, time.time()
    data = yield from reader.read(256)
    while data:
        total += len(data)
        data = yield from reader.read(256)
    writer.close()
    duration = time.time() - start
    return total, duration

def main():
    p = argparse.ArgumentParser(description="SOCKS5 client for benchmarking")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=256, dest="nclients")
    p.add_argument("dest", type=str, metavar="destination")
    p.add_argument("port", type=int, metavar="port")
    p.add_argument("--socks", action="store_true", default=True, dest="socks")
    p.add_argument("--no-socks", action="store_false", default=False, dest="socks")
    opts = p.parse_args()

    loop = asyncio.get_event_loop()
    clients = asyncio.gather(*(asyncio.async(test_client(i, opts.dest, opts.port,
            opts.socks)) for i in range(opts.nclients)))
    try:
        loop.run_until_complete(clients)
        throughput = [8 * t / d for t, d in clients.result()] 
        total, latency = zip(*clients.result())
        print("{} clients:".format(opts.nclients))
        print("\tthroughput: {} {} {}".format(min(throughput), max(throughput), sum(throughput) / opts.nclients))
        print("\tlatency: {} {} {}".format(min(latency), max(latency), sum(latency) / opts.nclients))
    except KeyboardInterrupt:
        pass


if __name__=='__main__':
    main()

