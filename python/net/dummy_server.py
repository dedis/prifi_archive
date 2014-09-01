import argparse
import asyncio
import logging
import socket
import threading

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class DummyServer:
    def __init__(self, payload, host=None, port=12345):
        self.payload = payload
        self.host = host
        self.port = port


class AsyncioDummyServer(DummyServer):
    def __init__(self, payload, host=None, port=12345):
        DummyServer.__init__(self, payload, host, port)
        self.loop = asyncio.get_event_loop()

    @asyncio.coroutine
    def handle_client(self, reader, writer):
        # read and ignore a simple HTTP request
        # assumes Content-Length: 0
        req = yield from reader.readline()
        while req != b'\r\n':
            req = yield from reader.readline()

        writer.write(self.payload)
        writer.write_eof()
        writer.close()

    def run(self):
        self.server = asyncio.start_server(self.handle_client, host=self.host,
                port=self.port, backlog=1024)
        self.loop.run_until_complete(self.server)
        self.loop.run_forever()

    def close(self):
        self.server.close()


class ThreadedDummyServer(DummyServer):
    def __init__(self, payload, host=None, port=12345):
        DummyServer.__init__(self, payload, host, port)
        if self.host is None:
            self.host = '0.0.0.0'

    def handle_client(self, conn, addr):
        connfile = conn.makefile("rb")
        req = connfile.readline()
        while req != b'\r\n':
            req = connfile.readline()
        connfile.close()

        conn.sendall(self.payload)
        conn.close()

    def run(self):
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssock.bind((self.host, self.port))
        self.ssock.listen(1024)
        while True:
            handler = threading.Thread(target=self.handle_client,
                    args=self.ssock.accept())
            handler.daemon = True
            handler.start()

    def close(self):
        self.ssock.close()


if __name__=='__main__':
    logging.basicConfig()
    logger.setLevel(logging.INFO)

    p = argparse.ArgumentParser(description="A dummy HTTP-like server")
    p.add_argument("-p", "--port", type=int, metavar="port", default=12345,
            dest="port")
    p.add_argument("-c", "--bytes", type=int, metavar="bytes", default=1024,
            dest="bytes")
    p.add_argument("--threads", action="store_true", default=False,
            dest="threads")
    p.add_argument("--asyncio", action="store_false", default=True,
            dest="threads")
    opts = p.parse_args()

    with open("/dev/urandom", "rb") as f:
        payload = f.read(opts.bytes)

    if opts.threads:
        server_class = ThreadedDummyServer
    else:
        server_class = AsyncioDummyServer
    server = server_class(payload, port=opts.port)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    server.close()

