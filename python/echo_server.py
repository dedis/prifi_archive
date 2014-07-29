import argparse
import asyncio
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class EchoServer:
    def __init__(self, host=None, port=12345):
        self.host = host
        self.port = port
        self.loop = asyncio.get_event_loop()

    @asyncio.coroutine
    def handle_client(self, reader, writer):
        totbytes = 0
        data = yield from reader.read(256)
        while data:
            writer.write(data)
            totbytes += len(data)
            data = yield from reader.read(256)
        writer.close()
        logger.info("echo: {} bytes".format(totbytes))

    def run(self):
        self.server = asyncio.start_server(self.handle_client, host=self.host,
                port=self.port, backlog=1024)
        logger.info("EchoServer listening on {}".format(self.port))
        self.loop.run_until_complete(self.server)
        self.loop.run_forever()

    def close(self):
        self.server.close()


if __name__ == "__main__":
    logging.basicConfig()
    logger.setLevel(logging.INFO)

    p = argparse.ArgumentParser(description="A simple asyncio echo server")
    p.add_argument("-p", "--port", type=int, metavar="port", default=12345,
            dest="port")
    opts = p.parse_args()

    server = EchoServer(port=opts.port)
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    server.close()
