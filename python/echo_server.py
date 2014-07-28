import argparse
import asyncio

def handle_client(reader, writer):
    data = yield from reader.read(256)
    while data:
        print("ECHO: {}".format(data.decode("utf-8")))
        writer.write(data)
        data = yield from reader.read(256)
    writer.close()


def main():
    p = argparse.ArgumentParser(description="A simple echo server")
    p.add_argument("-p", "--port", type=int, metavar="port", default=12345, dest="port")
    opts = p.parse_args()

    loop = asyncio.get_event_loop()
    server = asyncio.start_server(handle_client, host=None,
            port=opts.port, backlog=1024)
    try:
        loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.close()


if __name__ == "__main__":
    main()
