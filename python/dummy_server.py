import argparse
from asyncio import coroutine

@coroutine
def asyncio_handle(client_reader, client_writer):
    # read and ignore a simple HTTP request
    # XXX make more robust to actual protocol
    req = yield from client_reader.readline()
    while req != b'\r\n':
        req = yield from client_reader.readline()

    client_writer.write(response)
    client_writer.write_eof()
    client_writer.close()

def asyncio_main(opts):
    import asyncio

    loop = asyncio.get_event_loop()
    server = asyncio.start_server(asyncio_handle, host=None,
            port=opts.port, backlog=1024)
    try:
        loop.run_until_complete(server)
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.close()


def threaded_handle(conn, addr):
    connfile = conn.makefile("rb")
    req = connfile.readline()
    while req != b'\r\n':
        req = connfile.readline()
    connfile.close()

    conn.sendall(response)
    conn.close()

def threaded_main(opts):
    import socket
    import threading

    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("0.0.0.0", opts.port))
    ssock.listen(1024)
    try:
        while True:
            handler = threading.Thread(target=threaded_handle, args=ssock.accept())
            handler.daemon = True
            handler.start()
    except KeyboardInterrupt:
        pass
    ssock.close()


if __name__=='__main__':
    global response
    with open("/dev/urandom", "rb") as f:
        response = f.read(1 << 20)

    p = argparse.ArgumentParser(description="A dummy HTTP-like server")
    p.add_argument("-p", "--port", type=int, metavar="port", default=12345, dest="port")
    p.add_argument("--threads", action="store_true", default=False, dest="threads")
    p.add_argument("--asyncio", action="store_false", default=True, dest="threads")
    opts = p.parse_args()

    print("Starting {} server on port {}".format("threaded" if opts.threads
            else "asyncio", opts.port))
    if opts.threads:
        threaded_main(opts)
    else:
        asyncio_main(opts)

