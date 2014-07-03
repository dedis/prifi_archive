import select
import socket

def main():
    # listen for connections
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(("", 8080))
    ssock.listen(5)

    inputs = [ssock]
    outputs = []
    
    while True:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for r in readable:

            # new connection
            if r is ssock:
                sock, addr = ssock.accept()
                inputs.append(sock)

            # do the echo
            else:
                buf = bytearray(8)
                n = r.recv_into(buf)
                if n == 0:
                    r.close()
                    inputs.remove(r)
                    continue
                n = r.send(buf[:n])

if __name__ == "__main__":
    main()
