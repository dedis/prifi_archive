import argparse
import os
import requests
import time
import signal
import subprocess
import sys

def main():
    p = argparse.ArgumentParser(description="Start up a number of clients on localhost")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=4, dest="n_clients")
    p.add_argument("data_dir")
    opts = p.parse_args()

    n_clients = opts.n_clients
    data_dir = opts.data_dir
    print("Launching {} clients".format(n_clients))
    try:
        # spawn the processes
        procs = []
        for i in range(n_clients):
            private_data = os.path.join(opts.data_dir, "client-{}.json".format(i))
            p = subprocess.Popen([sys.executable, "dcnet_client.py", "-c", str(n_clients),
                                data_dir, private_data], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
            procs.append(p)

        # initiate the exchange on all clients
        time.sleep(1)
        print("Starting dc-net on {} clients".format(n_clients))
        for i in range(n_clients):
            r = requests.post("http://localhost:{}/start".format(i + 12345))

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("Cleaning up")
    for i, p in enumerate(procs):
        p.wait()
        print("Client {}".format(i))
        print("-"*200)
        print(p.stdout.read().decode("utf-8"))
        print("-"*200)


if __name__ == "__main__":
    main()
