import argparse
import os
import requests
import time
import signal
import subprocess
import sys

def main():
    p = argparse.ArgumentParser(description="Start up a number of clients on localhost")
    p.add_argument("-c", "--clients", type=int, metavar="N", default=10, dest="n_clients")
    p.add_argument("-t", "--trustees", type=int, metavar="N", default=3, dest="n_trustees")
    p.add_argument("data_dir")
    opts = p.parse_args()

    n_clients = opts.n_clients
    n_trustees = opts.n_trustees
    data_dir = opts.data_dir
    try:
        # spawn n client processes
        print("Launching {} clients".format(n_clients))
        procs = []
        for i in range(n_clients):
            private_data = os.path.join(opts.data_dir, "client-{}.json".format(i))
            p = subprocess.Popen([sys.executable, "dcnet_client.py", data_dir, private_data],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        # same with trustees
        print("Launching {} trustees".format(n_trustees))
        for i in range(n_trustees):
            private_data = os.path.join(opts.data_dir, "trustee-{}.json".format(i))
            p = subprocess.Popen([sys.executable, "dcnet_trustee.py", data_dir, private_data],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        # initiate an interval on all clients and trustees
        time.sleep(1)
        print("Starting dc-net on {} clients and {} trustees".format(n_clients, n_trustees))
        for i in range(n_clients + n_trustees):
            r = requests.post("http://localhost:{}/interval_conclusion".format(i + 12345))

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("Cleaning up")
    for i, p in enumerate(procs):
        p.wait()
        print(("Client {}" if i < n_clients else "Trustee {}").format(i))
        print("-"*20)
        print(p.stderr.read().decode("utf-8"))
        print("-"*20)


if __name__ == "__main__":
    main()
