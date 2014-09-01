import argparse
import json
import os
import time
import signal
import subprocess
import sys

import config

def main():
    p = argparse.ArgumentParser(description="Start up an lld configuration on localhost")
    p.add_argument("config_dir")
    p.add_argument("-l", "--local", type=int, metavar="local", default=0, dest="local")
    opts = p.parse_args()

    # find the ids and addresses of participants to start
    system_config = config.load(config.SystemConfig, os.path.join(opts.config_dir, "system.json"))
    client_ids = system_config.clients.ids
    trustee_ids = system_config.trustees.ids

    sesion_config = config.load(config.SessionConfig, os.path.join(opts.config_dir, "session.json"))

    # XXX assuming that relay is already running on addresses from config
    # so we don't start them up here - this makes debugging easier for now
    print("Relay should be running on {}".format(system_config.relay.port))

    nclients = max(len(client_ids) - opts.local, 0)
    ntrustees = len(trustee_ids)

    try:
        # spawn n client processes
        print("Launching {} clients, {} trustees".format(nclients, ntrustees))
        port = system_config.relay.port
        executable = "trustee.py"
        procs = []
        for i, id in enumerate(trustee_ids + client_ids[:nclients]):
            port += 1
            if i == len(trustee_ids):
                executable = "client.py"
            private_data = os.path.join(opts.config_dir, "{}.json".format(id))
            p = subprocess.Popen([sys.executable, executable, opts.config_dir,
                                private_data, "-p", str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        print("Manually launch: {}".format(client_ids[nclients:]))

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print("Cleaning up")
    for i, p in enumerate(procs):
        p.wait()
        print("Client {}".format(i))
        print("-"*20)
        print(p.stderr.read().decode("utf-8"))
        print("-"*20)


if __name__ == "__main__":
    main()
