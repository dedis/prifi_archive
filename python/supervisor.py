import argparse
import json
import os
import requests
import time
import signal
import subprocess
import sys

def main():
    p = argparse.ArgumentParser(description="Start up a number of clients on localhost")
    p.add_argument("config_dir")
    opts = p.parse_args()

    # find the ids and addresses of participants to start
    with open(os.path.join(opts.config_dir, "system.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        relay_ids, relay_ips = zip(*[(r["id"], r["ip"]) for r in data["relays"]])
        client_ids, client_ips = zip(*[(c["id"], c["ip"]) for c in data["clients"]])
        trustee_ids, trustee_ips = zip(*[(t["id"], t["ip"]) for t in data["servers"]])

    with open(os.path.join(opts.config_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        session_id = data["session-id"]

    # XXX assuming that relay is already running on addresses from config
    # so we don't start them up here - this makes debugging easier for now

    try:
        # spawn n trustee processes
        print("Launching {} trustees".format(len(trustee_ids)))
        procs = []
        for iden, ip in zip(trustee_ids, trustee_ips):
            private_data = os.path.join(opts.config_dir, "{}.json".format(iden))
            p = subprocess.Popen([sys.executable, "trustee.py", opts.config_dir,
                                private_data, "-p", ip.split(":")[1]],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        # XXX hack to ensure connection order
        time.sleep(3)

        # same with clients
        print("Launching {} clients".format(len(client_ids)))
        for iden, ip in zip(client_ids, client_ips):
            private_data = os.path.join(opts.config_dir, "{}.json".format(iden))
            p = subprocess.Popen([sys.executable, "client.py", opts.config_dir,
                                private_data, "-p", ip.split(":")[1]],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        while True:
            #for i, p in enumerate(procs):
            #    print(i, p.stdout.readline())
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
