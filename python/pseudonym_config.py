import argparse
import json
import os
import random

def main():
    p = argparse.ArgumentParser(description="Generate post-shuffle config from session config")
    p.add_argument("output_dir")
    opts = p.parse_args()

    # load in the session config
    with open(os.path.join(opts.output_dir, "session.json"), "r", encoding="utf-8") as fp:
        data = json.load(fp)
        clients = data["clients"]

    # shuffle session public keys
    session_pub_keys = [client["dhkey"] for client in clients]
    random.shuffle(session_pub_keys)

    # XXX trustee signatures
    group_id = data["group-id"]
    session_id = data["session-id"]
    shuffle = {
        "group-id" : group_id,
        "session-id" : session_id,
        "slots" : session_pub_keys,
    }

    with open(os.path.join(opts.output_dir, "shuffle.json"), "w", encoding="utf-8") as fp:
        json.dump(shuffle, fp)
    print("Generated post-shuffle config to {}".format(os.path.join(opts.output_dir, "shuffle.json")))

if __name__ == "__main__":
    main()
