import argparse
import json
import os
import random
import shutil

import config_utils
from config_utils import Config
import session_config

class PseudonymConfig:
    def __init__(self, group_id, session_id, slots):
        self.group_id = group_id
        self.session_id = session_id
        self.slots = slots


def generate(session):
    group_id = session.group_id
    session_id = session.session_id

    slot_keys = session.clients.keys
    random.shuffle(slot_keys)
    slots = Config.Slots(slot_keys)

    pseudonym = PseudonymConfig(group_id, session_id, slots)

    return pseudonym


def load(filename):
    with open(filename, "r", encoding="utf-8") as fp:
        data = json.load(fp)

    group_id = data["group-id"]
    session_id = data["session-id"]

    slots = data["slots"]
    slot_keys = config_utils.load_slots(slots)
    slots = Config.Slots(slot_keys)

    return PseudonymConfig(group_id, session_id, slots)

def save(config, filename):
    slots = config_utils.save_slots(config.slots)
    system = {
        "group-id" : config.group_id,
        "session-id" : config.session_id,
        "slots" : slots,
    }

    with open(filename, "w", encoding="utf-8") as fp:
        json.dump(system, fp)


def main():
    p = argparse.ArgumentParser(description="Generate pseudonym configuration")
    p.add_argument("output_dir")
    opts = p.parse_args()

    # XXX assumes hardcoded session config location
    session = session_config.load(os.path.join(opts.output_dir, "session.json"))

    pseudonym = generate(session)
    save(pseudonym, os.path.join(opts.output_dir, "pseudonym.json"))


if __name__ == "__main__":
    main()
