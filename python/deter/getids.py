import argparse
import os

import config

p = argparse.ArgumentParser(description="Generate system configuration")
p.add_argument("-c", "--clients", action="store_true", default=True, dest="clients")
p.add_argument("-t", "--trustees", action="store_false", default=False, dest="clients")
p.add_argument("config_dir")
opts = p.parse_args()

system_config = config.load(config.SystemConfig, os.path.join(opts.config_dir, "system.json"))
if opts.clients:
    ids = system_config.clients.ids
else:
    ids = system_config.trustees.ids
for id in ids:
    print(id)
