import pandas as pd
import numpy as np
import os
os.system("cat *.csv >input")
df = pd.read_csv("input", header=None, names=['Node', 'GroupSize', 'ActiveClients', 'Time', 'Corrupted'])
