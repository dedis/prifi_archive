#!/usr/local/bin/python -i
import pandas as pd
import numpy as np
import os
os.system("cat *.csv >input.")
df = pd.read_csv("input", header=None, names=['Node', 'GroupSize', 'Time'])
avg = df.groupby(['GroupSize', 'Node']).mean()
maxs = avg.groupby(level=0).max()
mins = avg.groupby(level=0).min()
means = avg.groupby(level=0).mean()
