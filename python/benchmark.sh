#!/bin/bash

if [[ $# -ne 2 ]]; then
  echo "usage: $0 host port"
  exit
fi

for i in 1 2 4 8 16 32 64; do
  for j in $(seq 0 9); do
    python3 test_client.py -c $i $1 $2
  done
done
