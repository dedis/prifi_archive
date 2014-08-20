#!/bin/bash
# different interpreter on client machines

source config.sh

for i in $(seq 0 $2); do
    echo -n "$1 " >> $OUT
    python3 test_client.py -c 1 localhost $BASE_PORT | cut -d" " -f2- >> $OUT
done
