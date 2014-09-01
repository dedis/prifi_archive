#!/bin/bash
# different interpreter on client machines

BASE=/users/ecawthon/dissent/python
source $BASE/deter/config.sh

for i in $(seq 0 $2); do
    echo -n "$1 " >> $OUT.$3
    python3 $BASE/test_client.py -c 1 --host localhost $BASE_PORT | cut -d" " -f2- >> $OUT.$3
done
