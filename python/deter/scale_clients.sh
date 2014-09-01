#!/usr/local/bin/bash

BASE=/users/ecawthon/dissent/python
source $BASE/deter/config.sh
rm $OUT.$1

TRIALS=9
t=$(($maxtrustee + 1))
a=$(($maxap + 1))

for c in 4 8 16 32 64 128; do
    echo "stopping processes"
    $SCRIPTS/stop.sh &> /dev/null

    echo "running for $c clients"
    $SCRIPTS/run-$1.sh $c
    sleep 3

    ssh client-0.$SUFFIX $SCRIPTS/dorequests.sh $c $TRIALS $1
done
echo "cleaning up"
$SCRIPTS/stop.sh &> /dev/null
echo "done"
