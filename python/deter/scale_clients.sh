#!/usr/local/bin/bash

source config.sh
rm $OUT

TRIALS=9
t=$(($maxtrustee + 1))

for c in 4 8 16 32 64 128; do
    echo "stopping processes"
    ./stop.sh &> /dev/null

    echo "running for $c clients"
    ssh client-0.$SUFFIX ./genconfig.sh $c $t
    ./run.sh
    sleep 3

    ssh client-0.$SUFFIX ./dorequests.sh $c $TRIALS
done
echo "cleaning up"
./stop.sh &> /dev/null
echo "done"
