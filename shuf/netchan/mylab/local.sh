#!/bin/sh
trap 'jobs -p | xargs kill' EXIT

redis-cli flushdb
rm -f /tmp/hosts
rm -rf ~/logs
rm -rf ~/stats
rm -f *.priv
rm -rf pubkeys

for x in `seq 48`; do
  echo 'localhost:'`expr 8999 + $x` >> /tmp/hosts
done
for x in `seq 0 15`; do
  env nodeId=$x mpg=2 shuffle=Butterfly split=Neff maxSize=32 times=1 servers=16 clients=32 minClients=1 maxClients=4 ./run.sh &
done
wait
