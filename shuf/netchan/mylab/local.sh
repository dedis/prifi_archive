#!/bin/sh
trap 'jobs -p | xargs kill' EXIT
rm -f /tmp/hosts
for x in `seq 48`; do
  echo 'localhost:'`expr 8999 + $x` >> /tmp/hosts
done
./wrapperG.sh 0 2 32 4 16 32 mainserver.sh &
for x in `seq 47`; do
  if [ $x -lt 16 ]
  then ./wrapperG.sh $x 2 32 4 16 32 server.sh &
  else ./wrapperG.sh `expr $x - 16` 2 32 4 16 32 client.sh &
  fi
done
wait

while pgrep -P "$$" > /dev/null; do
  wait
done
echo flushdb | redis-cli
