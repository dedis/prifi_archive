#!/bin/sh

(for x in `seq 12`; do echo localhost; done) > /tmp/fakehosts
./wrapperG.sh /tmp/fakehosts 0 2 8 1 4 8 mainserver.sh &
for x in `seq 11`; do
  if [ $x -lt 4 ]
  then ./wrapperG.sh /tmp/fakehosts $x 2 8 1 4 8 server.sh &
  else ./wrapperG.sh /tmp/fakehosts `expr $x - 4` 2 8 1 4 8 client.sh &
  fi
done
wait
