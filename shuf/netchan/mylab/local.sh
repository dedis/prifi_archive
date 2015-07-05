#!/bin/sh
trap 'jobs -p | xargs kill' EXIT

go build ~/go/src/github.com/dedis/prifi/shuf/netchan/client/client.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/server/server.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/genkey/genkey.go
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
  env syncprog=./syncit.py nodeId=$x mpg=2 shuffle=Butterfly split=Neff maxSize=32 times=4 servers=16 clients=32 minClients=32 maxClients=32 ./run.sh &
done
wait
