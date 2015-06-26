#!/bin/sh

emulab-sync -n install$mpg$t
./server $nodeId /tmp/config-$nodeId-server.sh $nodesFile $clientsFile pubkeys $nodeId.priv &
SERVER=$!
emulab-sync -n init$mpg$t
emulab-sync -n finish$mpg$t
kill $SERVER
