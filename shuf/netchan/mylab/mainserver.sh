#!/bin/sh
others=`echo $clients+$servers-1 | bc`
emulab-sync -i $others -n install$mpg$t
./server $nodeId /tmp/config-$nodeId-mainserver.sh $nodesFile $clientsFile pubkeys $nodeId.priv &
SERVER=$!
emulab-sync -i $others -n init$mpg$t
emulab-sync -i $others -n finish$mpg$t
kill $SERVER
