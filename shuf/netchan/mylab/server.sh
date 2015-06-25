#!/bin/sh

emulab-sync -n install$mpg$t
echo NODE ID IS $nodeId
./server $nodeId /tmp/config-$nodeId-server.sh /tmp/nodes /tmp/clients /tmp/pubkeys /tmp/$nodeId.priv &
SERVER=$!
emulab-sync -n init$mpg$t
emulab-sync -n finish$mpg$t
kill $SERVER
