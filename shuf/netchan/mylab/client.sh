#!/bin/sh
emulab-sync -n install$mpg$t
emulab-sync -n init$mpg$t
time -p ./client $nodeId /tmp/config-$nodeId-client.sh /tmp/nodes /tmp/clients /tmp/pubkeys
emulab-sync -n finish$mpg$t
