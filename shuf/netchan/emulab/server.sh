#!/bin/sh
# arg is nodeid

# create the hosts file
cd /proj/Dissent/shuffle
echo `hostname`:9000 > nd$1
emulab-sync -n hostnames

# install go, generate keys, start server
sudo apt --assume-yes install golang
./genkey pubkeys/$1.pub $1.priv
./server $1 config nodes clients pubkeys $1.priv &
SERVER=$!
emulab-sync -n init
emulab-sync -n finish
kill $SERVER
