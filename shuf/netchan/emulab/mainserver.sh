#!/bin/sh
# args: total, servers, clients, activeClients
cd /proj/Dissent/shuffle
mkdir -p pubkeys
echo Starting Up

# setup the config file
awk '/ActiveClients/ {$2='$4'}
     /NumClients/ {$2='$3'}
     /NumNodes/ {$2='$2'} {print}' config > newconfig
mv newconfig config

# create the hosts file
emulab-sync -a -i $1 -n hostnames
echo `hostname`:9000 > nd0
emulab-sync -n hostnames
ls nd* | sort | xargs cat > nodes
ls clt* | sort | xargs cat > clients
rm nd* clt*

# install go, generate keys, start server
emulab-sync -a -i $1 -n init
sudo apt --assume-yes install golang
./genkey pubkeys/0.pub 0.priv
./server 0 config nodes clients pubkeys 0.priv &
SERVER=$!
emulab-sync -n init
emulab-sync -i $1 -n finish
emulab-sync -n finish
kill $SERVER
