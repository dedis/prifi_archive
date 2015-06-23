#!/bin/bash
# args: clientid
cd /proj/Dissent/shuffle
sudo apt --assume-yes install golang
echo `hostname`:9000 > clt$1
emulab-sync -n hostnames
emulab-sync -n init
time -p ./client $1 config nodes clients pubkeys
emulab-sync -n finish
