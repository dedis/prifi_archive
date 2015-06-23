#!/bin/bash
# args: clientid
cd /proj/Dissent/shuffle
sudo apt --assume-yes install golang
echo `hostname`:9000 > clt$1
emulab-sync -n hostnames
emulab-sync -n init
time -p ./client $1 config nodes clients pubkeys
echo CLIENT $1 DONE
emulab-sync -n finish
