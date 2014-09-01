#!/usr/local/bin/bash
# setup nodes after swapin

packages="python3-crypto git"

BASE=/users/ecawthon/dissent/python
source $BASE/deter/config.sh

nodes="remote relay"
for i in $(seq 0 $maxap); do
	nodes="$nodes ap-$i"
done
for i in $(seq 0 $maxclient); do
	nodes="$nodes client-$i"
done
for i in $(seq 0 $maxtrustee); do
	nodes="$nodes trustee-$i"
done

for n in $nodes; do
	# install packages we need
	ssh -o "StrictHostKeyChecking no" $n.$SUFFIX \
		sudo apt-get -y install $packages &
done
wait

