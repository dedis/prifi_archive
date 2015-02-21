#!/usr/local/bin/bash
# kill processes across nodes

BASE=/users/ecawthon/dissent/python
source $BASE/deter/config.sh

ssh remote.$SUFFIX pkill python3
ssh relay.$SUFFIX pkill python3
for i in $(seq 0 $maxclient); do
	ssh client-$i.$SUFFIX pkill python3
done
for i in $(seq 0 $maxtrustee); do
	ssh trustee-$i.$SUFFIX pkill python3
done
for i in $(seq 0 $maxap); do
    ssh ap-$i.$SUFFIX pkill python3
done
