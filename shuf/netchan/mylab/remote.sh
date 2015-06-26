#!/bin/bash
cd /proj/Dissent/shuffle
tail -n +2 /etc/hosts | awk '{print $1, substr($4, 6)}' | sort -n -k2 | awk '{print $1 ":" NR + 8999}' > /tmp/hosts
./wrapperG.sh $1 2 32 4 16 32 $2
