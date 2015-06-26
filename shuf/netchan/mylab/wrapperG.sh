#!/bin/sh
export nodeId=$1
export mpg=$2
maxSize=$3
times=$4
export servers=$5
export clients=$6
cmd=$7
export nodesFile=/tmp/nodesFile$nodeId$cmd
export clientsFile=/tmp/clientsFile$nodeId$cmd

# calculate rounds
rounds=$(echo '
numgroups = '$clients' / '$mpg'
groupsize = '$servers' / numgroups
levels = (l(numgroups) / l(2)) ^ 2 + 1
scale = 0
(groupsize * 2 * levels) / 1
' | bc -l)

# create clients and servers files
head -n $servers /tmp/hosts > $nodesFile
tail -n $clients /tmp/hosts > $clientsFile
[ `wc -l $clientsFile | awk '{print $1}'` -eq $clients ] || (echo panic: not enough clients 1>&2; exit 1)
[ `wc -l $nodesFile | awk '{print $1}'` -eq $servers ] || (echo panic: not enough servers 1>&2; exit 1)

# synchronize servers and keys
mkdir -p pubkeys
if echo $cmd | grep server > /dev/null; then
  ./genkey pubkeys/$nodeId.pub $nodeId.priv
fi

# run it
mkdir -p ~/logs
mkdir -p ~/stats
while [ $mpg -le $maxSize ]
do
  for t in `seq $times`
  do
    export t
    awk '/MsgsPerGroup/ {$2='$mpg'}
         /ActiveClients/ {$2='$clients'}
         /NumRounds/ {$2='$rounds'}
         /NumClients/ {$2='$clients'}
         /NumNodes/ {$2='$servers'} {print}' config > /tmp/config-$nodeId-$cmd
    ./$cmd 2>&1 | tee -a ~/logs/$nodeId$cmd | awk '/real/ {print '$nodeId'",", '$mpg'",", $2}' >> ~/stats/$nodeId.csv
  done
  mpg=`echo $mpg*2 | bc`
done

