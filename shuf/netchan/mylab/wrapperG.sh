#!/bin/sh
hosts=$1
export nodeId=$2
export mpg=$3
maxSize=$4
times=$5
export servers=$6
export clients=$7
cmd=$8

exec 3>&1 4>&2 >log-$nodeId-$cmd 2>&1

# synchronize servers and keys
head -n $servers $hosts | awk '{print $0 ":" (NR + 9000)}' > /tmp/nodes
tail -n $clients $hosts | awk '{print $0 ":" (NR + 9000 + '$servers')}' > /tmp/clients
mkdir -p /tmp/pubkeys
if echo $cmd | grep server > /dev/null; then
  ./genkey /tmp/pubkeys/$nodeId.pub /tmp/$nodeId.priv
  for h in `head -n $servers $hosts`; do
    scp /tmp/$nodeId.priv $h:/tmp
    scp /tmp/pubkeys/$nodeId.pub $h:/tmp/pubkeys
  done
fi

while [ $mpg -le $maxSize ]
do
  for t in `seq $times`
  do
    export t
    awk '/MsgsPerGroup/ {$2='$mpg'}
         /ActiveClients/ {$2='$clients'}
         /NumClients/ {$2='$clients'}
         /NumNodes/ {$2='$servers'} {print}' config > /tmp/config-$nodeId-$cmd
    ./$cmd 2>&1 | awk '/real/ {print '$nodeId', '$mpg', $2}' | xargs tmcc log
  done
  mpg=`echo $mpg*2 | bc`
done

exec 1>&3 2>&4

