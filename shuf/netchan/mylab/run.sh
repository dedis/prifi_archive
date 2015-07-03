#!/bin/sh
trap 'jobs -p | xargs kill' EXIT

export nodesFile=/tmp/nodesFile$nodeId
export clientsFile=/tmp/clientsFile$nodeId

if [ $nodeId -eq 0 ]
then export esync="emulab-sync -i "`echo $clients+$servers-1 | bc`
else export esync="emulab-sync"
fi

startClient () {
  emulab-sync -n init$mpg$t$a
  echo CLIENT $clientId on `sed -n \`expr $clientId + 1\`p $clientsFile`
  time -p ./client $clientId /tmp/config-$nodeId $nodesFile $clientsFile pubkeys
  emulab-sync -n finish$mpg$t$a
}

# calculate rounds
rounds=`echo '
numgroups = '$clients' / '$mpg'
groupsize = '$servers' / numgroups
levels = ((l(numgroups) / l(2)) ^ 2) + 1
scale = 0
(groupsize * 2 * (levels / 1)) / 1
' | bc -l`

# create clients and servers files
head -n $servers /tmp/hosts > $nodesFile
tail -n $clients /tmp/hosts > $clientsFile

# synchronize servers and keys
mkdir -p pubkeys
./genkey pubkeys/$nodeId.pub $nodeId.priv
if [ $nodeId -eq 0 ]
then emulab-sync -i `echo $servers-1 | bc` -n install
else emulab-sync -n install
fi

# run it
mkdir -p ~/logs
mkdir -p ~/stats
while [ $mpg -le $maxSize ]; do
  for a in `seq $minClients $maxClients`; do
    export a
    for t in `seq $times`; do
      export t
      awk '/MsgsPerGroup/ {$2='$mpg'}
           /ActiveClients/ {$2='$a'}
           /NumRounds/ {$2='$rounds'}
           /NumClients/ {$2='$clients'}
           /Shuffle/ {$2='$shuffle'}
           /Split/ {$2='$split'}
           /NumNodes/ {$2='$servers'} {print}' config > /tmp/config-$nodeId
      for c in 0 1; do
        export clientId=`echo "$nodeId+$c*$servers" |bc`
        startClient 2>&1 | tee -a ~/logs/client$clientId.log | awk '
         BEGIN {CORRUPTED=0}
         /real/ {TIME = $2}
         /corrupted/ {CORRUPTED += 1}
         END {print '$clientId' ",", '$mpg' ",", '$a' ",", TIME ",", CORRUPTED}' >> ~/stats/client$clientId.csv &
      done
      echo NODE $nodeId on `sed -n \`expr $nodeId + 1\`p $nodesFile` >> ~/logs/server$nodeId.log 
      ./server $nodeId /tmp/config-$nodeId $nodesFile $clientsFile pubkeys $nodeId.priv >> ~/logs/server$nodeId.log 2>&1 &
      SERVER=$!
      echo 'server up' >> ~/logs/server$nodeId.log 
      $esync -n init$mpg$t$a
      $esync -n finish$mpg$t$a
      kill $SERVER
      wait
    done
  done
  mpg=`echo $mpg*2 | bc`
done
