#!/bin/sh
trap 'jobs -p | xargs kill' EXIT

export nodesFile=/tmp/nodesFile$nodeId
export clientsFile=/tmp/clientsFile$nodeId

if [ $nodeId -eq 0 ]
then export esync="$syncprog -i "`echo $clients+$servers-1 | bc`
else export esync=$syncprog
fi

startClient () {
  $syncprog -n init$mpg$t$a
  echo CLIENT $clientId on `sed -n \`expr $clientId + 1\`p $clientsFile` mpg=$mpg a=$a t=$t
  time -p ./client $clientId /tmp/config-$nodeId $nodesFile $clientsFile /tmp/pubkeys
  $syncprog -n finish$mpg$t$a
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
me=`sed -n \`expr $nodeId + 1\`'p' $nodesFile | cut -d: -f1`

mkdir -p ~/logs
mkdir -p ~/stats

# generate key
mkdir -p /tmp/pubkeys
./genkey /tmp/pubkeys/$nodeId.pub /tmp/$nodeId.priv 2>&1 >> ~/logs/server$nodeId.log 
echo Key generated with status $? >> ~/logs/server$nodeId.log
cat /tmp/$nodeId.priv 2>> ~/logs/server$nodeId.log >/dev/null

# sync the key
for n in `cat $nodesFile | cut -d: -f1 | sort | uniq | fgrep -v $me`; do
  scp /tmp/pubkeys/$nodeId.pub $n:/tmp/pubkeys/$nodeId.pub
done

if [ $nodeId -eq 0 ]
then $syncprog -i `echo $servers-1 | bc` -n install
else $syncprog -n install
fi

# run it
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
      echo NODE $nodeId on `sed -n \`expr $nodeId + 1\`p $nodesFile` mpg=$mpg a=$a t=$t >> ~/logs/server$nodeId.log 
      echo STARTING SERVER >> ~/logs/server$nodeId.log 
      ./server $nodeId /tmp/config-$nodeId $nodesFile $clientsFile /tmp/pubkeys /tmp/$nodeId.priv >> ~/logs/server$nodeId.log 2>&1 &
      SERVER=$!
      echo 'server up' >> ~/logs/server$nodeId.log 
      $esync -n init$mpg$t$a
      $esync -n finish$mpg$t$a
      kill $SERVER
      wait
      echo SERVER IS DEAD >> ~/logs/server$nodeId.log 
    done
  done
  mpg=`echo $mpg*2 | bc`
done
