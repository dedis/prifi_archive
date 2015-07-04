#!/bin/sh
sudo apt --assume-yes install golang
cd ~/go/src/github.com/dedis/prifi/shuf
git pull https://bogiebro@github.com/bogiebro/prifi.git
cd /proj/Dissent/shuffle
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/client/client.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/server/server.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/genkey/genkey.go
sed -n '/#/d; /node-[0-9]/p' /etc/hosts | awk '{print $1, substr($4, 6)}' | sort -n -k2 > /tmp/hostnames
cat /tmp/hostnames /tmp/hostnames /tmp/hostnames | awk '{print $1 ":" NR + 8999}' > /tmp/hosts
env nodeId=$1 mpg=2 maxSize=32 times=4 shuffle=Butterfly split=Neff servers=16 clients=32 minClients=32 maxClients=32 ./run.sh
