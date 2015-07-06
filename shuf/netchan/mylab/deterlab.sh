#!/bin/sh

servers=16
clients=32

go build ~/go/src/github.com/dedis/prifi/shuf/netchan/genkey/genkey.go
mkdir -p /tmp/pubkeys
mkdir -p /tmp/privkeys
for x in `seq 0 \`expr $servers - 1\``; do
  ./genkey /tmp/pubkeys/$x.pub /tmp/privkeys/$x.priv
done
scp -r /tmp/pubkeys ankles@users.isi.deterlab.net:~/pubkeys
scp -r /tmp/privkeys ankles@users.isi.deterlab.net:~/privkeys

ssh ankles@users.isi.deterlab.net <<'HERE'
mkdir -p ~/go/src/github.com/dedis/crypto
cd ~/go/src/github.com/dedis/crypto
[ -e .git ] || git init
git pull https://github.com/DeDiS/crypto.git master
mkdir -p ../prifi
cd ../prifi
[ -e .git ] || git init
git reset --hard
git pull https://github.com/bogiebro/prifi.git
HERE

cat > /tmp/remote.sh <<HERE
#!/bin/sh
export GOPATH=/users/ankles/go
export PATH=\$PATH:/usr/local/go/bin
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/client/client.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/server/server.go
go build ~/go/src/github.com/dedis/prifi/shuf/netchan/genkey/genkey.go
sed -n '/#/d; /node-[0-9]/p' /etc/hosts | awk '{print \$1, substr(\$4, 6)}' | sort -n -k2 > /tmp/hostnames
cat /tmp/hostnames /tmp/hostnames /tmp/hostnames | awk '{print \$1 ":" NR + 8999}' > /tmp/hosts
env syncprog=emulab-sync nodeId=\$1 mpg=2 maxSize=$clients times=4 shuffle=Butterfly \
  split=Neff servers=$servers clients=$clients minClients=$clients maxClients=$clients ./run.sh
HERE
scp /tmp/remote.sh ankles@users.isi.deterlab.net:~/go/src/github.com/dedis/prifi/shuf/netchan/mylab/

echo '
set ns [new Simulator]
source tb_compat.tcl
set lanstr ""
for {set x 0} {$x<'$servers'} {incr x} {
  set node($x) [$ns node]
  append lanstr "$node($x) "
  tb-set-node-os $node($x) Ubuntu1404-64-Go
  if {$x == 0} {
    tb-set-sync-server $node($x) 
  }
  tb-set-node-startcmd $node($x) "cd /users/ankles/go/src/github.com/dedis/prifi/shuf/netchan/mylab; ./remote.sh $x"
}
set big-lan [$ns make-lan "$lanstr" 100Mb 0ms]
$ns rtproto Static
$ns run' > /tmp/nsfile
scp /tmp/nsfile ankles@users.isi.deterlab.net:~/nsfile
