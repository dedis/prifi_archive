#!/bin/sh
mkdir -p /tmp/pubkeys
mkdir -p /tmp/privkeys
for x in `seq 0 \`expr $1 - 1\``; do
  ./genkey /tmp/pubkeys/$x.pub /tmp/privkeys/$x.priv
done
scp -r /tmp/pubkeys ankles@users.isi.deterlab.net:~/pubkeys
scp -r /tmp/privkeys ankles@users.isi.deterlab.net:~/privkeys

echo '
set ns [new Simulator]
source tb_compat.tcl
set lanstr ""
for {set x 0} {$x<'$1'} {incr x} {
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

ssh ankles@users.isi.deterlab.net <<HERE
mkdir -p ~/go/src/github.com/dedis/crypto
cd ~/go/src/github.com/dedis/crypto
[ -e .git ] || git init
git pull https://github.com/DeDiS/crypto.git master
mkdir -p ../prifi
cd ../prifi
[ -e .git ] || git init
git pull https://github.com/bogiebro/prifi.git
HERE
