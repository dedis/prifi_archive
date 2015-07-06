#!/bin/sh
cd ~/go/src/github.com/dedis/prifi
git archive -o prifi.tar HEAD
scp prifi.tar ankles@users.isi.deterlab.net:/proj/SAFER/tarfiles/
cd ../crypto
git archive -o crypto.tar HEAD
scp crypto.tar ankles@users.isi.deterlab.net:/proj/SAFER/tarfiles/
cd ../prifi/shuf/netchan/mylab
ssh ankles@users.isi.deterlab.net <<HERE
cd /proj/SAFER/tarfiles
mkdir -p ~/go/src/github.com/dedis/crypto
mkdir -p ~/go/src/github.com/dedis/prifi
tar -xf crypto.tar -C ~/go/src/github.com/dedis/crypto
tar -xf prifi.tar -C ~/go/src/github.com/dedis/prifi
HERE
