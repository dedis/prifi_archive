#!/bin/sh
cd ~/go/src/github.com/dedis/prifi
git archive -o prifi.tar HEAD
scp prifi.tar ankles@users.isi.deterlab.net:/proj/SAFER/tarfiles/
cd ../crypto
git archive -o crypto.tar HEAD
scp crypto.tar ankles@users.isi.deterlab.net:/proj/SAFER/tarfiles/
ssh ankles@users.isi.deterlab.net <<HERE
cd /proj/SAFER/tarfiles
tar -xvf crypto.tar -C ~/go/src/github.com/dedis/crypto
tar -xvf prifi.tar -C ~/go/src/github.com/dedis/prifi
HERE
