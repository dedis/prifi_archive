#!/bin/bash

set -v
set -e

go build
./deploy -mode pl -arch 386 -u yale_dissent -config ../data/zoo.json -hosts planetlab2.cs.unc.edu:9012,pl1.6test.edu.cn:9012,planetlab1.cs.du.edu:9012,planetlab02.cs.washington.edu:9012,planetlab-2.cse.ohio-state.edu:9012,planetlab2.cs.ubc.ca:9012