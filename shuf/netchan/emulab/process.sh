#!/bin/sh
cd /proj/Dissent/exp/Shuffler/
loghole sync
ls logs/*/local/logs/* | xargs awk '/real/ {print substr(FILENAME, 6, 5), $2}'
