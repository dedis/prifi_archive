#!/bin/bash
echo "clients throughput latency"
while read -r line; do
  echo -n "$(echo "$line" | cut -d' ' -f1) "
  read -r line
  echo -n "$(echo "$line" | cut -d' ' -f4 | cut -d'.' -f1) "
  read -r line
  echo $(echo "$line" | cut -d' ' -f4 | cut -c-8)
done < $1
