#!/usr/local/bin/bash
# setup nodes after swapin

source config.sh

clients=$((maxclient + 1))
trustees=$((maxtrustee + 1))

# Get the "remote" server going
echo "starting remote"
ssh remote.$SUFFIX python3 dummy_server.py -p 8080 -c 131072 &
sleep 2

# Setup the relay
echo "starting relay"
ssh relay.$SUFFIX python3 socks5.py -p 8080 &
ssh relay.$SUFFIX python3 relay.py -p $BASE_PORT $CONFIG &
sleep 2

# Start clients and trustees
readarray -t ids < $CLIENTIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $clients))
    offset=$(($i / $clients))
    port=$(($BASE_PORT + $offset))
    echo "starting client-$index:$port with id $id"
    ssh client-$index.$SUFFIX python3 client.py -p $port $CONFIG $CONFIG/$id.json &
done

readarray -t ids < $TRUSTEEIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $trustees))
    offset=$(($i / $trustees))
    port=$(($BASE_PORT + $offset))
    id=${ids[$i]}
    echo "starting trustee-$index:$port with id $id"
    ssh trustee-$index.$SUFFIX python3 trustee.py -p $port $CONFIG $CONFIG/$id.json &
done

