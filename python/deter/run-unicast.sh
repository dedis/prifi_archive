
#!/usr/local/bin/bash
# setup nodes after swapin

BASE=/users/ecawthon/dissent/python
SERVERS=$BASE/net
source $BASE/deter/config.sh

clients=$((maxclient + 1))
trustees=$((maxtrustee + 1))
ssh client-0.$SUFFIX $SCRIPTS/genconfig.sh $1 $trustees 0

# Get the "remote" server going
echo "starting remote"
ssh remote.$SUFFIX python3 $SERVERS/dummy_server.py -p 8080 -c 131072 &
sleep 2

# Setup the relay
echo "starting relay"
ssh relay.$SUFFIX python3 $SERVERS/socks5.py -p 8080 &
rm $BASE/rout
ssh relay.$SUFFIX python3 $BASE/relay.py -p $BASE_PORT $CONFIG -v $VERBOSE &> $BASE/rout &
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
    ssh client-$index.$SUFFIX python3 $BASE/client.py -p $port $CONFIG \
        $CONFIG/$id.json -v $VERBOSE &
done

readarray -t ids < $TRUSTEEIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $trustees))
    offset=$(($i / $trustees))
    id=${ids[$i]}
    echo "starting trustee-$index with id $id"
    ssh trustee-$index.$SUFFIX python3 $BASE/trustee.py $CONFIG $CONFIG/$id.json &
done

