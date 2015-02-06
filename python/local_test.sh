#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "usage: ./local_test.sh [clients] [trustees] [aps]"
    exit
fi

#paths
SCRIPTS=deter
SERVERS=net
CONFIG=config
VERBOSE=WARN
CLIENTIDS=$CONFIG/CLIENTS
TRUSTEEIDS=$CONFIG/TRUSTEES
APIDS=$CONFIG/APS
#ports
RELAY_PORT=12345
AP_PORT=23456
CLIENT_BASE_PORT=4747
RELAY_BASE_PORT=7474
#args
clients=$1
trustees=$2
aps=$3

echo "generating config"
python3 config.py -c $clients -t $trustees -a $aps -s scale \
        -r localhost:$RELAY_PORT --ap localhost:$AP_PORT $CONFIG
python3 getids.py --clients $CONFIG > $CLIENTIDS
python3 getids.py --trustees $CONFIG > $TRUSTEEIDS
python3 getids.py --aps $CONFIG > $APIDS

echo "starting remote on port 8080"
python3 $SERVERS/dummy_server.py -p 8080 -c 131072 &
sleep 2

# Setup the relay
echo "starting socks server"
python3 $SERVERS/socks5.py -p 8081 &
echo "starting relay"
python3 relay.py -p $RELAY_PORT $CONFIG -v $VERBOSE --socks localhost:8081&
sleep 2

# Setup the access point(s)
readarray -t ids < $APIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $aps))
    echo "starting ap-$index:$port with id $id"
    python3 access_point.py $CONFIG \
        $CONFIG/$id.json -v $VERBOSE &
    CLIENT_AP_ARG="-a 0 -m " # This will only work for 1 access point; see
                             # deter/run-mcast*.sh for scalable code
done
sleep 2

# Start the clients and trustees
readarray -t ids < $CLIENTIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $clients))
    port=$(($CLIENT_BASE_PORT + $index))
    echo "starting client-$index:$port with id $id"
    python3 client.py -p $port $CONFIG $CLIENT_AP_ARG \
            $CONFIG/$id.json -v $VERBOSE &
done

readarray -t ids < $TRUSTEEIDS
maxid=$((${#ids[@]} - 1))
for i in $(seq 0 $maxid); do
    id=${ids[$i]}
    index=$(($i % $trustees))
    id=${ids[$i]}
    echo "starting trustee-$index with id $id"
    python3 trustee.py $CONFIG $CONFIG/$id.json &
done

# do a couple of performance tests to confirm it's working
sleep 2
echo "Dissent is running. Now running tests."
for i in $(seq 0 $(($1+$2+$3))); do
    echo -n "$i "
    python3 $SERVERS/test_client.py -c 1 --dest localhost --host localhost $CLIENT_BASE_PORT | cut -d" " -f2-
done

echo "cleaning up"
killall python3
rm $TRUSTEEIDS $CLIENTIDS $APIDS
