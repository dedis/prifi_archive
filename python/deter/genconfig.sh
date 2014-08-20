#!/bin/bash
# different interpreter on client machines

source config.sh

SEED=scale

python3 config.py -c $1 -t $2 -s $SEED -r relay.$SUFFIX:$BASE_PORT $CONFIG
python3 getids.py --clients $CONFIG > $CLIENTIDS
python3 getids.py --trustees $CONFIG > $TRUSTEEIDS
