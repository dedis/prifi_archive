#!/bin/bash
# different interpreter on client machines

BASE=/users/ecawthon/dissent/python
source $BASE/deter/config.sh

SEED=scale

python3 $BASE/config.py -c $1 -t $2 -a $3 -s $SEED -r relay:$BASE_PORT --ap ap-0:$BASE_PORT $CONFIG
python3 $BASE/getids.py --clients $CONFIG > $CLIENTIDS
python3 $BASE/getids.py --trustees $CONFIG > $TRUSTEEIDS
python3 $BASE/getids.py --aps $CONFIG > $APIDS
