# deterlab details
SUFFIX=LLD-ecawthon.safer
VERBOSE=WARN
maxclient=31
maxtrustee=2
maxap=0

# internal file paths
CONFIG=$BASE/config
CLIENTIDS=$CONFIG/CLIENTS
TRUSTEEIDS=$CONFIG/TRUSTEES
APIDS=$CONFIG/APS
SCRIPTS=$BASE/deter

BASE_PORT=12345

# experiment specific
OUT=$BASE/evals/scale_clients.$(git --git-dir $HOME/dissent/.git log --pretty=format:'%H' -n 1).data
